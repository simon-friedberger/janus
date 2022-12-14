use anyhow::{anyhow, Context, Result};
use base64::{
    alphabet::STANDARD,
    engine::fast_portable::{FastPortable, NO_PAD},
};
use clap::Parser;
use janus_aggregator::{
    binary_utils::{database_pool, datastore, read_config, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
    datastore::{self, Datastore},
    metrics::install_metrics_exporter,
    task::{SerializedTask, Task},
    trace::install_trace_subscriber,
};
use janus_core::time::{Clock, RealClock};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{ObjectMeta, PostParams};
use rand::{distributions::Standard, thread_rng, Rng};
use ring::aead::AES_128_GCM;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::fs;
use tracing::{debug, info};

static SCHEMA: &str = include_str!("../../../db/schema.sql");

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line options, then read & parse config.
    let command_line_options = CommandLineOptions::parse();
    let config_file: ConfigFile = read_config(&command_line_options.common_options)?;

    install_tracing_and_metrics_handlers(config_file.common_config())?;

    debug!(?command_line_options, ?config_file, "Starting up");

    if command_line_options.dry_run {
        info!("DRY RUN: no persistent changes will be made")
    }

    command_line_options
        .cmd
        .execute(&command_line_options, &config_file)
        .await
}

#[derive(Debug, Parser)]
enum Command {
    /// Write the Janus database schema to the database.
    WriteSchema,

    /// Write a set of tasks identified in a file to the datastore.
    ProvisionTasks {
        /// A YAML file containing a list of tasks to be written. Existing tasks (matching by task
        /// ID) will be overwritten.
        tasks_file: PathBuf,

        /// If true, task parameters omitted from the YAML tasks file will be randomly generated.
        #[clap(long, default_value = "false")]
        generate_missing_parameters: bool,

        /// Write the YAML representation of the tasks that are written to stdout.
        #[clap(long, default_value = "false")]
        echo_tasks: bool,
    },

    /// Create a datastore key and write it to a Kubernetes secret.
    CreateDatastoreKey,
}

impl Command {
    async fn execute(
        &self,
        command_line_options: &CommandLineOptions,
        config_file: &ConfigFile,
    ) -> Result<()> {
        // Note: to keep this function reasonably-readable, individual command handlers should
        // generally create the command's dependencies based on options/config, then call another
        // function with the main command logic.
        match self {
            Command::WriteSchema => {
                let datastore =
                    datastore_from_opts(command_line_options, config_file, None).await?;
                write_schema(&datastore).await
            }

            Command::ProvisionTasks {
                tasks_file,
                generate_missing_parameters,
                echo_tasks,
            } => {
                let kube_client = kube::Client::try_default()
                    .await
                    .context("couldn't connect to Kubernetes environment")?;
                let datastore =
                    datastore_from_opts(command_line_options, config_file, Some(&kube_client))
                        .await?;

                let written_tasks =
                    provision_tasks(&datastore, tasks_file, *generate_missing_parameters).await?;

                if *echo_tasks {
                    let tasks_yaml = serde_yaml::to_string(&written_tasks)
                        .context("couldn't serialize tasks to YAML")?;
                    println!("{tasks_yaml}");
                }

                Ok(())
            }

            Command::CreateDatastoreKey => {
                let kube_client = kube::Client::try_default()
                    .await
                    .context("couldn't connect to Kubernetes environment")?;
                let k8s_namespace = command_line_options
                    .secrets_k8s_namespace
                    .as_deref()
                    .context("--secrets-k8s-namespace is required")?;
                create_datastore_key(
                    command_line_options.dry_run,
                    &kube_client,
                    k8s_namespace,
                    &command_line_options.datastore_keys_secret_name,
                    &command_line_options.datastore_keys_secret_data_key,
                )
                .await
            }
        }
    }
}

fn install_tracing_and_metrics_handlers(config: &CommonConfig) -> Result<()> {
    install_trace_subscriber(&config.logging_config)
        .context("couldn't install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.metrics_config)
        .context("failed to install metrics exporter")?;

    Ok(())
}

async fn write_schema<C: Clock>(datastore: &Datastore<C>) -> Result<()> {
    info!("Writing database schema");
    datastore
        .run_tx(|tx| Box::pin(async move { tx.batch_execute(SCHEMA).await }))
        .await
        .context("failed to write database schema")
}

async fn provision_tasks<C: Clock>(
    datastore: &Datastore<C>,
    tasks_file: &Path,
    generate_missing_parameters: bool,
) -> Result<Vec<Task>> {
    // Read tasks file.
    let tasks: Vec<SerializedTask> = {
        let task_file_contents = fs::read_to_string(tasks_file)
            .await
            .with_context(|| format!("couldn't read tasks file {:?}", tasks_file))?;
        serde_yaml::from_str(&task_file_contents)
            .with_context(|| format!("couldn't parse tasks file {:?}", tasks_file))?
    };

    let tasks: Vec<Task> = tasks
        .into_iter()
        .map(|mut task| {
            if generate_missing_parameters {
                task.generate_missing_fields();
            }

            Task::try_from(task)
        })
        .collect::<Result<_, _>>()?;

    let tasks = Arc::new(tasks);

    // Write all tasks requested.
    info!(task_count = %tasks.len(), "Writing tasks");
    let written_tasks = datastore
        .run_tx(|tx| {
            let tasks = Arc::clone(&tasks);
            Box::pin(async move {
                let mut written_tasks = Vec::new();
                for task in tasks.iter() {
                    // We attempt to delete the task, but ignore "task not found" errors since
                    // the task not existing is an OK outcome too.
                    match tx.delete_task(task.id()).await {
                        Ok(()) => {
                            info!(task_id = %task.id(), "replacing existing task");
                        }
                        Err(datastore::Error::MutationTargetNotFound) => (),
                        err => err?,
                    }

                    tx.put_task(task).await?;

                    written_tasks.push(task.clone());
                }
                Ok(written_tasks)
            })
        })
        .await
        .context("couldn't write tasks")?;

    Ok(written_tasks)
}

async fn fetch_datastore_keys(
    kube_client: &kube::Client,
    namespace: &str,
    secret_name: &str,
    secret_data_key: &str,
) -> Result<Vec<String>> {
    debug!(
        "Fetching value {} from secret {}/{}",
        secret_data_key, namespace, secret_name,
    );

    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client.clone(), namespace);

    let secret = secrets_api
        .get(secret_name)
        .await?
        .data
        .context(format!("no data on secret {secret_name}"))?;
    let secret_value = secret.get(secret_data_key).context(format!(
        "no data key {secret_data_key} on secret {secret_name}"
    ))?;

    Ok(String::from_utf8(secret_value.0.clone())?
        .split(',')
        .map(&str::to_string)
        .collect())
}

async fn create_datastore_key(
    dry_run: bool,
    kube_client: &kube::Client,
    k8s_namespace: &str,
    k8s_secret_name: &str,
    k8s_secret_data_key: &str,
) -> Result<()> {
    info!(
        namespace = k8s_namespace,
        secret_name = k8s_secret_name,
        secret_data_key = k8s_secret_data_key,
        "Creating datastore key"
    );
    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client.clone(), k8s_namespace);

    // Generate a random datastore key & encode it into unpadded base64 as will be expected by
    // consumers of the secret we are about to write.
    let key_bytes: Vec<_> = thread_rng()
        .sample_iter(Standard)
        .take(AES_128_GCM.key_len())
        .collect();
    let secret_content = base64::encode_engine(key_bytes, &STANDARD_NO_PAD);

    // Write the secret.
    secrets_api
        .create(
            &PostParams {
                dry_run,
                ..Default::default()
            },
            &Secret {
                metadata: ObjectMeta {
                    namespace: Some(k8s_namespace.to_string()),
                    name: Some(k8s_secret_name.to_string()),
                    ..ObjectMeta::default()
                },
                string_data: Some(BTreeMap::from([(
                    k8s_secret_data_key.to_string(),
                    secret_content,
                )])),
                ..Secret::default()
            },
        )
        .await
        .context("couldn't write datastore key secret")?;
    Ok(())
}

async fn datastore_from_opts(
    command_line_options: &CommandLineOptions,
    config_file: &ConfigFile,
    kube_client: Option<&kube::Client>,
) -> Result<Datastore<RealClock>> {
    let pool = database_pool(
        &config_file.common_config.database,
        command_line_options
            .common_options
            .database_password
            .as_deref(),
    )
    .await?;

    datastore(
        pool,
        RealClock::default(),
        &command_line_options.datastore_keys(kube_client).await?,
        config_file.common_config().database.dry_run_mode || command_line_options.dry_run,
    )
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus_cli",
    about = "Janus CLI tool",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct CommandLineOptions {
    #[clap(subcommand)]
    cmd: Command,

    #[clap(flatten)]
    common_options: CommonBinaryOptions,

    /// When in dry-run mode, the tool will print out what it would do but will not make any real,
    /// permanent changes.
    #[clap(long, default_value = "false")]
    dry_run: bool,

    /// The Kubernetes namespace where secrets are stored.
    #[clap(
        long,
        env = "SECRETS_K8S_NAMESPACE",
        num_args = 1,
        long_help = "Kubernetes namespace where the datastore key is stored. Required if \
        --datastore-keys is not set or if command is create-datastore-key."
    )]
    secrets_k8s_namespace: Option<String>,

    /// Kubernetes secret containing the datastore key(s).
    #[clap(
        long,
        env = "DATASTORE_KEYS_SECRET_NAME",
        num_args = 1,
        default_value = "datastore-key"
    )]
    datastore_keys_secret_name: String,

    /// Key into data of datastore key Kubernetes secret
    #[clap(
        long,
        env = "DATASTORE_KEYS_SECRET_KEY",
        num_args = 1,
        help = "Key into data of datastore key Kubernetes secret",
        default_value = "datastore_key"
    )]
    datastore_keys_secret_data_key: String,
}

impl CommandLineOptions {
    /// Fetch the datastore keys from the options. If --secrets-k8s-namespace is set, keys are fetched
    /// from a secret therein. Otherwise, returns the keys provided to --datastore-keys. If neither was
    /// set, returns an error.
    async fn datastore_keys(&self, kube_client: Option<&kube::Client>) -> Result<Vec<String>> {
        if let (Some(ref secrets_namespace), Some(kube_client)) =
            (&self.secrets_k8s_namespace, kube_client)
        {
            fetch_datastore_keys(
                kube_client,
                secrets_namespace,
                &self.datastore_keys_secret_name,
                &self.datastore_keys_secret_data_key,
            )
            .await
            .context("failed to fetch datastore key(s) from Kubernetes secret")
        } else if !self.common_options.datastore_keys.is_empty() {
            Ok(self.common_options.datastore_keys.clone())
        } else {
            Err(anyhow!(
                "Either --datastore-keys or --secrets-k8s-namespace must be set"
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(flatten)]
    common_config: CommonConfig,
}

impl BinaryConfig for ConfigFile {
    fn common_config(&self) -> &CommonConfig {
        &self.common_config
    }

    fn common_config_mut(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

const STANDARD_NO_PAD: FastPortable = FastPortable::from(&STANDARD, NO_PAD);

#[cfg(test)]
mod tests {
    use super::{fetch_datastore_keys, CommandLineOptions, ConfigFile};
    use crate::{Command, STANDARD_NO_PAD};
    use clap::CommandFactory;
    use janus_aggregator::{
        binary_utils::CommonBinaryOptions,
        config::test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        config::CommonConfig,
        datastore::{
            test_util::{
                ephemeral_datastore, ephemeral_datastore_with_dry_run, ephemeral_db_handle,
            },
            Datastore,
        },
        task::{test_util::TaskBuilder, QueryType, Task},
    };
    use janus_core::{task::VdafInstance, test_util::kubernetes, time::RealClock};
    use janus_messages::{Role, TaskId};
    use ring::aead::{UnboundKey, AES_128_GCM};
    use std::{
        collections::HashMap,
        io::Write,
        net::{Ipv4Addr, SocketAddr},
    };
    use tempfile::NamedTempFile;

    #[test]
    fn verify_app() {
        CommandLineOptions::command().debug_assert()
    }

    #[tokio::test]
    async fn options_datastore_keys() {
        // Prep: create a Kubernetes cluster and put a secret in it
        let k8s_cluster = kubernetes::EphemeralCluster::create();
        let kube_client = k8s_cluster.cluster().client().await;
        super::create_datastore_key(
            false,
            &kube_client,
            "default",
            "secret-name",
            "secret-data-key",
        )
        .await
        .unwrap();

        let expected_datastore_keys =
            Vec::from(["datastore-key-1".to_string(), "datastore-key-2".to_string()]);

        // Keys provided at command line, not present in k8s
        let mut binary_options = CommonBinaryOptions::default();
        binary_options.datastore_keys = expected_datastore_keys.clone();

        let options = CommandLineOptions {
            cmd: Command::CreateDatastoreKey,
            common_options: binary_options,
            dry_run: false,
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "secret-data-key".to_string(),
            secrets_k8s_namespace: None,
        };

        assert_eq!(
            options.datastore_keys(Some(&kube_client)).await.unwrap(),
            expected_datastore_keys
        );

        // Keys not provided at command line, present in k8s
        let options = CommandLineOptions {
            cmd: Command::CreateDatastoreKey,
            common_options: CommonBinaryOptions::default(),
            dry_run: false,
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "secret-data-key".to_string(),
            secrets_k8s_namespace: Some("default".to_string()),
        };

        assert_eq!(
            options
                .datastore_keys(Some(&kube_client))
                .await
                .unwrap()
                .len(),
            1
        );

        // Neither flag provided
        let options = CommandLineOptions {
            cmd: Command::CreateDatastoreKey,
            common_options: CommonBinaryOptions::default(),
            dry_run: false,
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "secret-data-key".to_string(),
            secrets_k8s_namespace: None,
        };

        options
            .datastore_keys(Some(&kube_client))
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn write_schema() {
        let db_handle = ephemeral_db_handle();
        let ds = db_handle.datastore(RealClock::default());

        // Verify that the query we will run later returns an error if there is no database schema written.
        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap_err();

        // Run the program logic.
        super::write_schema(&ds).await.unwrap();

        // Verify that the schema was written (by running a query that would fail if it weren't).
        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn write_schema_dry_run() {
        let db_handle = ephemeral_db_handle();
        let ds = db_handle.datastore_with_dry_run(RealClock::default(), true);

        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap_err();

        super::write_schema(&ds).await.unwrap();

        // Verify that no schema was written (by running a query that would fail if it weren't).
        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap_err();
    }

    fn task_hashmap_from_slice(tasks: Vec<Task>) -> HashMap<TaskId, Task> {
        tasks.into_iter().map(|task| (*task.id(), task)).collect()
    }

    async fn setup_provision_tasks_testcase(
        ds: &Datastore<RealClock>,
        tasks: &[Task],
    ) -> Vec<Task> {
        // Write tasks to a temporary file.
        let mut tasks_file = NamedTempFile::new().unwrap();
        tasks_file
            .write_all(serde_yaml::to_string(&tasks).unwrap().as_ref())
            .unwrap();
        let tasks_path = tasks_file.into_temp_path();

        // Run the program logic.
        super::provision_tasks(ds, &tasks_path, false)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn provision_tasks() {
        let (ds, _db_handle) = ephemeral_datastore(RealClock::default()).await;

        let tasks = Vec::from([
            TaskBuilder::new(
                QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build(),
            TaskBuilder::new(
                QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Sum { bits: 64 },
                Role::Helper,
            )
            .build(),
        ]);

        let written_tasks = setup_provision_tasks_testcase(&ds, &tasks).await;

        // Verify that the expected tasks were written.
        let want_tasks = task_hashmap_from_slice(tasks);
        let written_tasks = task_hashmap_from_slice(written_tasks);
        let got_tasks = task_hashmap_from_slice(
            ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
                .await
                .unwrap(),
        );
        assert_eq!(want_tasks, got_tasks);
        assert_eq!(want_tasks, written_tasks);
    }

    #[tokio::test]
    async fn provision_task_dry_run() {
        let (ds, _db_handle) = ephemeral_datastore_with_dry_run(RealClock::default(), true).await;

        let tasks = Vec::from([TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build()]);

        let written_tasks = setup_provision_tasks_testcase(&ds, &tasks).await;

        let want_tasks = task_hashmap_from_slice(tasks);
        let written_tasks = task_hashmap_from_slice(written_tasks);
        assert_eq!(want_tasks, written_tasks);
        let got_tasks = task_hashmap_from_slice(
            ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
                .await
                .unwrap(),
        );
        assert!(got_tasks.is_empty());
    }

    #[tokio::test]
    async fn replace_task() {
        let tasks = Vec::from([
            TaskBuilder::new(
                QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build(),
            TaskBuilder::new(
                QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Sum { bits: 64 },
                Role::Helper,
            )
            .build(),
        ]);

        let (ds, _db_handle) = ephemeral_datastore(RealClock::default()).await;

        let mut tasks_file = NamedTempFile::new().unwrap();
        tasks_file
            .write_all(serde_yaml::to_string(&tasks).unwrap().as_ref())
            .unwrap();

        super::provision_tasks(&ds, &tasks_file.into_temp_path(), false)
            .await
            .unwrap();

        // Construct a "new" task with a previously existing ID.
        let replacement_task = TaskBuilder::new(
            QueryType::FixedSize {
                max_batch_size: 100,
            },
            VdafInstance::Prio3Aes128CountVec { length: 4 },
            Role::Leader,
        )
        .with_id(*tasks[0].id())
        .build();

        let mut replacement_tasks_file = NamedTempFile::new().unwrap();
        replacement_tasks_file
            .write_all(
                serde_yaml::to_string(&[&replacement_task])
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();

        let written_tasks =
            super::provision_tasks(&ds, &replacement_tasks_file.into_temp_path(), false)
                .await
                .unwrap();
        assert_eq!(written_tasks.len(), 1);
        assert_eq!(written_tasks[0].id(), tasks[0].id());

        // Verify that the expected tasks were written.
        let got_tasks = task_hashmap_from_slice(
            ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
                .await
                .unwrap(),
        );
        let want_tasks = HashMap::from([
            (*replacement_task.id(), replacement_task),
            (*tasks[1].id(), tasks[1].clone()),
        ]);

        assert_eq!(want_tasks, got_tasks);
    }

    #[tokio::test]
    async fn provision_task_with_generated_values() {
        // YAML contains no task ID, VDAF verify keys, aggregator auth tokens, collector auth tokens
        // or HPKE keys.
        let serialized_task_yaml = r#"
- aggregator_endpoints:
  - https://leader
  - https://helper
  query_type: TimeInterval
  vdaf: !Prio3Aes128Sum
    bits: 2
  role: Leader
  vdaf_verify_keys:
  max_batch_query_count: 1
  task_expiration: 9000000000
  min_batch_size: 10
  time_precision: 300
  tolerable_clock_skew: 600
  input_share_aad_public_share_length_prefix: false
  collector_hpke_config:
    id: 23
    kem_id: X25519HkdfSha256
    kdf_id: HkdfSha256
    aead_id: Aes128Gcm
    public_key: 8lAqZ7OfNV2Gi_9cNE6J9WRmPbO-k1UPtu2Bztd0-yc
  aggregator_auth_tokens: []
  collector_auth_tokens: []
  hpke_keys: []
- aggregator_endpoints:
  - https://leader
  - https://helper
  query_type: TimeInterval
  vdaf: !Prio3Aes128Sum
    bits: 2
  role: Helper
  vdaf_verify_keys:
  max_batch_query_count: 1
  task_expiration: 9000000000
  min_batch_size: 10
  time_precision: 300
  tolerable_clock_skew: 600
  input_share_aad_public_share_length_prefix: false
  collector_hpke_config:
    id: 23
    kem_id: X25519HkdfSha256
    kdf_id: HkdfSha256
    aead_id: Aes128Gcm
    public_key: 8lAqZ7OfNV2Gi_9cNE6J9WRmPbO-k1UPtu2Bztd0-yc
  aggregator_auth_tokens: []
  collector_auth_tokens: []
  hpke_keys: []
"#;

        let (ds, _db_handle) = ephemeral_datastore(RealClock::default()).await;

        let mut tasks_file = NamedTempFile::new().unwrap();
        tasks_file
            .write_all(serialized_task_yaml.as_bytes())
            .unwrap();
        let tasks_file_path = tasks_file.into_temp_path();

        super::provision_tasks(
            &ds,
            &tasks_file_path,
            // do not generate missing parameters
            false,
        )
        .await
        // Should fail because parameters are omitted from task YAML
        .unwrap_err();

        let written_tasks = super::provision_tasks(
            &ds,
            &tasks_file_path,
            // generate missing parameters
            true,
        )
        .await
        .unwrap();

        // Verify that the expected tasks were written.
        let got_tasks = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap();

        assert_eq!(got_tasks.len(), 2);

        for task in &got_tasks {
            match task.role() {
                Role::Leader => assert_eq!(task.collector_auth_tokens().len(), 1),
                Role::Helper => assert!(task.collector_auth_tokens().is_empty()),
                role => panic!("unexpected role {role}"),
            }
        }

        assert_eq!(
            task_hashmap_from_slice(written_tasks),
            task_hashmap_from_slice(got_tasks)
        );
    }

    #[tokio::test]
    async fn create_datastore_key() {
        let k8s_cluster = kubernetes::EphemeralCluster::create();
        let kube_client = k8s_cluster.cluster().client().await;

        // Create a datastore key.
        const NAMESPACE: &str = "default";
        const SECRET_NAME: &str = "secret-name";
        const SECRET_DATA_KEY: &str = "secret-data-key";
        super::create_datastore_key(
            /* dry_run */ false,
            &kube_client,
            NAMESPACE,
            SECRET_NAME,
            SECRET_DATA_KEY,
        )
        .await
        .unwrap();

        // Verify that the secret was created.
        let secret_data =
            fetch_datastore_keys(&kube_client, NAMESPACE, SECRET_NAME, SECRET_DATA_KEY)
                .await
                .unwrap();

        // Verify that the written secret data can be parsed as a comma-separated list of datastore
        // keys.
        let datastore_key_bytes = base64::decode_engine(&secret_data[0], &STANDARD_NO_PAD).unwrap();
        UnboundKey::new(&AES_128_GCM, &datastore_key_bytes).unwrap();
    }

    #[tokio::test]
    async fn create_datastore_key_dry_run() {
        let k8s_cluster = kubernetes::EphemeralCluster::create();
        let kube_client = k8s_cluster.cluster().client().await;

        const NAMESPACE: &str = "default";
        const SECRET_NAME: &str = "secret-name";
        const SECRET_DATA_KEY: &str = "secret-data-key";
        super::create_datastore_key(
            /* dry_run */ true,
            &kube_client,
            NAMESPACE,
            SECRET_NAME,
            SECRET_DATA_KEY,
        )
        .await
        .unwrap();

        // Verify that no secret was created.
        fetch_datastore_keys(&kube_client, NAMESPACE, SECRET_NAME, SECRET_DATA_KEY)
            .await
            .unwrap_err();
    }

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(ConfigFile {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
                health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            },
        })
    }
}
