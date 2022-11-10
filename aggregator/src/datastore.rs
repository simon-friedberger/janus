//! Janus datastore (durable storage) implementation.

use self::models::{
    AcquiredAggregationJob, AcquiredCollectJob, AggregateShareJob, AggregationJob, AggregatorRole,
    BatchAggregation, CollectJob, CollectJobState, CollectJobStateCode, LeaderStoredReport, Lease,
    LeaseToken, OutstandingBatch, ReportAggregation, ReportAggregationState,
    ReportAggregationStateCode, SqlInterval,
};
#[cfg(test)]
use crate::aggregator::aggregation_job_creator::VdafHasAggregationParameter;
use crate::{
    messages::TimeExt,
    task::{self, Task},
    SecretBytes,
};
use anyhow::anyhow;
use futures::future::try_join_all;
use janus_core::{
    hpke::HpkePrivateKey,
    task::{AuthenticationToken, VdafInstance},
    time::Clock,
};
use janus_messages::{
    query_type::QueryType, AggregationJobId, BatchId, Duration, Extension, HpkeCiphertext,
    HpkeConfig, Interval, ReportId, ReportIdChecksum, ReportShare, Role, TaskId, Time,
    UploadReportMetadata,
};
use opentelemetry::{metrics::Counter, Context, KeyValue};
use postgres_types::{Json, ToSql};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use ring::aead::{self, LessSafeKey, AES_128_GCM};
use std::{
    collections::HashMap, convert::TryFrom, fmt::Display, future::Future, io::Cursor, mem::size_of,
    ops::RangeInclusive, pin::Pin,
};
use tokio::try_join;
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row};
use url::Url;
use uuid::Uuid;

// TODO(#196): retry network-related & other transient failures once we know what they look like

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore<C: Clock> {
    pool: deadpool_postgres::Pool,
    crypter: Crypter,
    clock: C,
    transaction_status_counter: Counter<u64>,
}

impl<C: Clock> Datastore<C> {
    /// new creates a new Datastore using the given Client for backing storage. It is assumed that
    /// the Client is connected to a database with a compatible version of the Janus database schema.
    pub fn new(pool: deadpool_postgres::Pool, crypter: Crypter, clock: C) -> Datastore<C> {
        let meter = opentelemetry::global::meter("janus_aggregator");
        let transaction_status_counter = meter
            .u64_counter("janus_database_transactions_total")
            .with_description("Count of database transactions run, with their status.")
            .init();

        // Initialize counters with desired status labels. This causes Prometheus to see the first
        // non-zero value we record.
        for status in ["success", "error_conflict", "error_db", "error_other"] {
            transaction_status_counter.add(
                &Context::current(),
                0,
                &[KeyValue::new("status", status)],
            );
        }

        Self {
            pool,
            crypter,
            clock,
            transaction_status_counter,
        }
    }

    /// run_tx runs a transaction, whose body is determined by the given function. The transaction
    /// is committed if the body returns a successful value, and rolled back if the body returns an
    /// error value.
    ///
    /// The datastore will automatically retry some failures (e.g. serialization failures) by
    /// rolling back & retrying with a new transaction, so the given function should support being
    /// called multiple times. Values read from the transaction should not be considered as
    /// "finalized" until the transaction is committed, i.e. after `run_tx` is run to completion.
    pub async fn run_tx<F, T>(&self, f: F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        loop {
            let rslt = self.run_tx_once(&f).await;
            match rslt.as_ref() {
                Ok(_) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[KeyValue::new("status", "success")],
                ),
                Err(err) if err.is_serialization_failure() => {
                    self.transaction_status_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("status", "error_conflict")],
                    );
                    continue;
                }
                Err(Error::Db(_)) | Err(Error::Pool(_)) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[KeyValue::new("status", "error_db")],
                ),
                Err(_) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[KeyValue::new("status", "error_other")],
                ),
            }
            return rslt;
        }
    }

    #[tracing::instrument(skip(self, f), err)]
    async fn run_tx_once<F, T>(&self, f: &F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        // Open transaction.
        let mut client = self.pool.get().await?;
        let tx = Transaction {
            tx: client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?,
            crypter: &self.crypter,
            clock: &self.clock,
        };

        // Run user-provided function with the transaction.
        let rslt = f(&tx).await?;

        // Commit.
        tx.tx.commit().await?;
        Ok(rslt)
    }

    /// Write a task into the datastore.
    #[cfg(feature = "test-util")]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        self.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
    }
}

/// Transaction represents an ongoing datastore transaction.
pub struct Transaction<'a, C: Clock> {
    tx: deadpool_postgres::Transaction<'a>,
    crypter: &'a Crypter,
    clock: &'a C,
}

impl<C: Clock> Transaction<'_, C> {
    /// Writes a task into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        let endpoints: Vec<_> = task
            .aggregator_endpoints()
            .iter()
            .map(Url::as_str)
            .collect();

        // Main task insert.
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (task_id, aggregator_role, aggregator_endpoints, query_type,
                    vdaf, max_batch_query_count, task_expiration, min_batch_size, time_precision,
                    tolerable_clock_skew, collector_hpke_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &task.id().as_ref(),
                    /* aggregator_role */ &AggregatorRole::from_role(*task.role())?,
                    /* aggregator_endpoints */ &endpoints,
                    /* query_type */ &Json(task.query_type()),
                    /* vdaf */ &Json(task.vdaf()),
                    /* max_batch_query_count */
                    &i64::try_from(task.max_batch_query_count())?,
                    /* task_expiration */ &task.task_expiration().as_naive_date_time(),
                    /* min_batch_size */ &i64::try_from(task.min_batch_size())?,
                    /* time_precision */
                    &i64::try_from(task.time_precision().as_seconds())?,
                    /* tolerable_clock_skew */
                    &i64::try_from(task.tolerable_clock_skew().as_seconds())?,
                    /* collector_hpke_config */ &task.collector_hpke_config().get_encoded(),
                ],
            )
            .await?;

        // Aggregator auth tokens.
        let mut aggregator_auth_token_ords = Vec::new();
        let mut aggregator_auth_tokens = Vec::new();
        for (ord, token) in task.aggregator_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_aggregator_auth_token = self.crypter.encrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            aggregator_auth_token_ords.push(ord);
            aggregator_auth_tokens.push(encrypted_aggregator_auth_token);
        }
        let stmt = self.tx.prepare_cached(
                "INSERT INTO task_aggregator_auth_tokens (task_id, ord, token)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
            )
            .await?;
        let aggregator_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &aggregator_auth_token_ords,
            /* tokens */ &aggregator_auth_tokens,
        ];
        let aggregator_auth_tokens_future = self.tx.execute(&stmt, aggregator_auth_tokens_params);

        // Collector auth tokens.
        let mut collector_auth_token_ords = Vec::new();
        let mut collector_auth_tokens = Vec::new();
        for (ord, token) in task.collector_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_collector_auth_token = self.crypter.encrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            collector_auth_token_ords.push(ord);
            collector_auth_tokens.push(encrypted_collector_auth_token);
        }
        let stmt = self.tx.prepare_cached(
            "INSERT INTO task_collector_auth_tokens (task_id, ord, token)
            SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
        ).await?;
        let collector_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &collector_auth_token_ords,
            /* tokens */ &collector_auth_tokens,
        ];
        let collector_auth_tokens_future = self.tx.execute(&stmt, collector_auth_tokens_params);

        // HPKE keys.
        let mut hpke_config_ids: Vec<i16> = Vec::new();
        let mut hpke_configs: Vec<Vec<u8>> = Vec::new();
        let mut hpke_private_keys: Vec<Vec<u8>> = Vec::new();
        for (hpke_config, hpke_private_key) in task.hpke_keys().values() {
            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&u8::from(*hpke_config.id()).to_be_bytes());

            let encrypted_hpke_private_key = self.crypter.encrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                hpke_private_key.as_ref(),
            )?;

            hpke_config_ids.push(u8::from(*hpke_config.id()) as i16);
            hpke_configs.push(hpke_config.get_encoded());
            hpke_private_keys.push(encrypted_hpke_private_key);
        }
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO task_hpke_keys (task_id, config_id, config, private_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::SMALLINT[], $3::BYTEA[], $4::BYTEA[])",
            )
            .await?;
        let hpke_configs_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* config_id */ &hpke_config_ids,
            /* configs */ &hpke_configs,
            /* private_keys */ &hpke_private_keys,
        ];
        let hpke_configs_future = self.tx.execute(&stmt, hpke_configs_params);

        // VDAF verification keys.
        let mut vdaf_verify_keys: Vec<Vec<u8>> = Vec::new();
        for vdaf_verify_key in task.vdaf_verify_keys() {
            let encrypted_vdaf_verify_key = self.crypter.encrypt(
                "task_vdaf_verify_keys",
                task.id().as_ref(),
                "vdaf_verify_key",
                vdaf_verify_key.as_ref(),
            )?;
            vdaf_verify_keys.push(encrypted_vdaf_verify_key);
        }
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO task_vdaf_verify_keys (task_id, vdaf_verify_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BYTEA[])",
            )
            .await?;
        let vdaf_verify_keys_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* vdaf_verify_keys */ &vdaf_verify_keys,
        ];
        let vdaf_verify_keys_future = self.tx.execute(&stmt, vdaf_verify_keys_params);

        try_join!(
            aggregator_auth_tokens_future,
            collector_auth_tokens_future,
            hpke_configs_future,
            vdaf_verify_keys_future
        )?;

        Ok(())
    }

    /// Deletes a task from the datastore. Fails if there is any data related to the task, such as
    /// client reports, aggregations, etc.
    #[tracing::instrument(skip(self))]
    pub async fn delete_task(&self, task_id: &TaskId) -> Result<(), Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];

        // Clean up dependent tables first.
        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_aggregator_auth_tokens_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_collector_auth_tokens_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_hpke_keys_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_vdaf_verify_keys_future = self.tx.execute(&stmt, params);

        try_join!(
            task_aggregator_auth_tokens_future,
            task_collector_auth_tokens_future,
            task_hpke_keys_future,
            task_vdaf_verify_keys_future,
        )?;

        // Then clean up tasks table itself.
        let stmt = self
            .tx
            .prepare_cached("DELETE FROM tasks WHERE task_id = $1")
            .await?;
        check_single_row_mutation(self.tx.execute(&stmt, params).await?)?;
        Ok(())
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task(&self, task_id: &TaskId) -> Result<Option<Task>, Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, min_batch_size, time_precision,
                    tolerable_clock_skew, collector_hpke_config
                FROM tasks WHERE task_id = $1",
            )
            .await?;
        let task_row = self.tx.query_opt(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT ord, token FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT ord, token FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT config_id, config, private_key FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let hpke_key_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT vdaf_verify_key FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let vdaf_verify_key_rows = self.tx.query(&stmt, params);

        let (
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        )?;
        task_row
            .map(|task_row| {
                self.task_from_rows(
                    task_id,
                    &task_row,
                    &aggregator_auth_token_rows,
                    &collector_auth_token_rows,
                    &hpke_key_rows,
                    &vdaf_verify_key_rows,
                )
            })
            .transpose()
    }

    /// Fetch all the tasks in the database.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_tasks(&self) -> Result<Vec<Task>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, min_batch_size, time_precision,
                    tolerable_clock_skew, collector_hpke_config
                FROM tasks",
            )
            .await?;
        let task_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_aggregator_auth_tokens.task_id),
                ord, token FROM task_aggregator_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_collector_auth_tokens.task_id),
                ord, token FROM task_collector_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_hpke_keys.task_id),
                config_id, config, private_key FROM task_hpke_keys",
            )
            .await?;
        let hpke_config_rows = self.tx.query(&stmt, &[]);

        let stmt = self.tx.prepare_cached(
            "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_vdaf_verify_keys.task_id),
            vdaf_verify_key FROM task_vdaf_verify_keys"
        ).await?;
        let vdaf_verify_key_rows = self.tx.query(&stmt, &[]);

        let (
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows
        )?;

        let mut task_row_by_id = Vec::new();
        for row in task_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            task_row_by_id.push((task_id, row));
        }

        let mut aggregator_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in aggregator_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            aggregator_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut collector_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in collector_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            collector_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut hpke_config_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in hpke_config_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            hpke_config_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut vdaf_verify_key_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in vdaf_verify_key_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            vdaf_verify_key_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        task_row_by_id
            .into_iter()
            .map(|(task_id, row)| {
                self.task_from_rows(
                    &task_id,
                    &row,
                    &aggregator_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &collector_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &hpke_config_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &vdaf_verify_key_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                )
            })
            .collect::<Result<_, _>>()
    }

    /// Construct a [`Task`] from the contents of the provided (tasks) `Row`,
    /// `hpke_aggregator_auth_tokens` rows, and `task_hpke_keys` rows.
    ///
    /// agg_auth_token_rows must be sorted in ascending order by `ord`.
    fn task_from_rows(
        &self,
        task_id: &TaskId,
        row: &Row,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
        hpke_key_rows: &[Row],
        vdaf_verify_key_rows: &[Row],
    ) -> Result<Task, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints = row
            .get::<_, Vec<String>>("aggregator_endpoints")
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
        let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
        let max_batch_query_count = row.get_bigint_and_convert("max_batch_query_count")?;
        let task_expiration = Time::from_naive_date_time(&row.get("task_expiration"));
        let min_batch_size = row.get_bigint_and_convert("min_batch_size")?;
        let time_precision = Duration::from_seconds(row.get_bigint_and_convert("time_precision")?);
        let tolerable_clock_skew =
            Duration::from_seconds(row.get_bigint_and_convert("tolerable_clock_skew")?);
        let collector_hpke_config = HpkeConfig::get_decoded(row.get("collector_hpke_config"))?;

        // Aggregator authentication tokens.
        let mut aggregator_auth_tokens = Vec::new();
        for row in aggregator_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_aggregator_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            aggregator_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                &encrypted_aggregator_auth_token,
            )?));
        }

        // Collector authentication tokens.
        let mut collector_auth_tokens = Vec::new();
        for row in collector_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_collector_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            collector_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                &encrypted_collector_auth_token,
            )?));
        }

        // HPKE keys.
        let mut hpke_configs = Vec::new();
        for row in hpke_key_rows {
            let config_id = u8::try_from(row.get::<_, i16>("config_id"))?;
            let config = HpkeConfig::get_decoded(row.get("config"))?;
            let encrypted_private_key: Vec<u8> = row.get("private_key");

            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&config_id.to_be_bytes());

            let private_key = HpkePrivateKey::new(self.crypter.decrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                &encrypted_private_key,
            )?);

            hpke_configs.push((config, private_key));
        }

        // VDAF verify keys.
        let mut vdaf_verify_keys = Vec::new();
        for row in vdaf_verify_key_rows {
            let encrypted_vdaf_verify_key: Vec<u8> = row.get("vdaf_verify_key");
            vdaf_verify_keys.push(SecretBytes::new(self.crypter.decrypt(
                "task_vdaf_verify_keys",
                task_id.as_ref(),
                "vdaf_verify_key",
                &encrypted_vdaf_verify_key,
            )?));
        }

        Ok(Task::new(
            *task_id,
            endpoints,
            query_type,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_keys,
            max_batch_query_count,
            task_expiration,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_configs,
        )?)
    }

    /// get_client_report retrieves a client report by ID.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn get_client_report<const L: usize, A>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
        report_id: &ReportId,
    ) -> Result<Option<LeaderStoredReport<L, A>>, Error>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    client_reports.client_timestamp,
                    client_reports.extensions,
                    client_reports.public_share,
                    client_reports.leader_input_share,
                    client_reports.helper_encrypted_input_share
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1 AND client_reports.report_id = $2",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* report_id */ &report_id.as_ref(),
                ],
            )
            .await?
            .map(|row| {
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));

                let encoded_extensions: Vec<u8> = row.get("extensions");
                let extensions: Vec<Extension> =
                    decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

                let encoded_public_share: Vec<u8> = row.get("public_share");
                let public_share =
                    A::PublicShare::get_decoded_with_param(&vdaf, &encoded_public_share)?;

                let encoded_leader_input_share: Vec<u8> = row.get("leader_input_share");
                let leader_input_share = A::InputShare::get_decoded_with_param(
                    &(vdaf, Role::Leader.index().unwrap()),
                    &encoded_leader_input_share,
                )?;

                let encoded_helper_input_share: Vec<u8> = row.get("helper_encrypted_input_share");
                let helper_encrypted_input_share =
                    HpkeCiphertext::get_decoded(&encoded_helper_input_share)?;

                Ok(LeaderStoredReport::new(
                    *task_id,
                    *report_id,
                    UploadReportMetadata::new(time, extensions),
                    public_share,
                    leader_input_share,
                    helper_encrypted_input_share,
                ))
            })
            .transpose()
    }

    /// `get_unaggregated_client_report_ids_for_task` returns some report IDs corresponding to
    /// unaggregated client reports for the task identified by the given task ID.
    ///
    /// This should only be used with VDAFs that have an aggregation parameter of the unit type.
    /// It relies on this assumption to find relevant reports without consulting collect jobs. For
    /// VDAFs that do have a different aggregation parameter,
    /// `get_unaggregated_client_report_ids_by_collect_for_task` should be used instead.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_ids_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<(ReportId, Time)>, Error> {
        // We choose to return the newest client reports first (LIFO). The goal is to maintain
        // throughput even if we begin to fall behind enough that reports are too old to be
        // aggregated.
        //
        // See https://medium.com/swlh/fifo-considered-harmful-793b76f98374 &
        // https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.376.5966&rep=rep1&type=pdf.

        // TODO(#269): allow the number of returned results to be controlled?

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT report_id, client_timestamp FROM client_reports
                LEFT JOIN report_aggregations ON report_aggregations.client_report_id = client_reports.id
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND report_aggregations.id IS NULL
                ORDER BY client_timestamp DESC LIMIT 5000",
            )
            .await?;
        let rows = self.tx.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let report_id_bytes: [u8; ReportId::LEN] = row
                    .get::<_, Vec<u8>>("report_id")
                    .try_into()
                    .map_err(|err| {
                        Error::DbState(format!("couldn't convert report_id value: {err:?}"))
                    })?;
                let report_id = ReportId::from(report_id_bytes);
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));
                Ok((report_id, time))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// `get_unaggregated_client_report_ids_by_collect_for_task` returns pairs of report IDs and
    /// aggregation parameters, corresponding to client reports that have not yet been aggregated,
    /// or not aggregated with a certain aggregation parameter, and for which there are collect
    /// jobs, for a given task.
    ///
    /// This should only be used with VDAFs with a non-unit type aggregation parameter. If a VDAF
    /// has the unit type as its aggregation parameter, then
    /// `get_unaggregated_client_report_ids_for_task` should be used instead. In such cases, it
    /// is not necessary to wait for a collect job to arrive before preparing reports.
    #[cfg(test)]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_ids_by_collect_for_task<const L: usize, A>(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<(ReportId, Time, A::AggregationParam)>, Error>
    where
        A: vdaf::Aggregator<L> + VdafHasAggregationParameter,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // TODO(#269): allow the number of returned results to be controlled?
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT DISTINCT report_id, client_timestamp, collect_jobs.aggregation_param
                FROM collect_jobs
                INNER JOIN client_reports
                ON collect_jobs.task_id = client_reports.task_id
                AND client_reports.client_timestamp <@ collect_jobs.batch_interval
                LEFT JOIN (
                    SELECT report_aggregations.id, report_aggregations.client_report_id,
                        aggregation_jobs.aggregation_param
                    FROM report_aggregations
                    INNER JOIN aggregation_jobs
                    ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                    WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                ) AS report_aggs
                ON report_aggs.client_report_id = client_reports.id
                AND report_aggs.aggregation_param = collect_jobs.aggregation_param
                WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND collect_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND collect_jobs.state = 'START'
                AND report_aggs.id IS NULL
                ORDER BY client_timestamp DESC LIMIT 5000",
            )
            .await?;
        let rows = self.tx.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let report_id_bytes: [u8; ReportId::LEN] = row
                    .get::<_, Vec<u8>>("report_id")
                    .try_into()
                    .map_err(|err| {
                        Error::DbState(format!("couldn't convert report_id value: {0:?}", err))
                    })?;
                let report_id = ReportId::from(report_id_bytes);
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));
                let agg_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Ok((report_id, time, agg_param))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// Return the number of reports in the provided task whose timestamp falls within the provided
    /// interval, regardless of whether the reports have been aggregated or collected.
    #[tracing::instrument(skip(self), err)]
    pub async fn count_client_reports_for_interval(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<u64, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT COUNT(1) AS count FROM client_reports
                WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND client_reports.client_timestamp <@ $2::TSRANGE",
            )
            .await?;
        let row = self
            .tx
            .query_one(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* batch_interval */ &SqlInterval::from(batch_interval),
                ],
            )
            .await?;

        Ok(row
            .get::<_, Option<i64>>("count")
            .unwrap_or_default()
            .try_into()?)
    }

    /// `put_client_report` stores a client report, the associated plaintext leader input share and
    /// the associated encrypted helper share.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_client_report<const L: usize, A>(
        &self,
        report: &LeaderStoredReport<L, A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_public_share = report.public_share().get_encoded();
        let encoded_leader_share = report.leader_input_share().get_encoded();
        let encoded_helper_share = report.helper_encrypted_input_share().get_encoded();
        let mut encoded_extensions = Vec::new();
        encode_u16_items(&mut encoded_extensions, &(), report.metadata().extensions());

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO client_reports (
                    task_id,
                    report_id,
                    client_timestamp,
                    extensions,
                    public_share,
                    leader_input_share,
                    helper_encrypted_input_share
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &report.task_id().get_encoded(),
                    /* report_id */ &report.id().get_encoded(),
                    /* client_timestamp */ &report.metadata().time().as_naive_date_time(),
                    /* extensions */ &encoded_extensions,
                    /* public_share */ &encoded_public_share,
                    /* leader_input_share */ &encoded_leader_share,
                    /* helper_encrypted_input_share */ &encoded_helper_share,
                ],
            )
            .await?;
        Ok(())
    }

    /// check_report_share_exists checks if a report share has been recorded in the datastore, given
    /// its associated task ID & report ID.
    ///
    /// This method is intended for use by aggregators acting in the helper role.
    #[tracing::instrument(skip(self), err)]
    pub async fn check_report_share_exists(
        &self,
        task_id: &TaskId,
        report_id: &ReportId,
    ) -> Result<bool, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT 1 FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.report_id = $2",
            )
            .await?;
        Ok(self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* report_id */ &report_id.as_ref(),
                ],
            )
            .await
            .map(|row| row.is_some())?)
    }

    /// put_report_share stores a report share, given its associated task ID.
    ///
    /// This method is intended for use by aggregators acting in the helper role; notably, it does
    /// not store extensions, public_share, or input_shares, as these are not required to be stored
    /// for the helper workflow (and the helper never observes the entire set of encrypted input
    /// shares, so it could not record the full client report in any case).
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_share(
        &self,
        task_id: &TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO client_reports (task_id, report_id, client_timestamp)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &task_id.get_encoded(),
                    /* report_id */ &report_share.metadata().id().as_ref(),
                    /* client_timestamp */
                    &report_share.metadata().time().as_naive_date_time(),
                ],
            )
            .await?;
        Ok(())
    }

    /// get_aggregation_job retrieves an aggregation job by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Option<AggregationJob<L, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT batch_identifier, aggregation_param, state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1 AND aggregation_jobs.aggregation_job_id = $2",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                ],
            )
            .await?
            .map(|row| Self::aggregation_job_from_row(task_id, aggregation_job_id, &row))
            .transpose()
    }

    /// get_aggregation_jobs_for_task_id returns all aggregation jobs for a given task ID.
    #[cfg(feature = "test-util")]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_jobs_for_task_id<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<AggregationJob<L, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregation_job_id, batch_identifier, aggregation_param, state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.tx
            .query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                Self::aggregation_job_from_row(
                    task_id,
                    &AggregationJobId::get_decoded(row.get("aggregation_job_id"))?,
                    &row,
                )
            })
            .collect()
    }

    fn aggregation_job_from_row<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        row: &Row,
    ) -> Result<AggregationJob<L, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Ok(AggregationJob::new(
            *task_id,
            *aggregation_job_id,
            Q::PartialBatchIdentifier::get_decoded(row.get("batch_identifier"))?,
            A::AggregationParam::get_decoded(row.get("aggregation_param"))?,
            row.get("state"),
        ))
    }

    /// acquire_incomplete_aggregation_jobs retrieves & acquires the IDs of unclaimed incomplete
    /// aggregation jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired
    /// with a "lease" that will time out; the desired duration of the lease is a parameter, and the
    /// returned lease provides the absolute timestamp at which the lease is no longer live.
    pub async fn acquire_incomplete_aggregation_jobs(
        &self,
        lease_duration: &Duration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredAggregationJob>>, Error> {
        let now = self.clock.now();
        let lease_expiry_time = now.add(lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        // TODO(#224): verify that this query is efficient. I am not sure if we would currently
        // scan over every (in-progress, not-leased) aggregation job for tasks where we are in the
        // HELPER role.
        // We generate the token on the DB to allow each acquired job to receive its own distinct
        // token. This is not strictly necessary as we only care about token collisions on a
        // per-row basis.
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET
                    lease_expiry = $1,
                    lease_token = gen_random_bytes(16),
                    lease_attempts = lease_attempts + 1
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                AND aggregation_jobs.id IN (SELECT aggregation_jobs.id FROM aggregation_jobs
                    JOIN tasks on tasks.id = aggregation_jobs.task_id
                    WHERE tasks.aggregator_role = 'LEADER'
                    AND aggregation_jobs.state = 'IN_PROGRESS'
                    AND aggregation_jobs.lease_expiry <= $2
                    ORDER BY aggregation_jobs.id DESC LIMIT $3)
                RETURNING tasks.task_id, tasks.query_type, tasks.vdaf,
                          aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_token,
                          aggregation_jobs.lease_attempts",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* lease_expiry */ &lease_expiry_time.as_naive_date_time(),
                    /* now */ &now.as_naive_date_time(),
                    /* limit */ &maximum_acquire_count,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                let aggregation_job_id =
                    AggregationJobId::get_decoded(row.get("aggregation_job_id"))?;
                let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
                let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
                let lease_token_bytes: [u8; LeaseToken::LEN] = row
                    .get::<_, Vec<u8>>("lease_token")
                    .try_into()
                    .map_err(|err| Error::DbState(format!("lease_token invalid: {:?}", err)))?;
                let lease_token = LeaseToken::from(lease_token_bytes);
                let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
                Ok(Lease::new(
                    AcquiredAggregationJob::new(task_id, aggregation_job_id, query_type, vdaf),
                    lease_expiry_time,
                    lease_token,
                    lease_attempts,
                ))
            })
            .collect()
    }

    /// release_aggregation_job releases an acquired (via e.g. acquire_incomplete_aggregation_jobs)
    /// aggregation job. It returns an error if the aggregation job has no current lease.
    pub async fn release_aggregation_job(
        &self,
        lease: &Lease<AcquiredAggregationJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                  AND tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND aggregation_jobs.lease_expiry = $3
                  AND aggregation_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* task_id */ &lease.leased().task_id().as_ref(),
                        /* aggregation_job_id */
                        &lease.leased().aggregation_job_id().as_ref(),
                        /* lease_expiry */ &lease.lease_expiry_time().as_naive_date_time(),
                        /* lease_token */ &lease.lease_token().as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// put_aggregation_job stores an aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO aggregation_jobs
                (task_id, aggregation_job_id, batch_identifier, aggregation_param, state)
            VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &aggregation_job.task_id().as_ref(),
                    /* aggregation_job_id */ &aggregation_job.id().as_ref(),
                    /* batch_identifier */ &aggregation_job.batch_identifier().get_encoded(),
                    /* aggregation_param */
                    &aggregation_job.aggregation_parameter().get_encoded(),
                    /* state */ &aggregation_job.state(),
                ],
            )
            .await?;
        Ok(())
    }

    /// update_aggregation_job updates a stored aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET
                    batch_identifier = $1,
                    aggregation_param = $2,
                    state = $3
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $4) AND aggregation_job_id = $5",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* batch_identifier */
                        &aggregation_job.batch_identifier().get_encoded(),
                        /* aggregation_param */
                        &aggregation_job.aggregation_parameter().get_encoded(),
                        /* state */ &aggregation_job.state(),
                        /* task_id */ &aggregation_job.task_id().as_ref(),
                        /* aggregation_job_id */
                        &aggregation_job.id().as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// get_report_aggregation gets a report aggregation by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
    ) -> Result<Option<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.report_id, client_reports.client_timestamp,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                  AND client_reports.report_id = $3",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                    /* task_id */ &task_id.as_ref(),
                    /* report_id */ &report_id.as_ref(),
                ],
            )
            .await?
            .map(|row| {
                Self::report_aggregation_from_row(
                    vdaf,
                    role,
                    task_id,
                    aggregation_job_id,
                    report_id,
                    &row,
                )
            })
            .transpose()
    }

    /// get_report_aggregations_for_aggregation_job retrieves all report aggregations associated
    /// with a given aggregation job, ordered by their natural ordering.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregations_for_aggregation_job<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Vec<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.report_id, client_reports.client_timestamp,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                ORDER BY report_aggregations.ord ASC"
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                    /* task_id */ &task_id.as_ref(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let report_id_bytes: [u8; ReportId::LEN] = row
                    .get::<_, Vec<u8>>("report_id")
                    .try_into()
                    .map_err(|err| {
                        Error::DbState(format!("couldn't convert report_id value: {err:?}"))
                    })?;
                let report_id = ReportId::from(report_id_bytes);
                Self::report_aggregation_from_row(
                    vdaf,
                    role,
                    task_id,
                    aggregation_job_id,
                    &report_id,
                    &row,
                )
            })
            .collect()
    }

    fn report_aggregation_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
        row: &Row,
    ) -> Result<ReportAggregation<L, A>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let time = Time::from_naive_date_time(&row.get("client_timestamp"));
        let ord: i64 = row.get("ord");
        let state: ReportAggregationStateCode = row.get("state");
        let prep_state_bytes: Option<Vec<u8>> = row.get("prep_state");
        let prep_msg_bytes: Option<Vec<u8>> = row.get("prep_msg");
        let out_share_bytes: Option<Vec<u8>> = row.get("out_share");
        let error_code: Option<i16> = row.get("error_code");

        let error_code = match error_code {
            Some(c) => {
                let c: u8 = c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {0}", err))
                })?;
                Some(c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {0}", err))
                })?)
            }
            None => None,
        };

        let agg_state = match state {
            ReportAggregationStateCode::Start => ReportAggregationState::Start,
            ReportAggregationStateCode::Waiting => {
                let agg_index = role.index().ok_or_else(|| {
                    Error::User(anyhow!("unexpected role: {}", role.as_str()).into())
                })?;
                let prep_state = A::PrepareState::get_decoded_with_param(
                    &(vdaf, agg_index),
                    &prep_state_bytes.ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state WAITING but prep_state is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let prep_msg = prep_msg_bytes
                    .map(|bytes| A::PrepareMessage::get_decoded_with_param(&prep_state, &bytes))
                    .transpose()?;
                ReportAggregationState::Waiting(prep_state, prep_msg)
            }
            ReportAggregationStateCode::Finished => ReportAggregationState::Finished(
                A::OutputShare::try_from(&out_share_bytes.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FINISHED but out_share is NULL".to_string(),
                    )
                })?)
                .map_err(|_| {
                    Error::Decode(CodecError::Other("couldn't decode output share".into()))
                })?,
            ),
            ReportAggregationStateCode::Failed => {
                ReportAggregationState::Failed(error_code.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FAILED but error_code is NULL".to_string(),
                    )
                })?)
            }
            ReportAggregationStateCode::Invalid => ReportAggregationState::Invalid,
        };

        Ok(ReportAggregation::new(
            *task_id,
            *aggregation_job_id,
            *report_id,
            time,
            ord,
            agg_state,
        ))
    }

    /// put_report_aggregation stores aggregation data for a single report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self.tx.prepare_cached(
            "INSERT INTO report_aggregations
            (aggregation_job_id, client_report_id, ord, state, prep_state, prep_msg, out_share, error_code)
            VALUES ((SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1),
                    (SELECT id FROM client_reports
                     WHERE task_id = (SELECT id FROM tasks WHERE task_id = $2)
                     AND report_id = $3),
                    $4, $5, $6, $7, $8, $9)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* aggregation_job_id */
                    &report_aggregation.aggregation_job_id().as_ref(),
                    /* task_id */ &report_aggregation.task_id().as_ref(),
                    /* report_id */ &report_aggregation.report_id().as_ref(),
                    /* ord */ &report_aggregation.ord(),
                    /* state */ &report_aggregation.state().state_code(),
                    /* prep_state */ &encoded_state_values.prep_state,
                    /* prep_msg */ &encoded_state_values.prep_msg,
                    /* out_share */ &encoded_state_values.output_share,
                    /* error_code */ &encoded_state_values.report_share_err,
                ],
            )
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn update_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE report_aggregations SET ord = $1, state = $2, prep_state = $3,
                prep_msg = $4, out_share = $5, error_code = $6
                WHERE aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $7)
                AND client_report_id = (SELECT id FROM client_reports
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $8)
                    AND report_id = $9)")
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* ord */ &report_aggregation.ord(),
                        /* state */ &report_aggregation.state().state_code(),
                        /* prep_state */ &encoded_state_values.prep_state,
                        /* prep_msg */ &encoded_state_values.prep_msg,
                        /* out_share */ &encoded_state_values.output_share,
                        /* error_code */ &encoded_state_values.report_share_err,
                        /* aggregation_job_id */
                        &report_aggregation.aggregation_job_id().as_ref(),
                        /* task_id */ &report_aggregation.task_id().as_ref(),
                        /* report_id */ &report_aggregation.report_id().as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// Returns the collect job for the provided UUID, or `None` if no such collect job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collect_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        collect_job_id: &Uuid,
    ) -> Result<Option<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    tasks.task_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.report_count,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE collect_jobs.collect_job_id = $1",
            )
            .await?;
        self.tx
            .query_opt(&stmt, &[&collect_job_id])
            .await?
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                Self::collect_job_from_row(&task_id, collect_job_id, &row)
            })
            .transpose()
    }

    /// If a collect job corresponding to the provided values exists, its UUID is returned, which
    /// may then be used to construct a collect job URI. If that collect job does not exist, returns
    /// `Ok(None)`.
    #[tracing::instrument(skip(self, aggregation_parameter), err)]
    pub(crate) async fn get_collect_job_id<const L: usize, A>(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<Uuid>, Error>
    where
        A: vdaf::Aggregator<L>,
        A::AggregationParam: Encode + std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT collect_job_id FROM collect_jobs
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND batch_interval = $2 AND aggregation_param = $3",
            )
            .await?;
        let row = self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* batch_interval */ &SqlInterval::from(batch_interval),
                    /* aggregation_param */ &aggregation_parameter.get_encoded(),
                ],
            )
            .await?;

        Ok(row.map(|row| row.get("collect_job_id")))
    }

    /// Returns all collect jobs for the given task which include the given timestamp.
    pub async fn get_collect_jobs_including_time<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    collect_jobs.collect_job_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.report_count,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collect_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* timestamp */ &timestamp.as_naive_date_time(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let collect_job_id = row.get("collect_job_id");
                Self::collect_job_from_row(task_id, &collect_job_id, &row)
            })
            .collect()
    }

    /// Returns all collect jobs for the given task whose collect intervals intersect with the given
    /// interval.
    pub async fn get_collect_jobs_jobs_intersecting_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
        interval: &Interval,
    ) -> Result<Vec<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    collect_jobs.collect_job_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.report_count,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collect_jobs.batch_interval && $2",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* collect_jobs.batch_interval */ &SqlInterval::from(interval),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let collect_job_id = row.get("collect_job_id");
                Self::collect_job_from_row(task_id, &collect_job_id, &row)
            })
            .collect()
    }

    fn collect_job_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        task_id: &TaskId,
        collect_job_id: &Uuid,
        row: &Row,
    ) -> Result<CollectJob<L, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let sql_interval: SqlInterval = row.try_get("batch_interval")?;
        let batch_interval = sql_interval.as_interval();
        let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
        let state: CollectJobStateCode = row.get("state");
        let report_count: Option<i64> = row.get("report_count");
        let helper_aggregate_share_bytes: Option<Vec<u8>> = row.get("helper_aggregate_share");
        let leader_aggregate_share_bytes: Option<Vec<u8>> = row.get("leader_aggregate_share");

        let state = match state {
            CollectJobStateCode::Start => CollectJobState::Start,

            CollectJobStateCode::Finished => {
                let report_count = u64::try_from(report_count.ok_or_else(|| {
                    Error::DbState(
                        "collect job in state FINISHED but report_count is NULL".to_string(),
                    )
                })?)?;
                let encrypted_helper_aggregate_share = HpkeCiphertext::get_decoded(
                    &helper_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collect job in state FINISHED but helper_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let leader_aggregate_share = A::AggregateShare::try_from(
                    &leader_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collect job is in state FINISHED but leader_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )
                .map_err(|err| {
                    Error::DbState(format!(
                        "leader_aggregate_share stored in database is invalid: {:?}",
                        err
                    ))
                })?;
                CollectJobState::Finished {
                    report_count,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                }
            }

            CollectJobStateCode::Abandoned => CollectJobState::Abandoned,

            CollectJobStateCode::Deleted => CollectJobState::Deleted,
        };

        Ok(CollectJob::new(
            *task_id,
            *collect_job_id,
            batch_interval,
            aggregation_param,
            state,
        ))
    }

    /// Stores a new collect job.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_collect_job<const L: usize, A>(
        &self,
        collect_job: &CollectJob<L, A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<L>,
        A::AggregationParam: Encode + std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO collect_jobs
                    (collect_job_id, task_id, batch_interval, aggregation_param, state)
                VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4, $5)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* collect_job_id */ &collect_job.collect_job_id(),
                    /* task_id */ &collect_job.task_id().as_ref(),
                    /* batch_interval */ &SqlInterval::from(collect_job.batch_interval()),
                    /* aggregation_param */
                    &collect_job.aggregation_parameter().get_encoded(),
                    /* state */ &collect_job.state().collect_job_state_code(),
                ],
            )
            .await?;

        Ok(())
    }

    /// acquire_incomplete_collect_jobs retrieves & acquires the IDs of unclaimed incomplete collect
    /// jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired with a "lease"
    /// that will time out; the desired duration of the lease is a parameter, and the lease
    /// expiration time is returned.
    pub async fn acquire_incomplete_collect_jobs(
        &self,
        lease_duration: &Duration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredCollectJob>>, Error> {
        let now = self.clock.now();
        let lease_expiry_time = now.add(lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        let stmt = self
            .tx
            .prepare_cached(
                r#"
WITH updated as (
    UPDATE collect_jobs SET lease_expiry = $1, lease_token = gen_random_bytes(16), lease_attempts = lease_attempts + 1
    FROM tasks
    WHERE collect_jobs.id IN (
        SELECT collect_jobs.id FROM collect_jobs
        -- Join on aggregation jobs with matching task ID and aggregation parameter
        INNER JOIN aggregation_jobs
            ON collect_jobs.aggregation_param = aggregation_jobs.aggregation_param
            AND collect_jobs.task_id = aggregation_jobs.task_id
        -- Join on report aggregations with matching aggregation job ID
        INNER JOIN report_aggregations
            ON report_aggregations.aggregation_job_id = aggregation_jobs.id
        -- Join on reports whose ID falls within the collect job batch interval and which are
        -- included in an aggregation job
        INNER JOIN client_reports
            ON client_reports.id = report_aggregations.client_report_id
            AND client_reports.client_timestamp <@ collect_jobs.batch_interval
        WHERE
            -- Constraint for tasks table in FROM position
            tasks.id = collect_jobs.task_id
            -- Only acquire collect jobs in a non-terminal state.
            AND collect_jobs.state = 'START'
            -- Do not acquire collect jobs with an unexpired lease
            AND collect_jobs.lease_expiry <= $2
        GROUP BY collect_jobs.id
        -- Do not acquire collect jobs where any associated aggregation jobs are not finished
        HAVING bool_and(aggregation_jobs.state != 'IN_PROGRESS')
        -- Honor maximum_acquire_count *after* winnowing down to runnable collect jobs
        LIMIT $3
    )
    RETURNING tasks.task_id, tasks.vdaf, collect_jobs.collect_job_id, collect_jobs.id, collect_jobs.lease_token, collect_jobs.lease_attempts
)
SELECT task_id, vdaf, collect_job_id, lease_token, lease_attempts FROM updated
-- TODO (#174): revisit collect job queueing behavior implied by this ORDER BY
ORDER BY id DESC
"#,
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* lease_expiry */ &lease_expiry_time.as_naive_date_time(),
                    /* now */ &now.as_naive_date_time(),
                    /* limit */ &maximum_acquire_count,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                let collect_job_id = row.get("collect_job_id");
                let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
                let lease_token_bytes: [u8; LeaseToken::LEN] = row
                    .get::<_, Vec<u8>>("lease_token")
                    .try_into()
                    .map_err(|err| Error::DbState(format!("lease_token invalid: {:?}", err)))?;
                let lease_token = LeaseToken::from(lease_token_bytes);
                let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
                Ok(Lease::new(
                    AcquiredCollectJob::new(task_id, collect_job_id, vdaf),
                    lease_expiry_time,
                    lease_token,
                    lease_attempts,
                ))
            })
            .collect()
    }

    /// release_collect_job releases an acquired (via e.g. acquire_incomplete_collect_jobs) collect
    /// job. It returns an error if the collect job has no current lease.
    pub async fn release_collect_job(
        &self,
        lease: &Lease<AcquiredCollectJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE collect_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = collect_jobs.task_id
                  AND tasks.task_id = $1
                  AND collect_jobs.collect_job_id = $2
                  AND collect_jobs.lease_expiry = $3
                  AND collect_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* task_id */ &lease.leased().task_id().as_ref(),
                        /* collect_job_id */ &lease.leased().collect_job_id(),
                        /* lease_expiry */ &lease.lease_expiry_time().as_naive_date_time(),
                        /* lease_token */ &lease.lease_token().as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// Updates an existing collect job.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn update_collect_job<const L: usize, A>(
        &self,
        collect_job: &CollectJob<L, A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<L>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let (report_count, leader_aggregate_share, helper_aggregate_share) = match collect_job
            .state()
        {
            CollectJobState::Start => {
                return Err(Error::InvalidParameter(
                    "cannot update collect job into START state",
                ));
            }
            CollectJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                let report_count: Option<i64> = Some(i64::try_from(*report_count)?);
                let leader_aggregate_share: Option<Vec<u8>> = Some(leader_aggregate_share.into());
                let helper_aggregate_share = Some(encrypted_helper_aggregate_share.get_encoded());

                (report_count, leader_aggregate_share, helper_aggregate_share)
            }
            CollectJobState::Abandoned | CollectJobState::Deleted => (None, None, None),
        };

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE collect_jobs SET
                    state = $1,
                    report_count = $2,
                    leader_aggregate_share = $3,
                    helper_aggregate_share = $4
                WHERE collect_job_id = $5",
            )
            .await?;

        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* state */ &collect_job.state().collect_job_state_code(),
                        /* report_count */ &report_count,
                        /* leader_aggregate_share */ &leader_aggregate_share,
                        /* helper_aggregate_share */ &helper_aggregate_share,
                        /* collect_job_id */ &collect_job.collect_job_id(),
                    ],
                )
                .await?,
        )
    }

    pub async fn get_batch_aggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<BatchAggregation<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregate_share, report_count, checksum
                FROM batch_aggregations
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_identifier = $2
                    AND aggregation_param = $3",
            )
            .await?;

        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* batch_identifier */ &batch_identifier.get_encoded(),
                    /* aggregation_param */ &aggregation_parameter.get_encoded(),
                ],
            )
            .await?
            .map(|row| {
                let aggregate_share = row.get_bytea_and_convert("aggregate_share")?;
                let report_count = row.get_bigint_and_convert("report_count")?;
                let checksum = ReportIdChecksum::get_decoded(row.get("checksum"))?;

                Ok(BatchAggregation::new(
                    *task_id,
                    batch_identifier.clone(),
                    aggregation_parameter.clone(),
                    aggregate_share,
                    report_count,
                    checksum,
                ))
            })
            .transpose()
    }

    /// Store a new `batch_aggregations` row in the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_batch_aggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        batch_aggregation: &BatchAggregation<L, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO batch_aggregations (task_id, batch_identifier,
                aggregation_param, aggregate_share, report_count, checksum)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &batch_aggregation.task_id().as_ref(),
                    /* batch_identifier */
                    &batch_aggregation.batch_identifier().get_encoded(),
                    /* aggregation_param */
                    &batch_aggregation.aggregation_parameter().get_encoded(),
                    /* aggregate_share */ &batch_aggregation.aggregate_share().into(),
                    /* report_count */
                    &i64::try_from(batch_aggregation.report_count())?,
                    /* checksum */ &batch_aggregation.checksum().get_encoded(),
                ],
            )
            .await?;

        Ok(())
    }

    /// Update an existing `batch_aggregations` row with the values from the provided batch
    /// aggregation.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_batch_aggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        batch_aggregation: &BatchAggregation<L, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE batch_aggregations
                SET aggregate_share = $1, report_count = $2, checksum = $3
                WHERE
                    task_id = (SELECT id from TASKS WHERE task_id = $4)
                    AND batch_identifier = $5
                    AND aggregation_param = $6",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* aggregate_share */
                        &batch_aggregation.aggregate_share().into(),
                        /* report_count */
                        &i64::try_from(batch_aggregation.report_count())?,
                        /* checksum */ &batch_aggregation.checksum().get_encoded(),
                        /* task_id */ &batch_aggregation.task_id().as_ref(),
                        /* batch_identifier */
                        &batch_aggregation.batch_identifier().get_encoded(),
                        /* aggregation_param */
                        &batch_aggregation.aggregation_parameter().get_encoded(),
                    ],
                )
                .await?,
        )?;

        Ok(())
    }

    /// Fetch an [`AggregateShareJob`] from the datastore corresponding to given parameters, or
    /// `None` if no such job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
        aggregation_parameter: &[u8],
    ) -> Result<Option<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT helper_aggregate_share, report_count, checksum FROM aggregate_share_jobs
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_interval = $2
                    AND aggregation_param = $3",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* batch_interval */
                    &SqlInterval::from(batch_interval),
                    /* aggregation_param */ &aggregation_parameter,
                ],
            )
            .await?
            .map(|row| {
                let aggregation_parameter =
                    A::AggregationParam::get_decoded(aggregation_parameter)?;
                Self::aggregate_share_job_from_row(
                    task_id,
                    batch_interval,
                    aggregation_parameter,
                    &row,
                )
            })
            .transpose()
    }

    /// Returns all aggregate share jobs for the given task which include the given timestamp.
    pub async fn get_aggregate_share_jobs_including_time<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_interval,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* timestamp */ &timestamp.as_naive_date_time(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let batch_interval: SqlInterval = row.get("batch_interval");
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Self::aggregate_share_job_from_row(
                    task_id,
                    &batch_interval.as_interval(),
                    aggregation_param,
                    &row,
                )
            })
            .collect()
    }

    /// Returns all aggregate share jobs for the given task whose collect intervals intersect with
    /// the given interval.
    pub async fn get_aggregate_share_jobs_intersecting_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
        interval: &Interval,
    ) -> Result<Vec<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_interval,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval && $2",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* interval */ &SqlInterval::from(interval),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let batch_interval: SqlInterval = row.get("batch_interval");
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Self::aggregate_share_job_from_row(
                    task_id,
                    &batch_interval.as_interval(),
                    aggregation_param,
                    &row,
                )
            })
            .collect()
    }

    fn aggregate_share_job_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        task_id: &TaskId,
        batch_interval: &Interval,
        aggregation_param: A::AggregationParam,
        row: &Row,
    ) -> Result<AggregateShareJob<L, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Ok(AggregateShareJob::new(
            *task_id,
            *batch_interval,
            aggregation_param,
            row.get_bytea_and_convert("helper_aggregate_share")?,
            row.get_bigint_and_convert("report_count")?,
            ReportIdChecksum::get_decoded(row.get("checksum"))?,
        ))
    }

    /// Put an `aggregate_share_job` row into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregate_share_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        job: &AggregateShareJob<L, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO aggregate_share_jobs (
                    task_id, batch_interval, aggregation_param,
                    helper_aggregate_share, report_count, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &job.task_id().as_ref(),
                    /* batch_interval */ &SqlInterval::from(job.batch_interval()),
                    /* aggregation_param */ &job.aggregation_parameter().get_encoded(),
                    /* helper_aggregate_share */ &job.helper_aggregate_share().into(),
                    /* report_count */ &i64::try_from(job.report_count())?,
                    /* checksum */ &job.checksum().get_encoded(),
                ],
            )
            .await?;

        Ok(())
    }

    /// Writes an outstanding batch. (This method does not take an [`OutstandingBatch`] as several
    /// of the included values are read implicitly.)
    pub async fn put_outstanding_batch(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO outstanding_batches (task_id, batch_id)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2)",
            )
            .await?;

        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ batch_id.as_ref(),
                ],
            )
            .await?;

        Ok(())
    }

    /// Retrieves all [`OutstandingBatch`]es for a given task.
    pub async fn get_outstanding_batches_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<OutstandingBatch>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT batch_id FROM outstanding_batches
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;

        try_join_all(
            self.tx
                .query(&stmt, &[/* task_id */ task_id.as_ref()])
                .await?
                .into_iter()
                .map(|row| async move {
                    let batch_id = BatchId::get_decoded(row.get("batch_id"))?;
                    let size = self.read_batch_size(task_id, &batch_id).await?;
                    Ok(OutstandingBatch::new(*task_id, batch_id, size))
                }),
        )
        .await
    }

    // Return value is an inclusive range [min_size, max_size], where:
    //  * min_size is the minimum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which have reached the FINISHED state.
    //  * max_size is the maximum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which are in a non-failure state (START/WAITING/FINISHED).
    async fn read_batch_size(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<RangeInclusive<usize>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "WITH batch_report_aggregation_statuses AS
                    (SELECT report_aggregations.state, COUNT(*) AS count FROM report_aggregations
                     JOIN aggregation_jobs ON report_aggregations.aggregation_job_id = aggregation_jobs.id
                     WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                     AND aggregation_jobs.batch_identifier = $2
                     GROUP BY report_aggregations.state)
                SELECT
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('FINISHED')) AS min_size,
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('START', 'WAITING', 'FINISHED')) AS max_size"
            )
            .await?;

        let row = self
            .tx
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ batch_id.as_ref(),
                ],
            )
            .await?;

        Ok(RangeInclusive::new(
            row.get::<_, Option<i64>>("min_size")
                .unwrap_or_default()
                .try_into()?,
            row.get::<_, Option<i64>>("max_size")
                .unwrap_or_default()
                .try_into()?,
        ))
    }
}

fn check_single_row_mutation(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetNotFound),
        1 => Ok(()),
        _ => panic!(
            "update which should have affected at most one row instead affected {} rows",
            row_count
        ),
    }
}

/// Extensions for [`tokio_postgres::row::Row`]
trait RowExt {
    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to the desired integer type `T`.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Like [`Self::get_bigint_and_convert`] but handles nullable columns.
    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BYTEA` from the row and then attempt to convert it to
    /// u64, treating it as an 8 byte big endian array.
    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> T: TryFrom<&'a [u8]>;
}

impl RowExt for Row {
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: i64 = self.try_get(idx)?;
        Ok(T::try_from(bigint)?)
    }

    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: Option<i64> = self.try_get(idx)?;
        Ok(bigint.map(|bigint| T::try_from(bigint)).transpose()?)
    }

    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display,
    {
        let encoded_u64: Vec<u8> = self.try_get(idx)?;

        // `u64::from_be_bytes` takes `[u8; 8]` and `Vec<u8>::try_into` will
        // fail unless the vector has exactly that length [1].
        //
        // [1]: https://doc.rust-lang.org/std/primitive.array.html#method.try_from-4
        Ok(u64::from_be_bytes(encoded_u64.try_into().map_err(
            // The error is just the vector that was rejected
            |_| Error::DbState("byte array in database does not have expected length".to_string()),
        )?))
    }

    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> T: TryFrom<&'a [u8]>,
    {
        let encoded: Vec<u8> = self.try_get(idx)?;
        let decoded = T::try_from(&encoded).map_err(|err| {
            Error::DbState(format!("{} stored in database is invalid: {:?}", idx, err))
        })?;
        Ok(decoded)
    }
}

/// A Crypter allows a Datastore to encrypt/decrypt sensitive values stored to the datastore. Values
/// are cryptographically bound to the specific location in the datastore in which they are stored.
/// Rollback protection is not provided.
pub struct Crypter {
    keys: Vec<LessSafeKey>,
}

impl Crypter {
    // The internal serialized format of a Crypter encrypted value is:
    //   ciphertext || tag || nonce
    // (the `ciphertext || tag` portion is as returned from `seal_in_place_append_tag`)

    /// Creates a new Crypter instance, using the given set of keys. The first key in the provided
    /// vector is considered to be the "primary" key, used for encryption operations; any of the
    /// provided keys can be used for decryption operations.
    ///
    /// The keys must be for the AES-128-GCM algorithm.
    pub fn new(keys: Vec<LessSafeKey>) -> Self {
        assert!(!keys.is_empty());
        for key in &keys {
            assert_eq!(key.algorithm(), &AES_128_GCM);
        }
        Self { keys }
    }

    fn encrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // It is safe to unwrap the key because we have already validated that keys is nonempty
        // in Crypter::new.
        Self::encrypt_with_key(self.keys.first().unwrap(), table, row, column, value)
    }

    fn encrypt_with_key(
        key: &LessSafeKey,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Generate a random nonce, compute AAD.
        let nonce_bytes: [u8; aead::NONCE_LEN] = random();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let aad = aead::Aad::from(Self::aad_bytes_for(table, row, column)?);

        // Encrypt, append nonce.
        let mut result = value.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut result)?;
        result.extend(nonce_bytes);
        Ok(result)
    }

    fn decrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if value.len() < aead::NONCE_LEN {
            return Err(Error::Crypt);
        }

        // TODO(https://github.com/rust-lang/rust/issues/90091): use `rsplit_array_ref` once it is stabilized.
        let (ciphertext_and_tag, nonce_bytes) = value.split_at(value.len() - aead::NONCE_LEN);
        let nonce_bytes: [u8; aead::NONCE_LEN] = nonce_bytes.try_into().unwrap();
        let aad_bytes = Self::aad_bytes_for(table, row, column)?;

        for key in &self.keys {
            let mut ciphertext_and_tag = ciphertext_and_tag.to_vec();
            if let Ok(plaintext) = key.open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(aad_bytes.clone()),
                &mut ciphertext_and_tag,
            ) {
                let len = plaintext.len();
                ciphertext_and_tag.truncate(len);
                return Ok(ciphertext_and_tag);
            }
        }
        Err(Error::Crypt)
    }

    fn aad_bytes_for(table: &str, row: &[u8], column: &str) -> Result<Vec<u8>, Error> {
        // AAD computation is based on (table, row, column).
        // The serialized AAD is:
        //   (length of table) || table || (length of row) || row || (length of column) || column.
        // Lengths are expressed as 8-byte unsigned integers.

        let aad_length = 3 * size_of::<u64>() + table.len() + row.len() + column.len();
        let mut aad_bytes = Vec::with_capacity(aad_length);
        aad_bytes.extend_from_slice(&u64::try_from(table.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(table.as_ref());
        aad_bytes.extend_from_slice(&u64::try_from(row.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(row);
        aad_bytes.extend_from_slice(&u64::try_from(column.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(column.as_ref());
        assert_eq!(aad_bytes.len(), aad_length);

        Ok(aad_bytes)
    }
}

/// Error represents a datastore-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying database library.
    #[error("DB error: {0}")]
    Db(#[from] tokio_postgres::Error),
    #[error("DB pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    #[error("crypter error")]
    Crypt,
    /// An attempt was made to mutate a row that does not exist.
    #[error("not found in datastore")]
    MutationTargetNotFound,
    /// The database was in an unexpected state.
    #[error("inconsistent database state: {0}")]
    DbState(String),
    /// An error from decoding a value stored encoded in the underlying database.
    #[error("decoding error: {0}")]
    Decode(#[from] CodecError),
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// An arbitrary error returned from the user callback; unrelated to DB internals. This error
    /// will never be generated by the datastore library itself.
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid task parameters: {0}")]
    Task(#[from] task::Error),
    #[error("integer conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Message(#[from] janus_messages::Error),
    /// An invalid parameter was provided.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
}

impl Error {
    // is_serialization_failure determines if a given error corresponds to a Postgres
    // "serialization" failure, which requires the entire transaction to be aborted & retried from
    // the beginning per https://www.postgresql.org/docs/current/transaction-iso.html.
    fn is_serialization_failure(&self) -> bool {
        match self {
            // T_R_SERIALIZATION_FAILURE (40001) is documented as the error code which is always used
            // for serialization failures which require rollback-and-retry.
            Error::Db(err) => err
                .code()
                .map_or(false, |c| c == &SqlState::T_R_SERIALIZATION_FAILURE),
            _ => false,
        }
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypt
    }
}

/// This module contains models used by the datastore that are not DAP messages.
pub mod models {
    use super::Error;
    use crate::{
        messages::{DurationExt, IntervalExt, TimeExt},
        task,
    };
    use base64::{display::Base64Display, URL_SAFE_NO_PAD};
    use derivative::Derivative;
    use janus_core::{report_id::ReportIdChecksumExt, task::VdafInstance};
    use janus_messages::{
        query_type::{FixedSize, QueryType, TimeInterval},
        AggregationJobId, BatchId, Duration, HpkeCiphertext, Interval, ReportId, ReportIdChecksum,
        ReportShareError, Role, TaskId, Time, UploadReportMetadata,
    };
    use postgres_protocol::types::{
        range_from_sql, range_to_sql, timestamp_from_sql, timestamp_to_sql, Range, RangeBound,
    };
    use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
    use prio::{
        codec::Encode,
        vdaf::{self, Aggregatable},
    };
    use rand::{distributions::Standard, prelude::Distribution};
    use std::fmt::{Debug, Formatter};
    use std::{fmt::Display, ops::RangeInclusive};
    use uuid::Uuid;

    // We have to manually implement [Partial]Eq for a number of types because the derived
    // implementations don't play nice with generic fields, even if those fields are constrained to
    // themselves implement [Partial]Eq.

    /// Represents a report as it is stored in the leader's database, corresponding to a row in
    /// `client_reports`, where `leader_input_share` and `helper_encrypted_input_share` are required
    /// to be populated.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) struct LeaderStoredReport<const L: usize, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        report_id: ReportId,
        metadata: UploadReportMetadata,
        #[derivative(Debug = "ignore")]
        public_share: A::PublicShare,
        #[derivative(Debug = "ignore")]
        leader_input_share: A::InputShare,
        #[derivative(Debug = "ignore")]
        helper_encrypted_input_share: HpkeCiphertext,
    }

    impl<const L: usize, A> LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(crate) fn new(
            task_id: TaskId,
            report_id: ReportId,
            metadata: UploadReportMetadata,
            public_share: A::PublicShare,
            leader_input_share: A::InputShare,
            helper_encrypted_input_share: HpkeCiphertext,
        ) -> Self {
            Self {
                task_id,
                report_id,
                metadata,
                public_share,
                leader_input_share,
                helper_encrypted_input_share,
            }
        }

        pub(crate) fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        pub(crate) fn id(&self) -> &ReportId {
            &self.report_id
        }

        pub(crate) fn metadata(&self) -> &UploadReportMetadata {
            &self.metadata
        }

        pub(crate) fn public_share(&self) -> &A::PublicShare {
            &self.public_share
        }

        pub(crate) fn leader_input_share(&self) -> &A::InputShare {
            &self.leader_input_share
        }

        pub(crate) fn helper_encrypted_input_share(&self) -> &HpkeCiphertext {
            &self.helper_encrypted_input_share
        }
    }

    impl<const L: usize, A> PartialEq for LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.report_id == other.report_id
                && self.metadata == other.metadata
                && self.public_share == other.public_share
                && self.leader_input_share == other.leader_input_share
                && self.helper_encrypted_input_share == other.helper_encrypted_input_share
        }
    }

    impl<const L: usize, A> Eq for LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: Eq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    #[cfg(test)]
    impl LeaderStoredReport<0, janus_core::test_util::dummy_vdaf::Vdaf> {
        pub(crate) fn new_dummy(task_id: &TaskId, when: Time) -> Self {
            use janus_messages::HpkeConfigId;
            use rand::random;

            Self::new(
                *task_id,
                random(),
                UploadReportMetadata::new(when, Vec::new()),
                (),
                (),
                HpkeCiphertext::new(
                    HpkeConfigId::from(13),
                    Vec::from("encapsulated_context_0"),
                    Vec::from("payload_0"),
                ),
            )
        }
    }

    /// AggregatorRole corresponds to the `AGGREGATOR_ROLE` enum in the schema.
    #[derive(Clone, Debug, ToSql, FromSql)]
    #[postgres(name = "aggregator_role")]
    pub enum AggregatorRole {
        #[postgres(name = "LEADER")]
        Leader,
        #[postgres(name = "HELPER")]
        Helper,
    }

    impl AggregatorRole {
        /// If the provided [`Role`] is an aggregator, returns the corresponding
        /// [`AggregatorRole`], or `None` otherwise.
        pub(super) fn from_role(role: Role) -> Result<Self, Error> {
            match role {
                Role::Leader => Ok(Self::Leader),
                Role::Helper => Ok(Self::Helper),
                _ => Err(Error::Task(task::Error::InvalidParameter(
                    "role is not an aggregator",
                ))),
            }
        }

        /// Returns the [`Role`] corresponding to this value.
        pub(super) fn as_role(&self) -> Role {
            match self {
                Self::Leader => Role::Leader,
                Self::Helper => Role::Helper,
            }
        }
    }

    /// AggregationJob represents an aggregation job from the DAP specification.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    // TODO(timg): deal with round here
    pub struct AggregationJob<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        batch_identifier: Q::PartialBatchIdentifier,
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        state: AggregationJobState,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> AggregationJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`AggregationJob`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            batch_identifier: Q::PartialBatchIdentifier,
            aggregation_parameter: A::AggregationParam,
            state: AggregationJobState,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                batch_identifier,
                aggregation_parameter,
                state,
            }
        }

        /// Returns the task ID associated with this aggregation job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this aggregation job.
        pub fn id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Gets the batch identifier associated with this aggregation job.
        ///
        /// This method would typically be used for code which is generic over the query type.
        /// Query-type specific code will typically call [`Self::batch_id`].
        pub fn batch_identifier(&self) -> &Q::PartialBatchIdentifier {
            &self.batch_identifier
        }

        /// Returns the aggregation parameter associated with this aggregation job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Returns the state of the aggregation job.
        pub fn state(&self) -> &AggregationJobState {
            &self.state
        }

        /// Returns a new [`AggregationJob`] corresponding to this aggregation job updated to have
        /// the given state.
        pub fn with_state(self, state: AggregationJobState) -> Self {
            AggregationJob { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> AggregationJob<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this aggregation job.
        pub fn batch_id(&self) -> &BatchId {
            self.batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for AggregationJob<L, Q, A>
    where
        A::AggregationParam: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.aggregation_job_id == other.aggregation_job_id
                && self.batch_identifier == other.batch_identifier
                && self.aggregation_parameter == other.aggregation_parameter
                && self.state == other.state
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for AggregationJob<L, Q, A>
    where
        A::AggregationParam: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// AggregationJobState represents the state of an aggregation job. It corresponds to the
    /// AGGREGATION_JOB_STATE enum in the schema.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, ToSql, FromSql)]
    #[postgres(name = "aggregation_job_state")]
    pub enum AggregationJobState {
        #[postgres(name = "IN_PROGRESS")]
        InProgress,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
    }

    /// LeaseToken represents an opaque value used to determine the identity of a lease.
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct LeaseToken([u8; Self::LEN]);

    impl LeaseToken {
        /// The length of a lease token in bytes.
        pub const LEN: usize = 16;
    }

    impl Debug for LeaseToken {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "LeaseToken({})",
                Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
            )
        }
    }

    impl Display for LeaseToken {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
            )
        }
    }

    impl From<[u8; Self::LEN]> for LeaseToken {
        fn from(lease_token: [u8; Self::LEN]) -> Self {
            Self(lease_token)
        }
    }

    impl AsRef<[u8; Self::LEN]> for LeaseToken {
        fn as_ref(&self) -> &[u8; Self::LEN] {
            &self.0
        }
    }

    impl Distribution<LeaseToken> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LeaseToken {
            LeaseToken(rng.gen())
        }
    }

    /// Lease represents a time-constrained lease for exclusive access to some entity in Janus. It
    /// has an expiry after which it is no longer valid; another process can take a lease on the
    /// same entity after the expiration time.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Lease<T> {
        leased: T,
        lease_expiry_time: Time,
        lease_token: LeaseToken,
        lease_attempts: usize,
    }

    impl<T> Lease<T> {
        /// Creates a new [`Lease`].
        pub(super) fn new(
            leased: T,
            lease_expiry_time: Time,
            lease_token: LeaseToken,
            lease_attempts: usize,
        ) -> Self {
            Self {
                leased,
                lease_expiry_time,
                lease_token,
                lease_attempts,
            }
        }

        /// Create a new artificial lease with a random lease token, acquired for the first time;
        /// intended for use in unit tests.
        #[cfg(test)]
        pub fn new_dummy(leased: T, lease_expiry_time: Time) -> Self {
            use rand::random;
            Self {
                leased,
                lease_expiry_time,
                lease_token: random(),
                lease_attempts: 1,
            }
        }

        /// Returns a reference to the leased entity associated with this lease.
        pub fn leased(&self) -> &T {
            &self.leased
        }

        /// Returns the lease expiry time associated with this lease.
        pub fn lease_expiry_time(&self) -> &Time {
            &self.lease_expiry_time
        }

        /// Returns the lease token associated with this lease.
        pub fn lease_token(&self) -> &LeaseToken {
            &self.lease_token
        }

        /// Returns the number of lease acquiries since the last successful release.
        pub fn lease_attempts(&self) -> usize {
            self.lease_attempts
        }
    }

    /// AcquiredAggregationJob represents an incomplete aggregation job whose lease has been
    /// acquired.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct AcquiredAggregationJob {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        query_type: task::QueryType,
        vdaf: VdafInstance,
    }

    impl AcquiredAggregationJob {
        /// Creates a new [`AcquiredAggregationJob`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            query_type: task::QueryType,
            vdaf: VdafInstance,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                query_type,
                vdaf,
            }
        }

        /// Returns the task ID associated with this acquired aggregation job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this acquired aggregation job.
        pub fn aggregation_job_id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Returns the query type associated with this acquired aggregation job.
        pub fn query_type(&self) -> &task::QueryType {
            &self.query_type
        }

        /// Returns the VDAF associated with this acquired aggregation job.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.vdaf
        }
    }

    /// AcquiredCollectJob represents an incomplete collect job whose lease has been acquired.
    #[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
    pub struct AcquiredCollectJob {
        task_id: TaskId,
        collect_job_id: Uuid,
        vdaf: VdafInstance,
    }

    impl AcquiredCollectJob {
        /// Creates a new [`AcquiredCollectJob`].
        pub fn new(task_id: TaskId, collect_job_id: Uuid, vdaf: VdafInstance) -> Self {
            Self {
                task_id,
                collect_job_id,
                vdaf,
            }
        }

        /// Returns the task ID associated with this acquired collect job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the collect job ID associated with this acquired collect job.
        pub fn collect_job_id(&self) -> &Uuid {
            &self.collect_job_id
        }

        /// Returns the VDAF associated with this acquired collect job.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.vdaf
        }
    }

    /// ReportAggregation represents a the state of a single client report's ongoing aggregation.
    #[derive(Clone, Debug)]
    pub struct ReportAggregation<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        report_id: ReportId,
        time: Time,
        ord: i64,
        state: ReportAggregationState<L, A>,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> ReportAggregation<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`ReportAggregation`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            report_id: ReportId,
            time: Time,
            ord: i64,
            state: ReportAggregationState<L, A>,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                report_id,
                time,
                ord,
                state,
            }
        }

        /// Returns the task ID associated with this report aggregation.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this report aggregation.
        pub fn aggregation_job_id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Returns the report ID associated with this report aggregation.
        pub fn report_id(&self) -> &ReportId {
            &self.report_id
        }

        /// Returns the client timestamp associated with this report aggregation.
        pub fn time(&self) -> &Time {
            &self.time
        }

        /// Returns the order of this report aggregation in its batch.
        pub fn ord(&self) -> i64 {
            self.ord
        }

        /// Returns the state of the report aggregation.
        pub fn state(&self) -> &ReportAggregationState<L, A> {
            &self.state
        }

        /// Returns a new [`ReportAggregation`] corresponding to this aggregation job updated to
        /// have the given state.
        pub fn with_state(self, state: ReportAggregationState<L, A>) -> Self {
            Self { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregation<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.aggregation_job_id == other.aggregation_job_id
                && self.report_id == other.report_id
                && self.time == other.time
                && self.ord == other.ord
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregation<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// ReportAggregationState represents the state of a single report aggregation. It corresponds
    /// to the REPORT_AGGREGATION_STATE enum in the schema, along with the state-specific data.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum ReportAggregationState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Waiting(
            #[derivative(Debug = "ignore")] A::PrepareState,
            #[derivative(Debug = "ignore")] Option<A::PrepareMessage>,
        ),
        Finished(#[derivative(Debug = "ignore")] A::OutputShare),
        Failed(ReportShareError),
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> ReportAggregationState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn state_code(&self) -> ReportAggregationStateCode {
            match self {
                ReportAggregationState::Start => ReportAggregationStateCode::Start,
                ReportAggregationState::Waiting(_, _) => ReportAggregationStateCode::Waiting,
                ReportAggregationState::Finished(_) => ReportAggregationStateCode::Finished,
                ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
                ReportAggregationState::Invalid => ReportAggregationStateCode::Invalid,
            }
        }

        /// Returns the encoded values for the various messages which might be included in a
        /// ReportAggregationState. The order of returned values is preparation state, preparation
        /// message, output share, transition error.
        pub(super) fn encoded_values_from_state(&self) -> EncodedReportAggregationStateValues
        where
            A::PrepareState: Encode,
            for<'a> &'a A::OutputShare: Into<Vec<u8>>,
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            let (prep_state, prep_msg, output_share, report_share_err) = match self {
                ReportAggregationState::Start => (None, None, None, None),
                ReportAggregationState::Waiting(prep_state, prep_msg) => (
                    Some(prep_state.get_encoded()),
                    prep_msg.as_ref().map(|msg| msg.get_encoded()),
                    None,
                    None,
                ),
                ReportAggregationState::Finished(output_share) => {
                    (None, None, Some(output_share.into()), None)
                }
                ReportAggregationState::Failed(report_share_err) => {
                    (None, None, None, Some(*report_share_err as i16))
                }
                ReportAggregationState::Invalid => (None, None, None, None),
            };
            EncodedReportAggregationStateValues {
                prep_state,
                prep_msg,
                output_share,
                report_share_err,
            }
        }
    }

    pub(super) struct EncodedReportAggregationStateValues {
        pub(super) prep_state: Option<Vec<u8>>,
        pub(super) prep_msg: Option<Vec<u8>>,
        pub(super) output_share: Option<Vec<u8>>,
        pub(super) report_share_err: Option<i16>,
    }

    // The private ReportAggregationStateCode exists alongside the public ReportAggregationState
    // because there is no apparent way to denote a Postgres enum literal without deriving
    // FromSql/ToSql on a Rust enum type, but it is not possible to derive FromSql/ToSql on a
    // non-C-style enum.
    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "report_aggregation_state")]
    pub(super) enum ReportAggregationStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "WAITING")]
        Waiting,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "FAILED")]
        Failed,
        #[postgres(name = "INVALID")]
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregationState<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Waiting(lhs_prep_state, lhs_prep_msg),
                    Self::Waiting(rhs_prep_state, rhs_prep_msg),
                ) => lhs_prep_state == rhs_prep_state && lhs_prep_msg == rhs_prep_msg,
                (Self::Finished(lhs_out_share), Self::Finished(rhs_out_share)) => {
                    lhs_out_share == rhs_out_share
                }
                (Self::Failed(lhs_report_share_err), Self::Failed(rhs_report_share_err)) => {
                    lhs_report_share_err == rhs_report_share_err
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregationState<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// BatchAggregation corresponds to a row in the `batch_aggregations` table and represents the
    /// possibly-ongoing aggregation of the set of input shares that fall within the batch
    /// identified by `batch_identifier`. This is the finest-grained possible aggregate share we can
    /// emit for this task. The aggregate share constructed to service a collect or aggregate share
    /// request consists of one or more `BatchAggregation`s merged together.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct BatchAggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregation result.
        task_id: TaskId,
        /// The identifier of the batch being aggregated over.
        batch_identifier: Q::BatchIdentifier,
        /// The VDAF aggregation parameter used to prepare and accumulate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The aggregate over all the input shares that have been prepared so far by this
        /// aggregator.
        #[derivative(Debug = "ignore")]
        aggregate_share: A::AggregateShare,
        /// The number of reports currently included in this aggregate sahre.
        report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        checksum: ReportIdChecksum,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> BatchAggregation<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`BatchAggregation`].
        pub fn new(
            task_id: TaskId,
            batch_identifier: Q::BatchIdentifier,
            aggregation_parameter: A::AggregationParam,
            aggregate_share: A::AggregateShare,
            report_count: u64,
            checksum: ReportIdChecksum,
        ) -> Self {
            Self {
                task_id,
                batch_identifier,
                aggregation_parameter,
                aggregate_share,
                report_count,
                checksum,
            }
        }

        /// Returns the task ID associated with this batch aggregation.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the batch identifier included in this batch aggregation.
        ///
        /// This method would typically be used for code which is generic over the query type.
        /// Query-type specific code will typically call one of [`Self::batch_interval`] or
        /// [`Self::batch_id`].
        pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
            &self.batch_identifier
        }

        /// Returns the aggregation parameter associated with this batch aggregation.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Returns the aggregate share associated with this batch aggregation.
        pub fn aggregate_share(&self) -> &A::AggregateShare {
            &self.aggregate_share
        }

        /// Returns the report count associated with this batch aggregation.
        pub fn report_count(&self) -> u64 {
            self.report_count
        }

        /// Returns the checksum associated with this batch aggregation.
        pub fn checksum(&self) -> &ReportIdChecksum {
            &self.checksum
        }

        /// Returns a new [`BatchAggregation`] corresponding to the current batch aggregation
        /// merged with the given parameters.
        pub fn merged_with(
            self,
            aggregate_share: &A::AggregateShare,
            report_count: u64,
            checksum: &ReportIdChecksum,
        ) -> Result<Self, Error> {
            let mut merged_aggregate_share = self.aggregate_share;
            merged_aggregate_share
                .merge(aggregate_share)
                .map_err(|err| Error::User(err.into()))?;
            Ok(Self {
                aggregate_share: merged_aggregate_share,
                report_count: self.report_count + report_count,
                checksum: self.checksum.combined_with(checksum),
                ..self
            })
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> BatchAggregation<L, TimeInterval, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch interval associated with this batch aggregation.
        pub fn batch_interval(&self) -> &Interval {
            self.batch_identifier()
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> BatchAggregation<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this batch aggregation.
        pub fn batch_id(&self) -> &BatchId {
            self.batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for BatchAggregation<L, Q, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.batch_identifier == other.batch_identifier
                && self.aggregation_parameter == other.aggregation_parameter
                && self.aggregate_share == other.aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for BatchAggregation<L, Q, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// CollectJob represents a row in the `collect_jobs` table, used by leaders to represent
    /// running collect jobs and store the results of completed ones.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct CollectJob<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this collect job.
        task_id: TaskId,
        /// The unique identifier for the collect job.
        collect_job_id: Uuid,
        /// The batch interval covered by the collect job.
        batch_interval: Interval,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The current state of the collect job.
        state: CollectJobState<L, A>,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> CollectJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`CollectJob`].
        pub fn new(
            task_id: TaskId,
            collect_job_id: Uuid,
            batch_interval: Interval,
            aggregation_parameter: A::AggregationParam,
            state: CollectJobState<L, A>,
        ) -> Self {
            Self {
                task_id,
                collect_job_id,
                batch_interval,
                aggregation_parameter,
                state,
            }
        }

        /// Returns the task ID associated with this collect job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the collect job ID associated with this collect job.
        pub fn collect_job_id(&self) -> &Uuid {
            &self.collect_job_id
        }

        /// Returns the batch interval associated with this collect job.
        pub fn batch_interval(&self) -> &Interval {
            &self.batch_interval
        }

        /// Returns the aggregation parameter associated with this collect job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Returns the state associated with this collect job.
        pub fn state(&self) -> &CollectJobState<L, A> {
            &self.state
        }

        /// Returns a new [`CollectJob`] corresponding to this collect job updated to have the given
        /// state.
        pub fn with_state(self, state: CollectJobState<L, A>) -> Self {
            Self { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for CollectJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: PartialEq,
        CollectJobState<L, A>: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.collect_job_id == other.collect_job_id
                && self.batch_interval == other.batch_interval
                && self.aggregation_parameter == other.aggregation_parameter
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for CollectJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Eq,
        CollectJobState<L, A>: Eq,
    {
    }

    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum CollectJobState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Finished {
            /// The number of reports included in this collect job.
            report_count: u64,
            /// The helper's encrypted aggregate share over the input shares in the interval.
            encrypted_helper_aggregate_share: HpkeCiphertext,
            /// The leader's aggregate share over the input shares in the interval.
            #[derivative(Debug = "ignore")]
            leader_aggregate_share: A::AggregateShare,
        },
        Abandoned,
        Deleted,
    }

    impl<const L: usize, A> CollectJobState<L, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn collect_job_state_code(&self) -> CollectJobStateCode {
            match self {
                Self::Start => CollectJobStateCode::Start,
                Self::Finished { .. } => CollectJobStateCode::Finished,
                Self::Abandoned => CollectJobStateCode::Abandoned,
                Self::Deleted => CollectJobStateCode::Deleted,
            }
        }
    }

    impl<const L: usize, A> Display for CollectJobState<L, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                match self {
                    Self::Start => "start",
                    Self::Finished { .. } => "finished",
                    Self::Abandoned => "abandoned",
                    Self::Deleted => "deleted",
                }
            )
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for CollectJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Finished {
                        report_count: self_report_count,
                        encrypted_helper_aggregate_share: self_helper_agg_share,
                        leader_aggregate_share: self_leader_agg_share,
                    },
                    Self::Finished {
                        report_count: other_report_count,
                        encrypted_helper_aggregate_share: other_helper_agg_share,
                        leader_aggregate_share: other_leader_agg_share,
                    },
                ) => {
                    self_report_count == other_report_count
                        && self_helper_agg_share == other_helper_agg_share
                        && self_leader_agg_share == other_leader_agg_share
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for CollectJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: Eq,
    {
    }

    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "collect_job_state")]
    pub(super) enum CollectJobStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
        #[postgres(name = "DELETED")]
        Deleted,
    }

    /// AggregateShareJob represents a row in the `aggregate_share_jobs` table, used by helpers to
    /// store the results of handling an AggregateShareReq from the leader.

    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct AggregateShareJob<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregate share.
        task_id: TaskId,
        /// The batch interval covered by the aggregate share.
        batch_interval: Interval,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The aggregate share over the input shares in the interval.
        #[derivative(Debug = "ignore")]
        helper_aggregate_share: A::AggregateShare,
        /// The number of reports included in the aggregate share.
        report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        checksum: ReportIdChecksum,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> AggregateShareJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`AggregateShareJob`].
        pub fn new(
            task_id: TaskId,
            batch_interval: Interval,
            aggregation_parameter: A::AggregationParam,
            helper_aggregate_share: A::AggregateShare,
            report_count: u64,
            checksum: ReportIdChecksum,
        ) -> Self {
            Self {
                task_id,
                batch_interval,
                aggregation_parameter,
                helper_aggregate_share,
                report_count,
                checksum,
            }
        }

        /// Gets the task ID associated with this aggregate share job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the batch interval associated with this aggregate share job.
        pub fn batch_interval(&self) -> &Interval {
            &self.batch_interval
        }

        /// Gets the aggregation parameter associated with this aggregate share job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Gets the helper aggregate share associated with this aggregate share job.
        pub fn helper_aggregate_share(&self) -> &A::AggregateShare {
            &self.helper_aggregate_share
        }

        /// Gets the report count associated with this aggregate share job.
        pub fn report_count(&self) -> u64 {
            self.report_count
        }

        /// Gets the checksum associated with this aggregate share job.
        pub fn checksum(&self) -> &ReportIdChecksum {
            &self.checksum
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for AggregateShareJob<L, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.batch_interval == other.batch_interval
                && self.aggregation_parameter == other.aggregation_parameter
                && self.helper_aggregate_share == other.helper_aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for AggregateShareJob<L, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// An outstanding batch, which is a batch which has not yet started collection. Such a batch
    /// may have additional reports allocated to it. Only applies to fixed-size batches.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct OutstandingBatch {
        /// The task ID for this outstanding batch.
        task_id: TaskId,
        /// The batch ID for this outstanding batch.
        batch_id: BatchId,
        /// The range of possible sizes of this batch. The minimum size is the count of reports
        /// which have successfully completed the aggregation process, while the maximum size is the
        /// count of reports which are currently being aggregated or have successfully completed the
        /// aggregation process.
        size: RangeInclusive<usize>,
    }

    impl OutstandingBatch {
        /// Creates a new [`OutstandingBatch`].
        pub fn new(task_id: TaskId, batch_id: BatchId, size: RangeInclusive<usize>) -> Self {
            Self {
                task_id,
                batch_id,
                size,
            }
        }

        /// Gets the [`TaskId`] associated with this outstanding batch.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the [`BatchId`] associated with this outstanding batch.
        pub fn id(&self) -> &BatchId {
            &self.batch_id
        }

        /// Gets the range of possible sizes of this batch. The minimum size is the count of reports
        /// which have successfully completed the aggregation process, while the maximum size is the
        /// count of reports which are currently being aggregated or have successfully completed the
        /// aggregation process.
        pub fn size(&self) -> &RangeInclusive<usize> {
            &self.size
        }
    }

    /// The SQL timestamp epoch, midnight UTC on 2000-01-01.
    const SQL_EPOCH_TIME: Time = Time::from_seconds_since_epoch(946_684_800);

    /// Wrapper around [`janus_messages::Interval`] that supports conversions to/from SQL.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SqlInterval(Interval);

    impl SqlInterval {
        pub fn as_interval(&self) -> Interval {
            self.0
        }
    }

    impl From<Interval> for SqlInterval {
        fn from(interval: Interval) -> Self {
            Self(interval)
        }
    }

    impl From<&Interval> for SqlInterval {
        fn from(interval: &Interval) -> Self {
            Self::from(*interval)
        }
    }

    impl<'a> FromSql<'a> for SqlInterval {
        fn from_sql(
            _: &postgres_types::Type,
            raw: &'a [u8],
        ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            match range_from_sql(raw)? {
            Range::Empty => Err("Interval cannot represent an empty timestamp range".into()),
            Range::Nonempty(RangeBound::Inclusive(None), _)
            | Range::Nonempty(RangeBound::Exclusive(None), _)
            | Range::Nonempty(_, RangeBound::Inclusive(None))
            | Range::Nonempty(_, RangeBound::Exclusive(None)) => {
                Err("Interval cannot represent a timestamp range with a null bound".into())
            }
            Range::Nonempty(RangeBound::Unbounded, _) | Range::Nonempty(_, RangeBound::Unbounded) => {
                Err("Interval cannot represent an unbounded timestamp range".into())
            }
            Range::Nonempty(RangeBound::Exclusive(_), _) | Range::Nonempty(_, RangeBound::Inclusive(_)) => {
                Err("Interval can only represent timestamp ranges that are closed at the start and open at the end".into())
            }
            Range::Nonempty(RangeBound::Inclusive(Some(start_raw)), RangeBound::Exclusive(Some(end_raw))) => {
                // These timestamps represent the number of microseconds before (if negative) or
                // after (if positive) midnight, 1/1/2000.
                let start_timestamp = timestamp_from_sql(start_raw)?;
                let end_timestamp = timestamp_from_sql(end_raw)?;

                // Convert from SQL timestamp representation to the internal representation.
                let negative = start_timestamp < 0;
                let abs_start_us = start_timestamp.unsigned_abs();
                let abs_start_duration = Duration::from_microseconds(abs_start_us);
                let time = if negative {
                    SQL_EPOCH_TIME.sub(&abs_start_duration).map_err(|_| "Interval cannot represent timestamp ranges starting before the Unix epoch")?
                } else {
                    SQL_EPOCH_TIME.add(&abs_start_duration).map_err(|_| "overflow when converting to Interval")?
                };

                if end_timestamp < start_timestamp {
                    return Err("timestamp range ends before it starts".into());
                }
                let duration_us = end_timestamp.abs_diff(start_timestamp);
                let duration = Duration::from_microseconds(duration_us);

                Ok(SqlInterval(Interval::new(time, duration)?))
            }
        }
        }

        accepts!(TS_RANGE);
    }

    fn time_to_sql_timestamp(time: Time) -> Result<i64, Error> {
        if time.is_after(&SQL_EPOCH_TIME) {
            let absolute_difference_us = time.difference(&SQL_EPOCH_TIME)?.as_microseconds()?;
            Ok(absolute_difference_us.try_into()?)
        } else {
            let absolute_difference_us = SQL_EPOCH_TIME.difference(&time)?.as_microseconds()?;
            Ok(-i64::try_from(absolute_difference_us)?)
        }
    }

    impl ToSql for SqlInterval {
        fn to_sql(
            &self,
            _: &postgres_types::Type,
            out: &mut bytes::BytesMut,
        ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
            // Convert the interval start and end to SQL timestamps.
            let start_sql_usec = time_to_sql_timestamp(*self.0.start())
                .map_err(|_| "millisecond timestamp of Interval start overflowed")?;
            let end_sql_usec = time_to_sql_timestamp(self.0.end())
                .map_err(|_| "millisecond timestamp of Interval end overflowed")?;

            range_to_sql(
                |out| {
                    timestamp_to_sql(start_sql_usec, out);
                    Ok(postgres_protocol::types::RangeBound::Inclusive(
                        postgres_protocol::IsNull::No,
                    ))
                },
                |out| {
                    timestamp_to_sql(end_sql_usec, out);
                    Ok(postgres_protocol::types::RangeBound::Exclusive(
                        postgres_protocol::IsNull::No,
                    ))
                },
                out,
            )?;

            Ok(postgres_types::IsNull::No)
        }

        accepts!(TS_RANGE);

        to_sql_checked!();
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::{Crypter, Datastore};
    use deadpool_postgres::{Manager, Pool};
    use janus_core::time::Clock;
    use lazy_static::lazy_static;
    use rand::{distributions::Standard, thread_rng, Rng};
    use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
    use std::{
        env::{self, VarError},
        process::Command,
        str::FromStr,
    };
    use testcontainers::{images::postgres::Postgres, Container, RunnableImage};
    use tokio_postgres::{Config, NoTls};
    use tracing::trace;

    /// The Janus database schema.
    pub const SCHEMA: &str = include_str!("../../db/schema.sql");

    lazy_static! {
        static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
            testcontainers::clients::Cli::default();
    }

    /// DbHandle represents a handle to a running (ephemeral) database. Dropping this value
    /// causes the database to be shut down & cleaned up.
    pub struct DbHandle {
        _db_container: Container<'static, Postgres>,
        connection_string: String,
        port_number: u16,
        datastore_key_bytes: Vec<u8>,
    }

    impl DbHandle {
        /// Retrieve a datastore attached to the ephemeral database.
        pub fn datastore<C: Clock>(&self, clock: C) -> Datastore<C> {
            // Create a crypter based on the generated key bytes.
            let datastore_key =
                LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &self.datastore_key_bytes).unwrap());
            let crypter = Crypter::new(Vec::from([datastore_key]));

            Datastore::new(self.pool(), crypter, clock)
        }

        /// Retrieve a Postgres connection pool attached to the ephemeral database.
        pub fn pool(&self) -> Pool {
            let cfg = Config::from_str(&self.connection_string).unwrap();
            let conn_mgr = Manager::new(cfg, NoTls);
            Pool::builder(conn_mgr).build().unwrap()
        }

        /// Get a PostgreSQL connection string to connect to the temporary database.
        pub fn connection_string(&self) -> &str {
            &self.connection_string
        }

        /// Get the bytes of the key used to encrypt sensitive datastore values.
        pub fn datastore_key_bytes(&self) -> &[u8] {
            &self.datastore_key_bytes
        }

        /// Get the port number that the temporary database is exposed on, via the 127.0.0.1
        /// loopback interface.
        pub fn port_number(&self) -> u16 {
            self.port_number
        }

        /// Open an interactive terminal to the database in a new terminal window, and block
        /// until the user exits from the terminal. This is intended to be used while
        /// debugging tests.
        ///
        /// By default, this will invoke `gnome-terminal`, which is readily available on
        /// GNOME-based Linux distributions. To use a different terminal, set the environment
        /// variable `JANUS_SHELL_CMD` to a shell command that will open a new terminal window
        /// of your choice. This command line should include a "{}" in the position appropriate
        /// for what command the terminal should run when it opens. A `psql` invocation will
        /// be substituted in place of the "{}". Note that this shell command must not exit
        /// immediately once the terminal is spawned; it should continue running as long as the
        /// terminal is open. If the command provided exits too soon, then the test will
        /// continue running without intervention, leading to the test's database shutting
        /// down.
        ///
        /// # Example
        ///
        /// ```text
        /// JANUS_SHELL_CMD='xterm -e {}' cargo test
        /// ```
        pub fn interactive_db_terminal(&self) {
            let mut command = match env::var("JANUS_SHELL_CMD") {
                Ok(shell_cmd) => {
                    if !shell_cmd.contains("{}") {
                        panic!("JANUS_SHELL_CMD should contain a \"{{}}\" to denote where the database command should be substituted");
                    }

                    #[cfg(not(windows))]
                    let mut command = {
                        let mut command = Command::new("sh");
                        command.arg("-c");
                        command
                    };

                    #[cfg(windows)]
                    let mut command = {
                        let mut command = Command::new("cmd.exe");
                        command.arg("/c");
                        command
                    };

                    let psql_command = format!(
                        "psql --host=127.0.0.1 --user=postgres -p {}",
                        self.port_number(),
                    );
                    command.arg(shell_cmd.replacen("{}", &psql_command, 1));
                    command
                }

                Err(VarError::NotPresent) => {
                    let mut command = Command::new("gnome-terminal");
                    command.args([
                        "--wait",
                        "--",
                        "psql",
                        "--host=127.0.0.1",
                        "--user=postgres",
                        "-p",
                    ]);
                    command.arg(format!("{}", self.port_number()));
                    command
                }

                Err(VarError::NotUnicode(_)) => {
                    panic!("JANUS_SHELL_CMD contains invalid unicode data");
                }
            };
            command.spawn().unwrap().wait().unwrap();
        }
    }

    impl Drop for DbHandle {
        fn drop(&mut self) {
            trace!(connection_string = %self.connection_string, "Dropping ephemeral Postgres container");
        }
    }

    /// ephemeral_db_handle creates a new ephemeral database which has no schema & is empty.
    /// Dropping the return value causes the database to be shut down & cleaned up.
    ///
    /// Most users will want to call ephemeral_datastore() instead, which applies the Janus
    /// schema and creates a datastore.
    pub fn ephemeral_db_handle() -> DbHandle {
        // Start an instance of Postgres running in a container.
        let db_container =
            CONTAINER_CLIENT.run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));

        // Compute the Postgres connection string.
        const POSTGRES_DEFAULT_PORT: u16 = 5432;
        let port_number = db_container.get_host_port_ipv4(POSTGRES_DEFAULT_PORT);
        let connection_string = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            port_number,
        );
        trace!("Postgres container is up with URL {}", connection_string);

        // Create a random (ephemeral) key.
        let datastore_key_bytes = generate_aead_key_bytes();

        DbHandle {
            _db_container: db_container,
            connection_string,
            port_number,
            datastore_key_bytes,
        }
    }

    /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database
    /// which has the Janus schema applied but is otherwise empty.
    ///
    /// Dropping the second return value causes the database to be shut down & cleaned up.
    pub async fn ephemeral_datastore<C: Clock>(clock: C) -> (Datastore<C>, DbHandle) {
        let db_handle = ephemeral_db_handle();
        let client = db_handle.pool().get().await.unwrap();
        client.batch_execute(SCHEMA).await.unwrap();
        (db_handle.datastore(clock), db_handle)
    }

    pub fn generate_aead_key_bytes() -> Vec<u8> {
        thread_rng()
            .sample_iter(Standard)
            .take(AES_128_GCM.key_len())
            .collect()
    }

    pub fn generate_aead_key() -> LessSafeKey {
        let unbound_key = UnboundKey::new(&AES_128_GCM, &generate_aead_key_bytes()).unwrap();
        LessSafeKey::new(unbound_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator::query_type::CollectableQueryType,
        datastore::{
            models::{
                AcquiredAggregationJob, AggregateShareJob, AggregationJob, AggregationJobState,
                BatchAggregation, CollectJob, CollectJobState, LeaderStoredReport, Lease,
                OutstandingBatch, ReportAggregation, ReportAggregationState, SqlInterval,
            },
            test_util::{ephemeral_datastore, generate_aead_key},
            Crypter, Error,
        },
        messages::{DurationExt, TimeExt},
        task::{self, test_util::TaskBuilder, QueryType, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    };
    use assert_matches::assert_matches;
    use chrono::NaiveDate;
    use futures::future::try_join_all;
    use janus_core::{
        hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, Label},
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, MockClock, TimeExt as CoreTimeExt},
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregateReportMetadata, Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId,
        Interval, ReportId, ReportIdChecksum, ReportShare, ReportShareError, Role, TaskId, Time,
        UploadReportMetadata,
    };
    use prio::{
        codec::{Decode, Encode},
        field::Field64,
        vdaf::{
            self,
            prio3::{Prio3, Prio3Aes128Count},
            AggregateShare, PrepareTransition,
        },
    };
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use std::{
        collections::{HashMap, HashSet},
        iter,
        ops::RangeInclusive,
        sync::Arc,
    };
    use uuid::Uuid;

    use super::{models::AcquiredCollectJob, Datastore};

    #[tokio::test]
    async fn roundtrip_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        // Insert tasks, check that they can be retrieved by ID.
        let mut want_tasks = HashMap::new();
        for (vdaf, role) in [
            (VdafInstance::Prio3Aes128Count, Role::Leader),
            (
                VdafInstance::Prio3Aes128CountVec { length: 8 },
                Role::Leader,
            ),
            (
                VdafInstance::Prio3Aes128CountVec { length: 64 },
                Role::Helper,
            ),
            (VdafInstance::Prio3Aes128Sum { bits: 64 }, Role::Helper),
            (VdafInstance::Prio3Aes128Sum { bits: 32 }, Role::Helper),
            (
                VdafInstance::Prio3Aes128Histogram {
                    buckets: Vec::from([0, 100, 200, 400]),
                },
                Role::Leader,
            ),
            (
                VdafInstance::Prio3Aes128Histogram {
                    buckets: Vec::from([0, 25, 50, 75, 100]),
                },
                Role::Leader,
            ),
            (VdafInstance::Poplar1 { bits: 8 }, Role::Helper),
            (VdafInstance::Poplar1 { bits: 64 }, Role::Helper),
        ] {
            let task = TaskBuilder::new(QueryType::TimeInterval, vdaf, role).build();
            want_tasks.insert(*task.id(), task.clone());

            let err = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.delete_task(task.id()).await })
                })
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(Some(&task), retrieved_task.as_ref());

            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.delete_task(task.id()).await })
            })
            .await
            .unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            let err = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.delete_task(task.id()).await })
                })
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            // Rewrite & retrieve the task again, to test that the delete is "clean" in the sense
            // that it deletes all task-related data (& therefore does not conflict with a later
            // write to the same task_id).
            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(Some(task), retrieved_task);
        }

        let got_tasks: HashMap<TaskId, Task> = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap()
            .into_iter()
            .map(|task| (*task.id(), task))
            .collect();
        assert_eq!(want_tasks, got_tasks);
    }

    #[tokio::test]
    async fn roundtrip_report() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        let report: LeaderStoredReport<0, dummy_vdaf::Vdaf> = LeaderStoredReport::new(
            *task.id(),
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            UploadReportMetadata::new(
                Time::from_seconds_since_epoch(12345),
                Vec::from([
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
                ]),
            ),
            (), // public share
            (), // leader input share
            /* Dummy ciphertext for the helper share */
            HpkeCiphertext::new(
                HpkeConfigId::from(13),
                Vec::from("encapsulated_context_1"),
                Vec::from("payload_1"),
            ),
        );

        ds.run_tx(|tx| {
            let (task, report) = (task.clone(), report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&report).await
            })
        })
        .await
        .unwrap();

        let retrieved_report = ds
            .run_tx(|tx| {
                let task_id = *report.task_id();
                let report_id = *report.id();
                Box::pin(async move {
                    tx.get_client_report::<0, dummy_vdaf::Vdaf>(
                        &dummy_vdaf::Vdaf::new(),
                        &task_id,
                        &report_id,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(report.task_id(), retrieved_report.task_id());
        assert_eq!(report.metadata(), retrieved_report.metadata());
    }

    #[tokio::test]
    async fn report_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report(
                        &dummy_vdaf::Vdaf::new(),
                        &random(),
                        &ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        assert_eq!(rslt, None);
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_ids_for_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let when = MockClock::default()
            .now()
            .to_batch_interval_start(&Duration::from_seconds(1000))
            .unwrap();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let unrelated_task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();

        let first_unaggregated_report = LeaderStoredReport::new_dummy(task.id(), when);
        let second_unaggregated_report = LeaderStoredReport::new_dummy(task.id(), when);
        let aggregated_report = LeaderStoredReport::new_dummy(task.id(), when);
        let unrelated_report = LeaderStoredReport::new_dummy(unrelated_task.id(), when);

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;

                tx.put_client_report(&first_unaggregated_report).await?;
                tx.put_client_report(&second_unaggregated_report).await?;
                tx.put_client_report(&aggregated_report).await?;
                tx.put_client_report(&unrelated_report).await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    (),
                    (),
                    AggregationJobState::InProgress,
                ))
                .await?;
                tx
                    .put_report_aggregation(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *aggregated_report.id(),
                            *aggregated_report.metadata().time(),
                            0,
                            ReportAggregationState::<
                                PRIO3_AES128_VERIFY_KEY_LENGTH,
                                Prio3Aes128Count,
                            >::Start,
                        ),
                    )
                    .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results.
        let got_reports = HashSet::from_iter(
            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_for_task(task.id())
                        .await
                })
            })
            .await
            .unwrap(),
        );

        assert_eq!(
            got_reports,
            HashSet::from([
                (
                    *first_unaggregated_report.id(),
                    *first_unaggregated_report.metadata().time(),
                ),
                (
                    *second_unaggregated_report.id(),
                    *second_unaggregated_report.metadata().time(),
                ),
            ]),
        );
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_ids_with_agg_param_for_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let unrelated_task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        let first_unaggregated_report =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12345));
        let second_unaggregated_report =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12346));
        let aggregated_report =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12347));
        let unrelated_report = LeaderStoredReport::new_dummy(
            unrelated_task.id(),
            Time::from_seconds_since_epoch(12348),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;

                tx.put_client_report(&first_unaggregated_report).await?;
                tx.put_client_report(&second_unaggregated_report).await?;
                tx.put_client_report(&aggregated_report).await?;
                tx.put_client_report(&unrelated_report).await?;

                // There are no client reports submitted under this task, so we shouldn't see
                // this aggregation parameter at all.
                tx.put_collect_job(&CollectJob::new(
                    *unrelated_task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(255),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. None should be returned yet, as there are no relevant
        // collect requests.
        let got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();
        assert!(got_reports.is_empty());

        // Add collect jobs, and mark one report as having already been aggregated once.
        ds.run_tx(|tx| {
            let (task, aggregated_report_id, aggregated_report_time) = (
                task.clone(),
                *aggregated_report.id(),
                *aggregated_report.metadata().time(),
            );
            Box::pin(async move {
                tx.put_collect_job(&CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(0),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                tx.put_collect_job(&CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(1),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                // No reports fall in this interval, so we shouldn't see it's aggregation
                // parameter at all.
                tx.put_collect_job(&CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(8 * 3600),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(2),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    aggregation_job_id,
                    (),
                    AggregationParam(0),
                    AggregationJobState::InProgress,
                ))
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    aggregation_job_id,
                    aggregated_report_id,
                    aggregated_report_time,
                    0,
                    ReportAggregationState::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. We should have two unaggregated reports with one parameter,
        // and three with another.
        let mut got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();

        let mut expected_reports = Vec::from([
            (
                *first_unaggregated_report.id(),
                *first_unaggregated_report.metadata().time(),
                AggregationParam(0),
            ),
            (
                *first_unaggregated_report.id(),
                *first_unaggregated_report.metadata().time(),
                AggregationParam(1),
            ),
            (
                *second_unaggregated_report.id(),
                *second_unaggregated_report.metadata().time(),
                AggregationParam(0),
            ),
            (
                *second_unaggregated_report.id(),
                *second_unaggregated_report.metadata().time(),
                AggregationParam(1),
            ),
            (
                *aggregated_report.id(),
                *aggregated_report.metadata().time(),
                AggregationParam(1),
            ),
        ]);
        got_reports.sort();
        expected_reports.sort();
        assert_eq!(got_reports, expected_reports);

        // Add overlapping collect jobs with repeated aggregation parameters. Make sure we don't
        // repeat result tuples, which could lead to double counting in batch aggregations.
        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_collect_job(&CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    dummy_vdaf::AggregationParam(0),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                tx.put_collect_job(&CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    dummy_vdaf::AggregationParam(1),
                    CollectJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify that we get the same result.
        let mut got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();
        got_reports.sort();
        assert_eq!(got_reports, expected_reports);
    }

    #[tokio::test]
    async fn count_client_reports_for_interval() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let unrelated_task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let no_reports_task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        let first_report_in_interval =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12340));
        let second_report_in_interval =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12341));
        let report_outside_interval =
            LeaderStoredReport::new_dummy(task.id(), Time::from_seconds_since_epoch(12350));
        let report_for_other_task = LeaderStoredReport::new_dummy(
            unrelated_task.id(),
            Time::from_seconds_since_epoch(12341),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                no_reports_task,
                first_report_in_interval,
                second_report_in_interval,
                report_outside_interval,
                report_for_other_task,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                no_reports_task.clone(),
                first_report_in_interval.clone(),
                second_report_in_interval.clone(),
                report_outside_interval.clone(),
                report_for_other_task.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;
                tx.put_task(&no_reports_task).await?;

                tx.put_client_report(&first_report_in_interval).await?;
                tx.put_client_report(&second_report_in_interval).await?;
                tx.put_client_report(&report_outside_interval).await?;
                tx.put_client_report(&report_for_other_task).await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let (report_count, no_reports_task_report_count) = ds
            .run_tx(|tx| {
                let (task, no_reports_task) = (task.clone(), no_reports_task.clone());
                Box::pin(async move {
                    let report_count = tx
                        .count_client_reports_for_interval(
                            task.id(),
                            &Interval::new(
                                Time::from_seconds_since_epoch(12340),
                                Duration::from_seconds(5),
                            )
                            .unwrap(),
                        )
                        .await?;

                    let no_reports_task_report_count = tx
                        .count_client_reports_for_interval(
                            no_reports_task.id(),
                            &Interval::new(
                                Time::from_seconds_since_epoch(12340),
                                Duration::from_seconds(5),
                            )
                            .unwrap(),
                        )
                        .await?;

                    Ok((report_count, no_reports_task_report_count))
                })
            })
            .await
            .unwrap();
        assert_eq!(report_count, 2);
        assert_eq!(no_reports_task_report_count, 0);
    }

    #[tokio::test]
    async fn roundtrip_report_share() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let report_share = ReportShare::new(
            AggregateReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
                Vec::from([
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
                ]),
            ),
            Vec::from("public_share"),
            HpkeCiphertext::new(
                HpkeConfigId::from(12),
                Vec::from("encapsulated_context_0"),
                Vec::from("payload_0"),
            ),
        );

        let got_report_share_exists = ds
            .run_tx(|tx| {
                let (task, report_share) = (task.clone(), report_share.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    let report_share_exists = tx
                        .check_report_share_exists(task.id(), report_share.metadata().id())
                        .await?;
                    tx.put_report_share(task.id(), &report_share).await?;
                    Ok(report_share_exists)
                })
            })
            .await
            .unwrap();
        assert!(!got_report_share_exists);

        let (
            got_report_share_exists,
            got_task_id,
            got_extensions,
            got_leader_input_share,
            got_helper_input_share,
        ) = ds
            .run_tx(|tx| {
                let (task, report_share_metadata) = (task.clone(), report_share.metadata().clone());
                Box::pin(async move {
                    let report_share_exists = tx
                        .check_report_share_exists(task.id(), report_share_metadata.id())
                        .await?;
                    let row = tx
                        .tx
                        .query_one(
                            "SELECT
                                tasks.task_id,
                                client_reports.report_id,
                                client_reports.client_timestamp,
                                client_reports.extensions,
                                client_reports.leader_input_share,
                                client_reports.helper_encrypted_input_share
                            FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                            WHERE report_id = $1 AND client_timestamp = $2",
                            &[
                                /* report_id */ &report_share_metadata.id().as_ref(),
                                /* client_timestamp */
                                &report_share_metadata.time().as_naive_date_time(),
                            ],
                        )
                        .await?;

                    let task_id = TaskId::get_decoded(row.get("task_id"))?;

                    let maybe_extensions: Option<Vec<u8>> = row.get("extensions");
                    let maybe_leader_input_share: Option<Vec<u8>> = row.get("leader_input_share");
                    let maybe_helper_input_share: Option<Vec<u8>> =
                        row.get("helper_encrypted_input_share");

                    Ok((
                        report_share_exists,
                        task_id,
                        maybe_extensions,
                        maybe_leader_input_share,
                        maybe_helper_input_share,
                    ))
                })
            })
            .await
            .unwrap();

        assert!(got_report_share_exists);
        assert_eq!(task.id(), &got_task_id);
        assert!(got_extensions.is_none());
        assert!(got_leader_input_share.is_none());
        assert!(got_helper_input_share.is_none());
    }

    #[tokio::test]
    async fn roundtrip_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        // We use a dummy VDAF & fixed-size task for this test, to better exercise the
        // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
        let task = TaskBuilder::new(
            QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            random(),
            dummy_vdaf::AggregationParam(23),
            AggregationJobState::InProgress,
        );

        ds.run_tx(|tx| {
            let (task, aggregation_job) = (task.clone(), aggregation_job.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_aggregation_job(&aggregation_job).await
            })
        })
        .await
        .unwrap();

        let got_aggregation_job = ds
            .run_tx(|tx| {
                let aggregation_job = aggregation_job.clone();
                Box::pin(async move {
                    tx.get_aggregation_job(aggregation_job.task_id(), aggregation_job.id())
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(&aggregation_job), got_aggregation_job.as_ref());

        let new_aggregation_job = aggregation_job
            .clone()
            .with_state(AggregationJobState::Finished);
        ds.run_tx(|tx| {
            let new_aggregation_job = new_aggregation_job.clone();
            Box::pin(async move { tx.update_aggregation_job(&new_aggregation_job).await })
        })
        .await
        .unwrap();

        let got_aggregation_job = ds
            .run_tx(|tx| {
                let aggregation_job = aggregation_job.clone();
                Box::pin(async move {
                    tx.get_aggregation_job(aggregation_job.task_id(), aggregation_job.id())
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(new_aggregation_job), got_aggregation_job);
    }

    #[tokio::test]
    async fn aggregation_job_acquire_release() {
        // Setup: insert a few aggregation jobs.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const AGGREGATION_JOB_COUNT: usize = 10;
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let mut aggregation_job_ids: Vec<_> = thread_rng()
            .sample_iter(Standard)
            .take(AGGREGATION_JOB_COUNT)
            .collect();
        aggregation_job_ids.sort();

        ds.run_tx(|tx| {
            let (task, aggregation_job_ids) = (task.clone(), aggregation_job_ids.clone());
            Box::pin(async move {
                // Write a few aggregation jobs we expect to be able to retrieve with
                // acquire_incomplete_aggregation_jobs().
                tx.put_task(&task).await?;
                for aggregation_job_id in aggregation_job_ids {
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                }

                // Write an aggregation job that is finished. We don't want to retrieve this one.
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    random(),
                    (),
                    (),
                    AggregationJobState::Finished,
                ))
                .await?;

                // Write an aggregation job for a task that we are taking on the helper role for.
                // We don't want to retrieve this one, either.
                let helper_task = TaskBuilder::new(
                    QueryType::TimeInterval,
                    VdafInstance::Prio3Aes128Count,
                    Role::Helper,
                )
                .build();
                tx.put_task(&helper_task).await?;
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *helper_task.id(),
                    random(),
                    (),
                    (),
                    AggregationJobState::InProgress,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run: run several transactions that all call acquire_incomplete_aggregation_jobs
        // concurrently. (We do things concurrently in an attempt to make sure the
        // mutual-exclusivity works properly.)
        const TX_COUNT: usize = 10;
        const LEASE_DURATION: Duration = Duration::from_seconds(300);
        const MAXIMUM_ACQUIRE_COUNT: usize = 4;

        // Sanity check constants: ensure we acquire jobs across multiple calls to exercise the
        // maximum-jobs-per-call functionality. Make sure we're attempting to acquire enough jobs
        // in total to cover the number of acquirable jobs we created.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAXIMUM_ACQUIRE_COUNT < AGGREGATION_JOB_COUNT);
            assert!(MAXIMUM_ACQUIRE_COUNT.checked_mul(TX_COUNT).unwrap() >= AGGREGATION_JOB_COUNT);
        }

        let results = try_join_all(
            iter::repeat_with(|| {
                ds.run_tx(|tx| {
                    Box::pin(async move {
                        tx.acquire_incomplete_aggregation_jobs(
                            &LEASE_DURATION,
                            MAXIMUM_ACQUIRE_COUNT,
                        )
                        .await
                    })
                })
            })
            .take(TX_COUNT),
        )
        .await
        .unwrap();

        // Verify: check that we got all of the desired aggregation jobs, with no duplication, and
        // the expected lease expiry.
        let want_expiry_time = clock.now().add(&LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&agg_job_id| {
                (
                    AcquiredAggregationJob::new(
                        *task.id(),
                        agg_job_id,
                        task::QueryType::TimeInterval,
                        VdafInstance::Prio3Aes128Count,
                    ),
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_leases = Vec::new();
        for result in results {
            assert!(result.len() <= MAXIMUM_ACQUIRE_COUNT);
            got_leases.extend(result.into_iter());
        }
        let mut got_aggregation_jobs: Vec<_> = got_leases
            .iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), *lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: release a few jobs, then attempt to acquire jobs again.
        const RELEASE_COUNT: usize = 2;

        // Sanity check constants: ensure we release fewer jobs than we're about to acquire to
        // ensure we can acquire them in all in a single call, while leaving headroom to acquire
        // at least one unwanted job if there is a logic bug.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(RELEASE_COUNT < MAXIMUM_ACQUIRE_COUNT);
        }

        let leases_to_release: Vec<_> = got_leases.into_iter().take(RELEASE_COUNT).collect();
        let mut jobs_to_release: Vec<_> = leases_to_release
            .iter()
            .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
            .collect();
        jobs_to_release.sort();
        ds.run_tx(|tx| {
            let leases_to_release = leases_to_release.clone();
            Box::pin(async move {
                for lease in leases_to_release {
                    tx.release_aggregation_job(&lease).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, MAXIMUM_ACQUIRE_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), *lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we should have re-acquired the jobs we released.
        assert_eq!(jobs_to_release, got_aggregation_jobs);

        // Run: advance time by the lease duration (which implicitly releases the jobs), and attempt
        // to acquire aggregation jobs again.
        clock.advance(LEASE_DURATION);
        let want_expiry_time = clock.now().add(&LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&job_id| {
                (
                    AcquiredAggregationJob::new(
                        *task.id(),
                        job_id,
                        task::QueryType::TimeInterval,
                        VdafInstance::Prio3Aes128Count,
                    ),
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    // This time, we just acquire all jobs in a single go for simplicity -- we've
                    // already tested the maximum acquire count functionality above.
                    tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, AGGREGATION_JOB_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                let job = (lease.leased().clone(), *lease.lease_expiry_time());
                let expected_attempts = if jobs_to_release.contains(&job) { 1 } else { 2 };
                assert_eq!(lease.lease_attempts(), expected_attempts);
                job
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we got all the jobs.
        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: advance time again to release jobs, acquire a single job, modify its lease token
        // to simulate a previously-held lease, and attempt to release it. Verify that releasing
        // fails.
        clock.advance(LEASE_DURATION);
        let lease = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&LEASE_DURATION, 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        let lease_with_random_token = Lease::new(
            lease.leased().clone(),
            *lease.lease_expiry_time(),
            random(),
            lease.lease_attempts(),
        );
        ds.run_tx(|tx| {
            let lease_with_random_token = lease_with_random_token.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease_with_random_token).await })
        })
        .await
        .unwrap_err();

        // Replace the original lease token and verify that we can release successfully with it in
        // place.
        ds.run_tx(|tx| {
            let lease = lease.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease).await })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn aggregation_job_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &random(),
                        &random(),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &AggregationJob::new(
                            random(),
                            random(),
                            (),
                            (),
                            AggregationJobState::InProgress,
                        ),
                    )
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_aggregation_jobs_for_task_id() {
        // Setup.
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        // We use a dummy VDAF & fixed-size task for this test, to better exercise the
        // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
        let task = TaskBuilder::new(
            QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let first_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            random(),
            dummy_vdaf::AggregationParam(23),
            AggregationJobState::InProgress,
        );
        let second_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            random(),
            dummy_vdaf::AggregationParam(42),
            AggregationJobState::InProgress,
        );

        ds.run_tx(|tx| {
            let (task, first_aggregation_job, second_aggregation_job) = (
                task.clone(),
                first_aggregation_job.clone(),
                second_aggregation_job.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_aggregation_job(&first_aggregation_job).await?;
                tx.put_aggregation_job(&second_aggregation_job).await?;

                // Also write an unrelated aggregation job with a different task ID to check that it
                // is not returned.
                let unrelated_task = TaskBuilder::new(
                    QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                tx.put_task(&unrelated_task).await?;
                tx.put_aggregation_job(&AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *unrelated_task.id(),
                    random(),
                    random(),
                    dummy_vdaf::AggregationParam(82),
                    AggregationJobState::InProgress,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run.
        let mut want_agg_jobs = Vec::from([first_aggregation_job, second_aggregation_job]);
        want_agg_jobs.sort_by_key(|agg_job| *agg_job.id());
        let mut got_agg_jobs = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_aggregation_jobs_for_task_id(task.id()).await })
            })
            .await
            .unwrap();
        got_agg_jobs.sort_by_key(|agg_job| *agg_job.id());

        // Verify.
        assert_eq!(want_agg_jobs, got_agg_jobs);
    }

    #[tokio::test]
    async fn roundtrip_report_aggregation() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let (prep_state, prep_msg, output_share) = generate_vdaf_values(vdaf.as_ref(), (), 0);

        for (ord, state) in [
            ReportAggregationState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
            ReportAggregationState::Waiting(prep_state.clone(), None),
            ReportAggregationState::Waiting(prep_state, Some(prep_msg)),
            ReportAggregationState::Finished(output_share),
            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            ReportAggregationState::Invalid,
        ]
        .into_iter()
        .enumerate()
        {
            let task = TaskBuilder::new(
                QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build();
            let aggregation_job_id = random();
            let time = Time::from_seconds_since_epoch(12345);
            let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

            let report_aggregation = ds
                .run_tx(|tx| {
                    let (task, state) = (task.clone(), state.clone());
                    Box::pin(async move {
                        tx.put_task(&task).await?;
                        tx.put_aggregation_job(&AggregationJob::<
                            PRIO3_AES128_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            Prio3Aes128Count,
                        >::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            (),
                            AggregationJobState::InProgress,
                        ))
                        .await?;
                        tx.put_report_share(
                            task.id(),
                            &ReportShare::new(
                                AggregateReportMetadata::new(report_id, time, Vec::new()),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            report_id,
                            time,
                            ord as i64,
                            state,
                        );
                        tx.put_report_aggregation(&report_aggregation).await?;
                        Ok(report_aggregation)
                    })
                })
                .await
                .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(&report_aggregation), got_report_aggregation.as_ref());

            let new_report_aggregation = ReportAggregation::new(
                *report_aggregation.task_id(),
                *report_aggregation.aggregation_job_id(),
                *report_aggregation.report_id(),
                *report_aggregation.time(),
                report_aggregation.ord() + 10,
                report_aggregation.state().clone(),
            );
            ds.run_tx(|tx| {
                let new_report_aggregation = new_report_aggregation.clone();
                Box::pin(async move { tx.update_report_aggregation(&new_report_aggregation).await })
            })
            .await
            .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(new_report_aggregation), got_report_aggregation);
        }
    }

    #[tokio::test]
    async fn report_aggregation_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let vdaf = Arc::new(dummy_vdaf::Vdaf::default());

        let rslt = ds
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        &Role::Leader,
                        &random(),
                        &random(),
                        &ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        random(),
                        random(),
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(12345),
                        0,
                        ReportAggregationState::Invalid,
                    ))
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_report_aggregations_for_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let (prep_state, prep_msg, output_share) = generate_vdaf_values(vdaf.as_ref(), (), 0);

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let aggregation_job_id = random();

        let report_aggregations = ds
            .run_tx(|tx| {
                let (task, prep_msg, prep_state, output_share) = (
                    task.clone(),
                    prep_msg.clone(),
                    prep_state.clone(),
                    output_share.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        AggregationJobState::InProgress,
                    ))
                    .await?;

                    let mut report_aggregations = Vec::new();
                    for (ord, state) in
                        [
                            ReportAggregationState::<
                                PRIO3_AES128_VERIFY_KEY_LENGTH,
                                Prio3Aes128Count,
                            >::Start,
                            ReportAggregationState::Waiting(prep_state.clone(), None),
                            ReportAggregationState::Waiting(prep_state, Some(prep_msg)),
                            ReportAggregationState::Finished(output_share),
                            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                            ReportAggregationState::Invalid,
                        ]
                        .iter()
                        .enumerate()
                    {
                        let time = Time::from_seconds_since_epoch(12345);
                        let report_id = ReportId::from((ord as u128).to_be_bytes());
                        tx.put_report_share(
                            task.id(),
                            &ReportShare::new(
                                AggregateReportMetadata::new(report_id, time, Vec::new()),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            report_id,
                            time,
                            ord as i64,
                            state.clone(),
                        );
                        tx.put_report_aggregation(&report_aggregation).await?;
                        report_aggregations.push(report_aggregation);
                    }
                    Ok(report_aggregations)
                })
            })
            .await
            .unwrap();

        let got_report_aggregations = ds
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    tx.get_report_aggregations_for_aggregation_job(
                        vdaf.as_ref(),
                        &Role::Leader,
                        task.id(),
                        &aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report_aggregations, got_report_aggregations);
    }

    #[tokio::test]
    async fn crypter() {
        let crypter = Crypter::new(Vec::from([generate_aead_key(), generate_aead_key()]));
        let bad_key = generate_aead_key();

        const TABLE: &str = "some_table";
        const ROW: &[u8] = b"12345";
        const COLUMN: &str = "some_column";
        const PLAINTEXT: &[u8] = b"This is my plaintext value.";

        // Test that roundtripping encryption works.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption works even if a non-primary key was used for encryption.
        let ciphertext =
            Crypter::encrypt_with_key(crypter.keys.last().unwrap(), TABLE, ROW, COLUMN, PLAINTEXT)
                .unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption with an unknown key fails.
        let ciphertext =
            Crypter::encrypt_with_key(&bad_key, TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).is_err());

        // Roundtripping encryption with a mismatched table, row, or column fails.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter
            .decrypt("wrong_table", ROW, COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, b"wrong_row", COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, ROW, "wrong_column", &ciphertext)
            .is_err());
    }

    #[tokio::test]
    async fn lookup_collect_job() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let timestamp = Time::from_seconds_since_epoch(150);
        let interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(10),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
        .unwrap();

        let collect_job_id = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_collect_job_id::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task.id(),
                        &batch_interval,
                        &(),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert!(collect_job_id.is_none());

        let collect_job_id = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    let collect_job = CollectJob::new(
                        *task.id(),
                        Uuid::new_v4(),
                        batch_interval,
                        (),
                        CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                    );
                    tx.put_collect_job(&collect_job).await?;
                    Ok(*collect_job.collect_job_id())
                })
            })
            .await
            .unwrap();

        let same_collect_job_id = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_collect_job_id::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task.id(),
                        &batch_interval,
                        &(),
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();

        // Should get the same UUID for the same values.
        assert_eq!(collect_job_id, same_collect_job_id);

        // Check that we can find the collect job by timestamp.
        let (collect_jobs_by_time, collect_jobs_by_interval) = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    let collect_jobs_by_time = tx.get_collect_jobs_including_time::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task.id(), &timestamp).await?;
                    let collect_jobs_by_interval = tx.get_collect_jobs_jobs_intersecting_interval::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task.id(), &interval).await?;
                    Ok((collect_jobs_by_time, collect_jobs_by_interval))
                })
            })
            .await
            .unwrap();

        let want_collect_jobs = Vec::from([CollectJob::<
            PRIO3_AES128_VERIFY_KEY_LENGTH,
            Prio3Aes128Count,
        >::new(
            *task.id(),
            collect_job_id,
            batch_interval,
            (),
            CollectJobState::Start,
        )]);

        assert_eq!(collect_jobs_by_time, want_collect_jobs);
        assert_eq!(collect_jobs_by_interval, want_collect_jobs);

        let rows = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.tx
                        .query("SELECT id FROM collect_jobs", &[])
                        .await
                        .map_err(Error::from)
                })
            })
            .await
            .unwrap();

        assert!(rows.len() == 1);

        let different_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(101),
            Duration::from_seconds(100),
        )
        .unwrap();
        let different_collect_job_id = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    let collect_job_id = Uuid::new_v4();
                    tx.put_collect_job(&CollectJob::new(
                        *task.id(),
                        collect_job_id,
                        different_batch_interval,
                        (),
                        CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                    ))
                    .await?;
                    Ok(collect_job_id)
                })
            })
            .await
            .unwrap();

        // New collect job should yield a new UUID.
        assert!(different_collect_job_id != collect_job_id);

        let rows = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.tx
                        .query("SELECT id FROM collect_jobs", &[])
                        .await
                        .map_err(Error::from)
                })
            })
            .await
            .unwrap();

        // A new row should be present.
        assert!(rows.len() == 2);

        // Check that we can find both collect jobs by timestamp.
        let (mut collect_jobs_by_time, mut collect_jobs_by_interval) = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    let collect_jobs_by_time = tx.get_collect_jobs_including_time::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task.id(), &timestamp).await?;
                    let collect_jobs_by_interval = tx.get_collect_jobs_jobs_intersecting_interval::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task.id(), &interval).await?;
                    Ok((collect_jobs_by_time, collect_jobs_by_interval))
                })
            })
            .await
            .unwrap();
        collect_jobs_by_time.sort_by(|x, y| x.collect_job_id().cmp(y.collect_job_id()));
        collect_jobs_by_interval.sort_by(|x, y| x.collect_job_id().cmp(y.collect_job_id()));

        let mut want_collect_jobs = Vec::from([
            CollectJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                collect_job_id,
                batch_interval,
                (),
                CollectJobState::Start,
            ),
            CollectJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                different_collect_job_id,
                different_batch_interval,
                (),
                CollectJobState::Start,
            ),
        ]);
        want_collect_jobs.sort_by(|x, y| x.collect_job_id().cmp(y.collect_job_id()));

        assert_eq!(collect_jobs_by_time, want_collect_jobs);
        assert_eq!(collect_jobs_by_interval, want_collect_jobs);
    }

    #[tokio::test]
    async fn get_collect_job() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let first_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let second_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(200),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await.unwrap();

                let first_collect_job = CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    first_batch_interval,
                    (),
                    CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                );
                tx.put_collect_job(&first_collect_job).await.unwrap();

                let second_collect_job = CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    second_batch_interval,
                    (),
                    CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                );
                tx.put_collect_job(&second_collect_job).await.unwrap();

                let first_collect_job_again = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        first_collect_job.collect_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collect_job, first_collect_job_again);

                let second_collect_job_again = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        second_collect_job.collect_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(second_collect_job, second_collect_job_again);

                let leader_aggregate_share = AggregateShare::from(Vec::from([Field64::from(1)]));

                let encrypted_helper_aggregate_share = hpke::seal(
                    task.collector_hpke_config(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &[0, 1, 2, 3, 4, 5],
                    &associated_data_for_aggregate_share::<TimeInterval>(
                        task.id(),
                        &first_batch_interval,
                    ),
                )
                .unwrap();

                let first_collect_job = first_collect_job.with_state(CollectJobState::Finished {
                    report_count: 12,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                });

                tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &first_collect_job,
                )
                .await
                .unwrap();

                let updated_first_collect_job = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        first_collect_job.collect_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collect_job, updated_first_collect_job);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn update_collect_jobs() {
        // Setup: write collect jobs to the datastore.
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let abandoned_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let deleted_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(100),
        )
        .unwrap();

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await?;

                let abandoned_collect_job = CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    abandoned_batch_interval,
                    (),
                    CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                );
                tx.put_collect_job(&abandoned_collect_job).await?;

                let deleted_collect_job = CollectJob::new(
                    *task.id(),
                    Uuid::new_v4(),
                    deleted_batch_interval,
                    (),
                    CollectJobState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
                );
                tx.put_collect_job(&deleted_collect_job).await?;

                let abandoned_collect_job_again = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        abandoned_collect_job.collect_job_id(),
                    )
                    .await?
                    .unwrap();

                // Verify: initial state.
                assert_eq!(abandoned_collect_job, abandoned_collect_job_again);

                // Setup: update the collect jobs.
                let abandoned_collect_job =
                    abandoned_collect_job.with_state(CollectJobState::Abandoned);
                let deleted_collect_job = deleted_collect_job.with_state(CollectJobState::Deleted);

                tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &abandoned_collect_job,
                )
                .await?;
                tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &deleted_collect_job,
                )
                .await?;

                let abandoned_collect_job_again = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        abandoned_collect_job.collect_job_id(),
                    )
                    .await?
                    .unwrap();

                let deleted_collect_job_again = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        deleted_collect_job.collect_job_id(),
                    )
                    .await?
                    .unwrap();

                // Verify: collect jobs were updated.
                assert_eq!(abandoned_collect_job, abandoned_collect_job_again);
                assert_eq!(deleted_collect_job, deleted_collect_job_again);

                // Setup: try to update a job into state `Start`
                let abandoned_collect_job =
                    abandoned_collect_job.with_state(CollectJobState::Start);

                // Verify: Update should fail
                tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &abandoned_collect_job,
                )
                .await
                .unwrap_err();
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[derive(Copy, Clone)]
    enum CollectJobTestCaseState {
        Start,
        Finished,
        Deleted,
        Abandoned,
    }

    #[derive(Clone)]
    struct CollectJobTestCase {
        should_be_acquired: bool,
        task_id: TaskId,
        batch_interval: Interval,
        agg_param: AggregationParam,
        collect_job_id: Option<Uuid>,
        state: CollectJobTestCaseState,
    }

    #[derive(Clone)]
    struct CollectJobAcquireTestCase {
        task_ids: Vec<TaskId>,
        reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>>,
        aggregation_jobs: Vec<AggregationJob<0, TimeInterval, dummy_vdaf::Vdaf>>,
        report_aggregations: Vec<ReportAggregation<0, dummy_vdaf::Vdaf>>,
        collect_job_test_cases: Vec<CollectJobTestCase>,
    }

    async fn setup_collect_job_acquire_test_case(
        ds: &Datastore<MockClock>,
        test_case: CollectJobAcquireTestCase,
    ) -> CollectJobAcquireTestCase {
        ds.run_tx(|tx| {
            let mut test_case = test_case.clone();
            Box::pin(async move {
                for task_id in &test_case.task_ids {
                    tx.put_task(
                        &TaskBuilder::new(
                            QueryType::TimeInterval,
                            VdafInstance::Fake,
                            Role::Leader,
                        )
                        .with_id(*task_id)
                        .build(),
                    )
                    .await?;
                }

                for report in &test_case.reports {
                    tx.put_client_report(report).await?;
                }

                for aggregation_job in &test_case.aggregation_jobs {
                    tx.put_aggregation_job(aggregation_job).await?;
                }

                for report_aggregation in &test_case.report_aggregations {
                    tx.put_report_aggregation(report_aggregation).await?;
                }

                for test_case in test_case.collect_job_test_cases.iter_mut() {
                    let collect_job = CollectJob::<0, dummy_vdaf::Vdaf>::new(
                        test_case.task_id,
                        Uuid::new_v4(),
                        test_case.batch_interval,
                        test_case.agg_param,
                        match test_case.state {
                            CollectJobTestCaseState::Start => CollectJobState::Start,
                            CollectJobTestCaseState::Finished => CollectJobState::Finished {
                                report_count: 1,
                                encrypted_helper_aggregate_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(0),
                                    Vec::new(),
                                    Vec::new(),
                                ),
                                leader_aggregate_share: dummy_vdaf::AggregateShare(0),
                            },
                            CollectJobTestCaseState::Abandoned => CollectJobState::Abandoned,
                            CollectJobTestCaseState::Deleted => CollectJobState::Deleted,
                        },
                    );
                    tx.put_collect_job(&collect_job).await?;
                    test_case.collect_job_id = Some(*collect_job.collect_job_id());
                }

                Ok(test_case)
            })
        })
        .await
        .unwrap()
    }

    async fn run_collect_job_acquire_test_case(
        ds: &Datastore<MockClock>,
        test_case: CollectJobAcquireTestCase,
    ) -> Vec<Lease<AcquiredCollectJob>> {
        let test_case = setup_collect_job_acquire_test_case(ds, test_case).await;

        let clock = &ds.clock;
        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                let collect_job_leases = tx
                    .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 10)
                    .await?;

                let mut leased_collect_jobs: Vec<_> = collect_job_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                    .collect();
                leased_collect_jobs.sort();

                let mut expected_collect_jobs: Vec<_> = test_case
                    .collect_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectJob::new(
                                c.task_id,
                                c.collect_job_id.unwrap(),
                                VdafInstance::Fake,
                            ),
                            clock.now().add(&Duration::from_seconds(100)).unwrap(),
                        )
                    })
                    .collect();
                expected_collect_jobs.sort();

                assert_eq!(leased_collect_jobs, expected_collect_jobs);

                Ok(collect_job_leases)
            })
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn collect_job_acquire_release_happy_path() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            )]);
        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start, // Doesn't matter what state the report aggregation is in
        )]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: true,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            state: CollectJobTestCaseState::Start,
        }]);

        let collect_job_leases = run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;

        let reacquired_jobs = ds
            .run_tx(|tx| {
                let collect_job_leases = collect_job_leases.clone();
                Box::pin(async move {
                    // Try to re-acquire collect jobs. Nothing should happen because the lease is still
                    // valid.
                    assert!(tx
                        .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 10)
                        .await
                        .unwrap()
                        .is_empty());

                    // Release the lease, then re-acquire it.
                    tx.release_collect_job(&collect_job_leases[0])
                        .await
                        .unwrap();

                    let reacquired_leases = tx
                        .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 10)
                        .await
                        .unwrap();
                    let reacquired_jobs: Vec<_> = reacquired_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    let collect_jobs: Vec<_> = collect_job_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    assert_eq!(reacquired_jobs.len(), 1);
                    assert_eq!(reacquired_jobs, collect_jobs);

                    Ok(reacquired_leases)
                })
            })
            .await
            .unwrap();

        // Advance time by the lease duration
        clock.advance(Duration::from_seconds(100));

        ds.run_tx(|tx| {
            let reacquired_jobs = reacquired_jobs.clone();
            Box::pin(async move {
                // Re-acquire the jobs whose lease should have lapsed.
                let acquired_jobs = tx
                    .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 10)
                    .await
                    .unwrap();

                for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                    assert_eq!(acquired_job.leased(), reacquired_job.leased());
                    assert_eq!(
                        acquired_job.lease_expiry_time(),
                        &reacquired_job
                            .lease_expiry_time()
                            .add(&Duration::from_seconds(100))
                            .unwrap(),
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn collect_job_acquire_no_aggregation_job_with_task_id() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let other_task_id = random();

        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                // Aggregation job task ID does not match collect job task ID
                other_task_id,
                random(),
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            )]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            state: CollectJobTestCaseState::Start,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id, other_task_id]),
                reports: Vec::new(),
                aggregation_jobs,
                report_aggregations: Vec::new(),
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_no_aggregation_job_with_agg_param() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            Time::from_seconds_since_epoch(0),
        )]);

        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                random(),
                (),
                // Aggregation job agg param does not match collect job agg param
                AggregationParam(1),
                AggregationJobState::Finished,
            )]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            state: CollectJobTestCaseState::Start,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations: Vec::new(),
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_report_shares_outside_interval() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            // Report associated with the aggregation job is outside the collect job's batch
            // interval
            Time::from_seconds_since_epoch(200),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            )]);
        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start, // Shouldn't matter what state the report aggregation is in
        )]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            state: CollectJobTestCaseState::Start,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_release_job_finished() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            )]);

        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start,
        )]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            // Collect job has already run to completion
            state: CollectJobTestCaseState::Finished,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_release_aggregation_job_in_progress() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([
            LeaderStoredReport::new_dummy(&task_id, Time::from_seconds_since_epoch(0)),
            LeaderStoredReport::new_dummy(&task_id, Time::from_seconds_since_epoch(50)),
        ]);

        let aggregation_job_ids: [_; 2] = random();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                (),
                AggregationParam(0),
                // Aggregation job included in collect request is in progress
                AggregationJobState::InProgress,
            ),
        ]);

        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[1].id(),
                *reports[1].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            state: CollectJobTestCaseState::Start,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_job_max() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_ids: [_; 2] = random();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                (),
                AggregationParam(1),
                AggregationJobState::Finished,
            ),
        ]);
        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collect_job_test_cases = Vec::from([
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(0),
                collect_job_id: None,
                state: CollectJobTestCaseState::Start,
            },
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(1),
                collect_job_id: None,
                state: CollectJobTestCaseState::Start,
            },
        ]);

        let test_case = setup_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;

        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                // Acquire a single collect job, twice. Each call should yield one job. We don't
                // care what order they are acquired in.
                let mut acquired_collect_jobs = tx
                    .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 1)
                    .await?;
                assert_eq!(acquired_collect_jobs.len(), 1);

                acquired_collect_jobs.extend(
                    tx.acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 1)
                        .await?,
                );

                assert_eq!(acquired_collect_jobs.len(), 2);

                let mut acquired_collect_jobs: Vec<_> = acquired_collect_jobs
                    .iter()
                    .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                    .collect();
                acquired_collect_jobs.sort();

                let mut expected_collect_jobs: Vec<_> = test_case
                    .collect_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectJob::new(
                                c.task_id,
                                c.collect_job_id.unwrap(),
                                VdafInstance::Fake,
                            ),
                            clock.now().add(&Duration::from_seconds(100)).unwrap(),
                        )
                    })
                    .collect();
                expected_collect_jobs.sort();

                assert_eq!(acquired_collect_jobs, expected_collect_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn collect_job_acquire_state_filtering() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            &task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_ids: [_; 3] = random();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                (),
                AggregationParam(0),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                (),
                AggregationParam(1),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[2],
                (),
                AggregationParam(2),
                AggregationJobState::Finished,
            ),
        ]);
        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[2],
                *reports[0].id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collect_job_test_cases = Vec::from([
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(0),
                collect_job_id: None,
                state: CollectJobTestCaseState::Finished,
            },
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(1),
                collect_job_id: None,
                state: CollectJobTestCaseState::Abandoned,
            },
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(2),
                collect_job_id: None,
                state: CollectJobTestCaseState::Deleted,
            },
        ]);

        setup_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                // No collect jobs should be acquired because none of them are in the START state
                let acquired_collect_jobs = tx
                    .acquire_incomplete_collect_jobs(&Duration::from_seconds(100), 10)
                    .await?;
                assert!(acquired_collect_jobs.is_empty());

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_batch_aggregation_time_interval() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let time_precision = Duration::from_seconds(100);
                let task =
                    TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                        .with_time_precision(time_precision)
                        .build();
                let other_task =
                    TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                        .build();
                let aggregate_share = dummy_vdaf::AggregateShare(23);
                let aggregation_param = AggregationParam(12);

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                let first_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(100), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                let second_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(200), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                let third_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(300), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                // Start of this aggregation's interval is before the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(0), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Following three batches are within the interval queried below.
                tx.put_batch_aggregation(&first_batch_aggregation).await?;
                tx.put_batch_aggregation(&second_batch_aggregation).await?;
                tx.put_batch_aggregation(&third_batch_aggregation).await?;

                // Aggregation parameter differs from the one queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(100), time_precision).unwrap(),
                        dummy_vdaf::AggregationParam(13),
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Start of this aggregation's interval is after the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(400), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *other_task.id(),
                        Interval::new(Time::from_seconds_since_epoch(200), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                let batch_aggregations =
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        0,
                        dummy_vdaf::Vdaf,
                        _,
                    >(
                        tx,
                        &task,
                        &Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(3 * time_precision.as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(batch_aggregations.len(), 3, "{:#?}", batch_aggregations);
                for batch_aggregation in [
                    &first_batch_aggregation,
                    &second_batch_aggregation,
                    &third_batch_aggregation,
                ] {
                    assert!(
                        batch_aggregations.contains(batch_aggregation),
                        "{:#?}",
                        batch_aggregations
                    );
                }

                let first_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *first_batch_aggregation.task_id(),
                        *first_batch_aggregation.batch_interval(),
                        *first_batch_aggregation.aggregation_parameter(),
                        dummy_vdaf::AggregateShare(92),
                        1,
                        ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                    );
                tx.update_batch_aggregation(&first_batch_aggregation)
                    .await?;

                let batch_aggregations =
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        0,
                        dummy_vdaf::Vdaf,
                        _,
                    >(
                        tx,
                        &task,
                        &Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(3 * time_precision.as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(batch_aggregations.len(), 3, "{:#?}", batch_aggregations);
                for batch_aggregation in [
                    &first_batch_aggregation,
                    &second_batch_aggregation,
                    &third_batch_aggregation,
                ] {
                    assert!(
                        batch_aggregations.contains(batch_aggregation),
                        "{:#?}",
                        batch_aggregations
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_batch_aggregation_fixed_size() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                let other_task = TaskBuilder::new(
                    QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                let batch_id = random();
                let aggregate_share = dummy_vdaf::AggregateShare(23);
                let aggregation_param = dummy_vdaf::AggregationParam(12);

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                );

                // Following three batches are within the interval queried below.
                tx.put_batch_aggregation(&batch_aggregation).await?;

                // Wrong batch ID.
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    dummy_vdaf::AggregationParam(13),
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                ))
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *other_task.id(),
                    batch_id,
                    aggregation_param,
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                ))
                .await?;

                let got_batch_aggregation = tx
                    .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_id,
                        &aggregation_param,
                    )
                    .await?;
                assert_eq!(got_batch_aggregation.as_ref(), Some(&batch_aggregation));

                let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *batch_aggregation.task_id(),
                    *batch_aggregation.batch_id(),
                    *batch_aggregation.aggregation_parameter(),
                    dummy_vdaf::AggregateShare(92),
                    1,
                    ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                );
                tx.update_batch_aggregation(&batch_aggregation).await?;

                let got_batch_aggregation = tx
                    .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_id,
                        &aggregation_param,
                    )
                    .await?;
                assert_eq!(got_batch_aggregation, Some(batch_aggregation));
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_aggregate_share_job() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    QueryType::TimeInterval,
                    VdafInstance::Prio3Aes128Count,
                    Role::Helper,
                ).build();
                tx.put_task(&task).await?;

                let aggregate_share = AggregateShare::from(Vec::from([Field64::from(17)]));
                let batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(100),
                    Duration::from_seconds(100),
                )
                .unwrap();
                let other_batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(101),
                    Duration::from_seconds(101),
                )
                .unwrap();
                let report_count = 10;
                let checksum = ReportIdChecksum::get_decoded(&[1; 32]).unwrap();

                let aggregate_share_job = AggregateShareJob::new(
                    *task.id(),
                    batch_interval,
                    (),
                    aggregate_share.clone(),
                    report_count,
                    checksum,
                );

                tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &aggregate_share_job,
                )
                .await
                .unwrap();

                let aggregate_share_job_again = tx
                    .get_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task.id(),
                        &batch_interval,
                        &().get_encoded(),
                    )
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(aggregate_share_job, aggregate_share_job_again);

                assert!(tx
                    .get_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task.id(),
                        &other_batch_interval,
                        &().get_encoded(),
                    )
                    .await
                    .unwrap()
                    .is_none());

                let want_aggregate_share_jobs = Vec::from([aggregate_share_job]);

                let got_aggregate_share_jobs = tx.get_aggregate_share_jobs_including_time::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    task.id(), &Time::from_seconds_since_epoch(150)).await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                let got_aggregate_share_jobs = tx.get_aggregate_share_jobs_intersecting_interval::
                    <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task.id(),
                        &Interval::new(
                            Time::from_seconds_since_epoch(145),
                            Duration::from_seconds(10))
                        .unwrap()).await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_outstanding_batch() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let (task_id, batch_id) = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    let task = TaskBuilder::new(
                        QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    tx.put_task(&task).await?;
                    let batch_id = random();
                    tx.put_outstanding_batch(task.id(), &batch_id).await?;

                    // Write a few aggregation jobs & report aggregations to produce useful
                    // min_size/max_size values to validate later.
                    let aggregation_job_0 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        batch_id,
                        AggregationParam(0),
                        AggregationJobState::Finished,
                    );
                    let report_aggregation_0_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        0,
                        ReportAggregationState::Start, // Counted among max_size.
                    );
                    let report_aggregation_0_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        1,
                        ReportAggregationState::Waiting((), Some(())), // Counted among max_size.
                    );
                    let report_aggregation_0_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        2,
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                    );
                    let report_aggregation_0_3 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        3,
                        ReportAggregationState::Invalid, // Not counted among min_size or max_size.
                    );

                    let aggregation_job_1 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        batch_id,
                        AggregationParam(0),
                        AggregationJobState::Finished,
                    );
                    let report_aggregation_1_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        0,
                        ReportAggregationState::Finished(dummy_vdaf::OutputShare()), // Counted among min_size and max_size.
                    );
                    let report_aggregation_1_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        1,
                        ReportAggregationState::Finished(dummy_vdaf::OutputShare()), // Counted among min_size and max_size.
                    );
                    let report_aggregation_1_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        2,
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                    );
                    let report_aggregation_1_3 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        3,
                        ReportAggregationState::Invalid, // Not counted among min_size or max_size.
                    );

                    for aggregation_job in &[aggregation_job_0, aggregation_job_1] {
                        tx.put_aggregation_job(aggregation_job).await?;
                    }
                    for report_aggregation in &[
                        report_aggregation_0_0,
                        report_aggregation_0_1,
                        report_aggregation_0_2,
                        report_aggregation_0_3,
                        report_aggregation_1_0,
                        report_aggregation_1_1,
                        report_aggregation_1_2,
                        report_aggregation_1_3,
                    ] {
                        tx.put_client_report::<0, dummy_vdaf::Vdaf>(&LeaderStoredReport::new(
                            *report_aggregation.task_id(),
                            *report_aggregation.report_id(),
                            UploadReportMetadata::new(*report_aggregation.time(), Vec::new()),
                            (), // Dummy public share
                            (), // Dummy leader input share
                            // Dummy helper encrypted input share
                            HpkeCiphertext::new(
                                HpkeConfigId::from(13),
                                Vec::from("encapsulated_context_0"),
                                Vec::from("payload_0"),
                            ),
                        ))
                        .await?;
                        tx.put_report_aggregation(report_aggregation).await?;
                    }

                    Ok((*task.id(), batch_id))
                })
            })
            .await
            .unwrap();

        let outstanding_batches = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.get_outstanding_batches_for_task(&task_id).await })
            })
            .await
            .unwrap();
        assert_eq!(
            outstanding_batches,
            Vec::from([OutstandingBatch::new(
                task_id,
                batch_id,
                RangeInclusive::new(2, 4)
            )])
        );
    }

    /// generate_vdaf_values generates some arbitrary VDAF values for use in testing. It is cribbed
    /// heavily from `libprio-rs`' `run_vdaf`. The resulting values are guaranteed to be associated
    /// with the same aggregator.
    ///
    /// generate_vdaf_values assumes that the VDAF in use is one-round.
    fn generate_vdaf_values<const L: usize, A: vdaf::Aggregator<L> + vdaf::Client>(
        vdaf: &A,
        agg_param: A::AggregationParam,
        measurement: A::Measurement,
    ) -> (A::PrepareState, A::PrepareMessage, A::OutputShare)
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let (public_share, input_shares) = vdaf.shard(&measurement).unwrap();
        let verify_key: [u8; L] = random();

        let (mut prep_states, prep_shares): (Vec<_>, Vec<_>) = input_shares
            .iter()
            .enumerate()
            .map(|(agg_id, input_share)| {
                vdaf.prepare_init(
                    &verify_key,
                    agg_id,
                    &agg_param,
                    b"nonce",
                    &public_share,
                    input_share,
                )
                .unwrap()
            })
            .unzip();
        let prep_msg = vdaf.prepare_preprocess(prep_shares).unwrap();
        let mut output_shares: Vec<A::OutputShare> = prep_states
            .iter()
            .map(|prep_state| {
                if let PrepareTransition::Finish(output_share) = vdaf
                    .prepare_step(prep_state.clone(), prep_msg.clone())
                    .unwrap()
                {
                    output_share
                } else {
                    panic!("generate_vdaf_values: VDAF returned something other than Finish")
                }
            })
            .collect();

        (prep_states.remove(0), prep_msg, output_shares.remove(0))
    }

    #[tokio::test]
    async fn roundtrip_interval_sql() {
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let interval = tx
                        .tx
                        .query_one(
                            "SELECT '[2020-01-01 10:00, 2020-01-01 10:30)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, SqlInterval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            &NaiveDate::from_ymd(2020, 1, 1).and_hms(10, 0, 0),
                        ),
                        Duration::from_minutes(30).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(interval.as_interval(), ref_interval);

                    let interval = tx
                        .tx
                        .query_one(
                            "SELECT '[1970-02-03 23:00, 1970-02-04 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, SqlInterval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            &NaiveDate::from_ymd(1970, 2, 3).and_hms(23, 0, 0),
                        ),
                        Duration::from_hours(1).unwrap(),
                    )?;
                    assert_eq!(interval.as_interval(), ref_interval);

                    let res = tx
                        .tx
                        .query_one(
                            "SELECT '[1969-01-01 00:00, 1970-01-01 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .try_get::<_, SqlInterval>("interval");
                    assert!(res.is_err());

                    let ok = tx
                        .tx
                        .query_one(
                            "SELECT (lower(interval) = '1972-07-21 05:30:00' AND
                            upper(interval) = '1972-07-21 06:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&SqlInterval::from(
                                Interval::new(
                                    Time::from_naive_date_time(
                                        &NaiveDate::from_ymd(1972, 7, 21).and_hms(5, 30, 0),
                                    ),
                                    Duration::from_minutes(30).unwrap(),
                                )
                                .unwrap(),
                            )],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    let ok = tx
                        .tx
                        .query_one(
                            "SELECT (lower(interval) = '2021-10-05 00:00:00' AND
                            upper(interval) = '2021-10-06 00:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&SqlInterval::from(
                                Interval::new(
                                    Time::from_naive_date_time(
                                        &NaiveDate::from_ymd(2021, 10, 5).and_hms(0, 0, 0),
                                    ),
                                    Duration::from_hours(24).unwrap(),
                                )
                                .unwrap(),
                            )],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    Ok(())
                })
            })
            .await
            .unwrap();
    }
}
