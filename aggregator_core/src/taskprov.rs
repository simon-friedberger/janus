use derivative::Derivative;
use janus_core::task::{AuthenticationToken, VdafInstance};
use janus_messages::{Duration, HpkeConfig, Role, TaskId, Time};
use lazy_static::lazy_static;
use rand::{distributions::Standard, prelude::Distribution};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use url::Url;

use crate::{
    task::{self, Error, QueryType},
    SecretBytes,
};

#[derive(Derivative, Clone, Copy, PartialEq, Eq)]
#[derivative(Debug)]
pub struct VerifyKeyInit(#[derivative(Debug = "ignore")] [u8; Self::LEN]);

impl VerifyKeyInit {
    pub const LEN: usize = 32;
}

impl TryFrom<&[u8]> for VerifyKeyInit {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            Error::InvalidParameter("byte slice has incorrect length for VerifyKeyInit")
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for VerifyKeyInit {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Distribution<VerifyKeyInit> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> VerifyKeyInit {
        VerifyKeyInit(rng.gen())
    }
}

/// Represents another aggregator that is peered with our aggregator for taskprov purposes. Contains
/// data that needs to be identical between both aggregators for the taskprov flow to work.
#[derive(Debug, Clone, Derivative, PartialEq, Eq)]
pub struct PeerAggregator {
    /// The URL at which the peer aggregator can be reached. This, along with `role`, is used to
    /// uniquely represent the peer aggregator.
    endpoint: Url,

    /// The role that the peer aggregator takes in DAP. Must be [`Role::Leader`] or [`Role::Helper`].
    /// This, along with `endpoint`, uniquely represents the peer aggregator.
    role: Role,

    /// The preshared key used to derive the VDAF verify key for each task.
    verify_key_init: VerifyKeyInit,

    // The HPKE configuration of the collector. This needs to be shared out-of-band with the peer
    // aggregator.
    collector_hpke_config: HpkeConfig,

    /// How long reports exist until they're eligible for GC. Set to None for no GC. This value is
    /// copied into the definition for a provisioned task.
    report_expiry_age: Option<Duration>,

    /// The maximum allowable clock skew between peers. This value is copied into the definition for
    /// a provisioned task.
    tolerable_clock_skew: Duration,

    /// Auth tokens used for authenticating Leader to Helper requests.
    aggregator_auth_tokens: Vec<AuthenticationToken>,

    /// Auth tokens used for authenticating Collector to Leader requests. It should be empty if the
    /// peer aggregator is the Leader.
    collector_auth_tokens: Vec<AuthenticationToken>,
}

lazy_static! {
    /// Salt generated by the SHA256 of the string 'dap-taskprov". See [taskprov section 3.2][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-wang-ppm-dap-taskprov-04.html#name-deriving-the-vdaf-verificat
    static ref SALT: Salt = Salt::new(
        HKDF_SHA256,
        &[
            0x28, 0xb9, 0xbb, 0x4f, 0x62, 0x4f, 0x67, 0x9a, 0xc1, 0x98, 0xd9, 0x68, 0xf4, 0xb0,
            0x9e, 0xec, 0x74, 0x1, 0x7a, 0x52, 0xcb, 0x4c, 0xf6, 0x39, 0xfb, 0x83, 0xe0, 0x47,
            0x72, 0x3a, 0xf, 0xfe,
        ]
    );
}

impl PeerAggregator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: Url,
        role: Role,
        verify_key_init: VerifyKeyInit,
        collector_hpke_config: HpkeConfig,
        report_expiry_age: Option<Duration>,
        tolerable_clock_skew: Duration,
        aggregator_auth_tokens: Vec<AuthenticationToken>,
        collector_auth_tokens: Vec<AuthenticationToken>,
    ) -> Self {
        Self {
            endpoint,
            role,
            verify_key_init,
            collector_hpke_config,
            report_expiry_age,
            tolerable_clock_skew,
            aggregator_auth_tokens,
            collector_auth_tokens,
        }
    }

    /// Retrieve the URL endpoint of the peer.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Retrieve the role of the peer.
    pub fn role(&self) -> &Role {
        &self.role
    }

    /// Retrieve the VDAF verify key initialization parameter, used for derivation of the VDAF
    /// verify key for a task.
    pub fn verify_key_init(&self) -> &VerifyKeyInit {
        &self.verify_key_init
    }

    /// Retrieve the collector HPKE configuration for this peer.
    pub fn collector_hpke_config(&self) -> &HpkeConfig {
        &self.collector_hpke_config
    }

    /// Retrieve the report expiry age that each task will be configured with.
    pub fn report_expiry_age(&self) -> Option<&Duration> {
        self.report_expiry_age.as_ref()
    }

    /// Retrieve the maximum tolerable clock skew that each task will be configured with.
    pub fn tolerable_clock_skew(&self) -> &Duration {
        &self.tolerable_clock_skew
    }

    /// Retrieve the [`AuthenticationToken`]s used for authenticating leader to helper requests.
    pub fn aggregator_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.aggregator_auth_tokens
    }

    /// Retrieve the [`AuthenticationToken`]s used for authenticating collector to leader requests.
    pub fn collector_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.collector_auth_tokens
    }

    /// Returns the [`AuthenticationToken`] currently used by this peer to authenticate itself.
    pub fn primary_aggregator_auth_token(&self) -> &AuthenticationToken {
        self.aggregator_auth_tokens.iter().next_back().unwrap()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub fn check_aggregator_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.aggregator_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Returns the [`AuthenticationToken`] currently used by the collector to authenticate itself
    /// to the aggregators.
    pub fn primary_collector_auth_token(&self) -> &AuthenticationToken {
        // Unwrap safety: self.collector_auth_tokens is never empty
        self.collector_auth_tokens.iter().next_back().unwrap()
    }

    /// Checks if the given collector authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub fn check_collector_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.collector_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Computes the VDAF verify key using the method defined in [draft-wang-ppm-dap-taskprov][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-wang-ppm-dap-taskprov-04.html#name-deriving-the-vdaf-verificat
    pub fn derive_vdaf_verify_key(
        &self,
        task_id: &TaskId,
        vdaf_instance: &VdafInstance,
    ) -> SecretBytes {
        let prk = SALT.extract(self.verify_key_init.as_ref());
        let info = [task_id.as_ref().as_slice()];

        // Unwrap safety: this function only errors if the OKM length is too long
        // (<= 255 * HashLength). It is not expected that a VDAF's verify key length will ever
        // be _that_ long.
        let length = vdaf_instance.verify_key_length();
        let okm = prk.expand(&info, VdafVerifyKeyLength(length)).unwrap();

        let mut vdaf_verify_key = vec![0; length];
        // Same unwrap rationale as above.
        okm.fill(&mut vdaf_verify_key).unwrap();
        SecretBytes::new(vdaf_verify_key)
    }
}

/// Helper type for using `ring::Prk::expand()`.
struct VdafVerifyKeyLength(usize);

impl KeyType for VdafVerifyKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// Newtype for [`task::Task`], which omits certain fields that aren't required for taskprov tasks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task(pub(super) task::Task);

impl Task {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        query_type: QueryType,
        vdaf: VdafInstance,
        role: Role,
        vdaf_verify_keys: Vec<SecretBytes>,
        max_batch_query_count: u64,
        task_expiration: Option<Time>,
        report_expiry_age: Option<Duration>,
        min_batch_size: u64,
        time_precision: Duration,
        tolerable_clock_skew: Duration,
    ) -> Result<Self, Error> {
        let task = Self(task::Task::new_without_validation(
            task_id,
            aggregator_endpoints,
            query_type,
            vdaf,
            role,
            vdaf_verify_keys,
            max_batch_query_count,
            task_expiration,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
        task.validate()?;
        Ok(task)
    }

    pub(super) fn validate(&self) -> Result<(), Error> {
        self.0.validate_common()?;
        if let QueryType::FixedSize {
            batch_time_window_size,
            ..
        } = self.0.query_type()
        {
            if batch_time_window_size.is_some() {
                return Err(Error::InvalidParameter(
                    "batch_time_window_size is not supported for taskprov",
                ));
            }
        }
        Ok(())
    }

    pub fn task(&self) -> &task::Task {
        &self.0
    }
}

impl From<Task> for task::Task {
    fn from(value: Task) -> Self {
        value.0
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use janus_core::{
        hpke::test_util::generate_test_hpke_config_and_private_key, task::AuthenticationToken,
    };
    use janus_messages::{Duration, HpkeConfig, Role};
    use rand::random;
    use url::Url;

    use super::{PeerAggregator, VerifyKeyInit};

    #[derive(Debug, Clone)]
    pub struct PeerAggregatorBuilder(PeerAggregator);

    impl PeerAggregatorBuilder {
        pub fn new() -> Self {
            Self(PeerAggregator::new(
                Url::parse("https://example.com").unwrap(),
                Role::Leader,
                random(),
                generate_test_hpke_config_and_private_key().config().clone(),
                None,
                Duration::from_seconds(1),
                Vec::from([random()]),
                Vec::from([random()]),
            ))
        }

        pub fn with_endpoint(self, endpoint: Url) -> Self {
            Self(PeerAggregator { endpoint, ..self.0 })
        }

        pub fn with_role(self, role: Role) -> Self {
            Self(PeerAggregator { role, ..self.0 })
        }

        pub fn with_verify_key_init(self, verify_key_init: VerifyKeyInit) -> Self {
            Self(PeerAggregator {
                verify_key_init,
                ..self.0
            })
        }

        pub fn with_collector_hpke_config(self, collector_hpke_config: HpkeConfig) -> Self {
            Self(PeerAggregator {
                collector_hpke_config,
                ..self.0
            })
        }

        pub fn with_report_expiry_age(self, report_expiry_age: Option<Duration>) -> Self {
            Self(PeerAggregator {
                report_expiry_age,
                ..self.0
            })
        }

        pub fn with_tolerable_clock_skew(self, tolerable_clock_skew: Duration) -> Self {
            Self(PeerAggregator {
                tolerable_clock_skew,
                ..self.0
            })
        }

        pub fn with_aggregator_auth_tokens(
            self,
            aggregator_auth_tokens: Vec<AuthenticationToken>,
        ) -> Self {
            Self(PeerAggregator {
                aggregator_auth_tokens,
                ..self.0
            })
        }

        pub fn with_collector_auth_tokens(
            self,
            collector_auth_tokens: Vec<AuthenticationToken>,
        ) -> Self {
            Self(PeerAggregator {
                collector_auth_tokens,
                ..self.0
            })
        }

        pub fn build(self) -> PeerAggregator {
            self.0
        }
    }

    impl From<PeerAggregator> for PeerAggregatorBuilder {
        fn from(value: PeerAggregator) -> Self {
            Self(value)
        }
    }

    impl Default for PeerAggregatorBuilder {
        fn default() -> Self {
            Self::new()
        }
    }
}