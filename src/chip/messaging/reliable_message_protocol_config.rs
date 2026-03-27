use core::time::Duration;

pub const CHIP_CONFIG_MRP_LOCAL_ACTIVE_RETRY_INTERVAL: Duration = Duration::from_millis(2000);
pub const CHIP_CONFIG_MRP_LOCAL_IDLE_RETRY_INTERVAL: Duration = Duration::from_millis(2000);
pub const CHIP_CONFIG_RMP_DEFAULT_ACK_TIMEOUT: Duration = Duration::from_millis(200);
pub const CHIP_CONFIG_RESOLVE_PEER_ON_FIRST_TRANSMIT_FAILURE: u32 = 0;
pub const CHIP_CONFIG_RMP_RETRANS_TABLE_SIZE: usize = crate::chip::chip_lib::core::chip_config::CHIP_CONFIG_MAX_EXCHANGE_CONTEXTS;
pub const CHIP_CONFIG_RMP_DEFAULT_MAX_RETRANS: usize = 4;
pub const CHIP_CONFIG_MRP_RETRY_INTERVAL_SECOND_BOOST: Duration = Duration::from_millis(1500);

pub const K_DEFAULT_ACTIVE_TIME: Duration = Duration::from_millis(4000);

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ReliableMessageProtocolConfig {
    pub m_idle_retrans_timeout: Duration,
    pub m_active_retrans_timeout: Duration,
    pub m_active_threshold_time: Duration,
}

impl Default for ReliableMessageProtocolConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ReliableMessageProtocolConfig {
    pub const fn new() -> Self {
        Self {
            m_idle_retrans_timeout: Duration::from_millis(500),
            m_active_retrans_timeout: Duration::from_millis(300),
            m_active_threshold_time: K_DEFAULT_ACTIVE_TIME,
        }
    }

    pub const fn new_with_all(idle_interval: Duration, active_interval: Duration, active_threshold: Duration) -> ReliableMessageProtocolConfig {
        ReliableMessageProtocolConfig {
            m_idle_retrans_timeout: idle_interval,
            m_active_retrans_timeout: active_interval,
            m_active_threshold_time: active_threshold,
        }
    }

    pub const fn new_with(idle_interval: Duration, active_interval: Duration) -> ReliableMessageProtocolConfig {
        ReliableMessageProtocolConfig::new_with_all(idle_interval, active_interval, K_DEFAULT_ACTIVE_TIME)
    }

    pub fn get_local_mrp_config() -> Option<ReliableMessageProtocolConfig> {
        let config = ReliableMessageProtocolConfig::new_with(CHIP_CONFIG_MRP_LOCAL_IDLE_RETRY_INTERVAL, CHIP_CONFIG_MRP_LOCAL_ACTIVE_RETRY_INTERVAL);

        if config == ReliableMessageProtocolConfig::new() {
            Some(config);
        }

        None
    }

    pub fn get_retransmission_timeout
}
