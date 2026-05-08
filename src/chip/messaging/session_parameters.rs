use crate::{
    tlv_estimate_struct_overhead,
    chip::{
        messaging::reliable_message_protocol_config::ReliableMessageProtocolConfig,
        system::system_clock::Milliseconds,
    },
};
use core::mem::size_of;

#[repr(u32)]
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum Tag {
    KSessionIdleInterval      = 1,
    KSessionActiveInterval    = 2,
    KSessionActiveThreshold   = 3,
    KDataModelRevision        = 4,
    KInteractionModelRevision = 5,
    KSpecificationVersion     = 6,
    KMaxPathsPerInvoke        = 7,
}

#[derive(Clone)]
pub struct SessionParameters {
    m_mrp_config: ReliableMessageProtocolConfig,
    m_data_model_revision: Option<u16>,
    m_interaction_model_revision: Option<u16>,
    m_specification_version: Option<u32>,
    m_max_paths_per_invoke: u16,
}

impl SessionParameters {
    pub const K_SIZE_OF_SESSION_IDLE_INTERVAL: usize = size_of::<u32>();
    pub const K_SIZE_OF_SESSION_ACTIVE_INTERVAL: usize = size_of::<u32>();
    pub const K_SIZE_OF_SESSION_ACTIVE_THRESHOLD: usize = size_of::<u16>();
    pub const K_SIZE_OF_DATA_MODEL_REVISION: usize = size_of::<u16>();
    pub const K_SIZE_OF_INTERACTION_MODEL_REVISION: usize = size_of::<u16>();
    pub const K_SIZE_OF_SPECIFICATION_VISION: usize = size_of::<u32>();
    pub const K_SIZE_OF_MAX_PATHS_PER_INVOKE: usize = size_of::<u16>();
    pub const K_ESTIMATED_TLV_SIZE: usize = tlv_estimate_struct_overhead!(
        Self::K_SIZE_OF_SESSION_IDLE_INTERVAL, Self::K_SIZE_OF_SESSION_ACTIVE_INTERVAL, Self::K_SIZE_OF_SESSION_ACTIVE_THRESHOLD, Self::K_SIZE_OF_DATA_MODEL_REVISION,
        Self::K_SIZE_OF_INTERACTION_MODEL_REVISION, Self::K_SIZE_OF_SPECIFICATION_VISION, Self::K_SIZE_OF_MAX_PATHS_PER_INVOKE);

    pub const fn new() -> Self {
        Self {
            m_mrp_config: ReliableMessageProtocolConfig::new(),
            m_data_model_revision: None,
            m_interaction_model_revision: None,
            m_specification_version: None,
            m_max_paths_per_invoke: 1,
        }
    }

    pub const fn new_with(config: ReliableMessageProtocolConfig) -> Self {
        Self {
            m_mrp_config: config,
            m_data_model_revision: None,
            m_interaction_model_revision: None,
            m_specification_version: None,
            m_max_paths_per_invoke: 1,
        }
    }

    pub fn get_mrp_config(&self) -> &ReliableMessageProtocolConfig {
        &self.m_mrp_config
    }

    pub fn set_mrp_config(&mut self, config: ReliableMessageProtocolConfig) {
        self.m_mrp_config = config;
    }

    pub fn set_mrp_idle_retrans_timeout(&mut self, idle_retrans_timeout: Milliseconds) {
        self.m_mrp_config.m_idle_retrans_timeout = idle_retrans_timeout;
    }

    pub fn set_mrp_active_retrans_timeout(&mut self, active_retrans_timeout: Milliseconds) {
        self.m_mrp_config.m_active_retrans_timeout = active_retrans_timeout;
    }

    pub fn set_mrp_active_threshold_time(&mut self, active_threshold_time: Milliseconds) {
        self.m_mrp_config.m_active_threshold_time = active_threshold_time;
    }

    pub fn get_data_model_revision(&self) -> &Option<u16> {
        &self.m_data_model_revision
    }

    pub fn set_data_model_revision(&mut self, data_model_revision: u16) {
        self.m_data_model_revision = Some(data_model_revision);
    }

    pub fn get_interaction_model_revision(&self) -> &Option<u16> {
        &self.m_interaction_model_revision
    }

    pub fn set_interaction_model_revision(&mut self, interaction_model_revision: u16) {
        self.m_interaction_model_revision = Some(interaction_model_revision);
    }

    pub fn get_specification_version(&self) -> &Option<u32> {
        &self.m_specification_version
    }

    pub fn set_specification_version(&mut self, specification_version: u32) {
        self.m_specification_version = Some(specification_version);
    }

    pub fn get_max_paths_per_invoke(&self) -> u16 {
        self.m_max_paths_per_invoke
    }

    pub fn set_max_paths_per_invoke(&mut self, max_paths_per_invoke: u16) {
        self.m_max_paths_per_invoke = max_paths_per_invoke;
    }
}
