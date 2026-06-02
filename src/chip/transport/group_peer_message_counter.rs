use crate::chip::{
    chip_lib::{
        core::{
            chip_persistent_storage_delegate::PersistentStorageDelegate,
            node_id::KUNDEFINED_NODE_ID,
            chip_config::{CHIP_CONFIG_MAX_GROUP_DATA_PEERS, CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS, CHIP_CONFIG_MAX_FABRICS},
            data_model_types::{
                FabricIndex, KUNDEFINED_FABRIC_INDEX,
            },
        },
    },
    transport::{
        peer_message_counter::PeerMessageCounter,
    },
    NodeId,
};

use core::ptr::NonNull;

pub struct GroupSender
{
    pub m_node_id: NodeId,
    pub msg_counter: PeerMessageCounter,
}

impl GroupSender {
    pub const fn new() -> Self {
        Self {
            m_node_id: KUNDEFINED_NODE_ID,
            msg_counter: PeerMessageCounter::new(),
        }
    }
}

pub struct GroupFabric {
    pub m_fabric_index: FabricIndex,
    pub m_control_peer_count: u8,
    pub m_data_peer_count: u8,
    pub m_data_group_senders: [GroupSender; CHIP_CONFIG_MAX_GROUP_DATA_PEERS],
    pub m_control_group_senders: [GroupSender; CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS],
}

impl GroupFabric {
    pub const fn new() -> Self {
        Self {
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_control_peer_count: 0,
            m_data_peer_count: 0,
            m_data_group_senders: [ const { GroupSender::new() }; CHIP_CONFIG_MAX_GROUP_DATA_PEERS],
            m_control_group_senders: [ const { GroupSender::new() }; CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS],
        }
    }
}

pub struct GroupPeerTable {
    m_group_fabrics: [GroupFabric; CHIP_CONFIG_MAX_FABRICS],
}

impl GroupPeerTable {
    pub const fn new() -> Self {
        Self {
            m_group_fabrics: [ const { GroupFabric::new() }; CHIP_CONFIG_MAX_FABRICS],
        }
    }
}

pub struct GroupOutgoingCounters<PSD>
where
    PSD: PersistentStorageDelegate,
{
    m_group_data_counter: u32,
    m_group_control_counter: u32,
    m_storage: Option<NonNull<PSD>>,
}

impl<PSD> GroupOutgoingCounters<PSD>
where
    PSD: PersistentStorageDelegate
{
    pub const K_MESSAGE_COUNTER_RANDOM_INIT_MASK: u32 = 0x0FFFFFFF;

    pub const fn new() -> Self {
        Self {
            m_group_data_counter: 0,
            m_group_control_counter: 0,
            m_storage: None,
        }
    }

    pub fn new_with(storage_delegate: NonNull<PSD>) -> Self {
        let mut counters = Self::new();
        counters.m_storage = Some(storage_delegate);

        counters.init();

        counters
    }

    pub fn init(&mut self) {
    }
}

