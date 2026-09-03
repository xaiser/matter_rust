use crate::chip::{
    /*
    chip_lib::{
        core::{
            chip_persistent_storage_delegate::PersistentStorageDelegate,
            node_id::KUNDEFINED_NODE_ID,
            chip_config::{CHIP_CONFIG_MAX_GROUP_DATA_PEERS, CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS, CHIP_CONFIG_MAX_FABRICS},
            data_model_types::{
                FabricIndex, KUNDEFINED_FABRIC_INDEX,
            },
        },
        support::{
            default_storage_key_allocator::DefaultStorageKeyAllocator,
        },
    },
    */
    transport::{
        peer_message_counter::PeerMessageCounter,
        message_counter::MessageCounter,
    },
};

pub struct SessionMessageCounter {
    m_local_message_counter: MessageCounter,
    m_peer_message_counter: PeerMessageCounter,
}

impl SessionMessageCounter {
    pub const fn new() -> Self {
        Self {
            m_local_message_counter: MessageCounter::new_session(),
            m_peer_message_counter: PeerMessageCounter::new(),
        }
    }

    pub fn init(&mut self) {
        self.m_local_message_counter.init();
    }

    pub fn get_local_message_counter(&mut self) -> &mut MessageCounter {
        &mut self.m_local_message_counter
    }

    pub fn get_peer_message_counter(&mut self) -> &mut PeerMessageCounter {
        &mut self.m_peer_message_counter
    }
}
