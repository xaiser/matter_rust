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
        support::{
            default_storage_key_allocator::DefaultStorageKeyAllocator,
        },
    },
    transport::{
        peer_message_counter::PeerMessageCounter,
    },
    NodeId,
};

use crate::{
    chip_core_error,
    chip_ok,
    chip_sdk_error,
    chip_error_invalid_argument,
    chip_error_internal,
    chip_error_persisted_storage_value_not_found,
    //verify_or_return_error,
    //verify_or_return_value,
    ChipError,
    ChipErrorResult,
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
    pub const GROUP_MSG_COUNTER_MIN_INCREMENT: u32 = 1000;

    pub const fn new() -> Self {
        Self {
            m_group_data_counter: 0,
            m_group_control_counter: 0,
            m_storage: None,
        }
    }

    pub fn new_with(storage_delegate: Option<NonNull<PSD>>) -> Self {
        let mut counters = Self::new();
        counters.m_storage = storage_delegate;

        //counters.init();

        counters
    }

    pub fn init(&mut self) -> ChipErrorResult {
        let storage;
        const SIZE: usize = core::mem::size_of::<u32>();
        let mut temp = [0u8; SIZE];
        unsafe {
            storage = self.m_storage.as_mut().ok_or(chip_error_invalid_argument!())?.as_mut();
        }
        match storage.sync_get_key_value(DefaultStorageKeyAllocator::group_control_counter().key_name_str(), &mut temp) {
            Ok(read_size) => {
                if read_size <= SIZE {
                    self.m_group_control_counter = u32::from_le_bytes(temp[..read_size].try_into().map_err(|_| chip_error_internal!())?);
                } else {
                    return Err(chip_error_internal!());
                }
            },
            Err(e) => {
                if e == chip_error_persisted_storage_value_not_found!() {
                    // First time retrieving the counter
                    self.m_group_control_counter = (crate::chip::crypto::get_rand_u32() & Self::K_MESSAGE_COUNTER_RANDOM_INIT_MASK) + 1;
                } else {
                    return Err(e);
                }
            }
        }
        match storage.sync_get_key_value(DefaultStorageKeyAllocator::group_data_counter().key_name_str(), &mut temp) {
            Ok(read_size) => {
                if read_size <= SIZE {
                    self.m_group_data_counter = u32::from_le_bytes(temp[..read_size].try_into().map_err(|_| chip_error_internal!())?);
                } else {
                    return Err(chip_error_internal!());
                }
            },
            Err(e) => {
                if e == chip_error_persisted_storage_value_not_found!() {
                    // First time retrieving the counter
                    self.m_group_data_counter = (crate::chip::crypto::get_rand_u32() & Self::K_MESSAGE_COUNTER_RANDOM_INIT_MASK) + 1;
                } else {
                    return Err(e);
                }
            }
        }

        let temp = self.m_group_control_counter + Self::GROUP_MSG_COUNTER_MIN_INCREMENT;
        storage.sync_set_key_value(DefaultStorageKeyAllocator::group_control_counter().key_name_str(), temp.to_le_bytes().as_slice())?;

        let temp = self.m_group_data_counter + Self::GROUP_MSG_COUNTER_MIN_INCREMENT;
        storage.sync_set_key_value(DefaultStorageKeyAllocator::group_data_counter().key_name_str(), temp.to_le_bytes().as_slice())
    }

    pub fn get_counter(&self, is_control: bool) -> u32 {
        if is_control {
            self.m_group_control_counter
        } else {
            self.m_group_data_counter
        }
    }

    pub fn increment_counter(&mut self, is_control: bool) -> ChipErrorResult {
        let key, value;
        const SIZE: usize = core::mem::size_of::<u32>();

        if is_control {
            self.m_group_control_counter += 1;
            key = DefaultStorageKeyAllocator::group_control_counter();
            value = self.m_group_control_counter;
        } else {
            self.m_group_data_counter += 1;
            key = DefaultStorageKeyAllocator::group_data_counter();
            value = self.m_group_data_counter;
        }
        let storage;
        unsafe {
            storage = self.m_storage.as_mut().ok_or(chip_error_persisted_storage_value_not_found!())?.as_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                support::test_persistent_storage::TestPersistentStorage,
            },
        },
    };

    #[test]
    fn init_successfully() {
        let mut pa = TestPersistentStorage::default();
        let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

        assert!(gc.init().is_ok());
    }

    #[test]
    fn init_failed_on_control_counter() {
        let mut pa = TestPersistentStorage::default();
        let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

        // inject posion key to corrupt the storage
        pa.add_posion_key(
            DefaultStorageKeyAllocator::group_control_counter().key_name_str(),
        );

        assert!(gc.init().is_err());
    }

    #[test]
    fn init_failed_on_data_counter() {
        let mut pa = TestPersistentStorage::default();
        let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

        // inject posion key to corrupt the storage
        pa.add_posion_key(
            DefaultStorageKeyAllocator::group_data_counter().key_name_str(),
        );

        assert!(gc.init().is_err());
    }
}// end of tess

