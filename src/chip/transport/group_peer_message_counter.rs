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
    chip_error_too_many_peer_nodes,
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

    pub fn find_or_add_peer(&mut self, fabric_index: FabricIndex, node_id: NodeId, is_control: bool) -> Result<&mut PeerMessageCounter, ChipError> {
        if fabric_index == KUNDEFINED_FABRIC_INDEX || node_id == KUNDEFINED_NODE_ID {
            return Err(chip_error_invalid_argument!());
        }

        for group_fabric in &mut self.m_group_fabrics {
            if group_fabric.m_fabric_index == KUNDEFINED_FABRIC_INDEX {
                // Already iterated through all known fabricIndex
                // Add the new peer to save some processing time
                group_fabric.m_fabric_index = fabric_index;
                if is_control {
                    group_fabric.m_control_group_senders[0].m_node_id = node_id;
                    group_fabric.m_control_peer_count += 1;
                    return Ok(&mut group_fabric.m_control_group_senders[0].msg_counter);
                } else {
                    group_fabric.m_data_group_senders[0].m_node_id = node_id;
                    group_fabric.m_data_peer_count += 1;
                    return Ok(&mut group_fabric.m_data_group_senders[0].msg_counter);
                }
            }

            if fabric_index == group_fabric.m_fabric_index {
                if is_control {
                    for node in &mut group_fabric.m_control_group_senders {
                        if node.m_node_id == KUNDEFINED_NODE_ID {
                            // Already iterated through all known NodeIds
                            // Add the new peer to save some processing time
                            node.m_node_id = node_id;
                            group_fabric.m_control_peer_count += 1;
                            return Ok(&mut node.msg_counter);
                        }

                        if node.m_node_id == node_id {
                            return Ok(&mut node.msg_counter);
                        }
                    }
                } else {
                    for node in &mut group_fabric.m_data_group_senders {
                        if node.m_node_id == KUNDEFINED_NODE_ID {
                            // Already iterated through all known NodeIds
                            // Add the new peer to save some processing time
                            node.m_node_id = node_id;
                            group_fabric.m_data_peer_count += 1;
                            return Ok(&mut node.msg_counter);
                        }

                        if node.m_node_id == node_id {
                            return Ok(&mut node.msg_counter);
                        }
                    }
                }

                return Err(chip_error_too_many_peer_nodes!());
            }
        }

        Err(chip_error_too_many_peer_nodes!())
    }

    fn remove_specific_peer(list: &mut [GroupSender], node_id: NodeId) -> bool {
        let mut removed = false;

        for sender in list.iter_mut() {
            if sender.m_node_id == node_id {
                sender.m_node_id = KUNDEFINED_NODE_ID;
                sender.msg_counter.reset();
                removed = true;
                break;
            }
        }

        if removed {
            Self::compact_peers(list);
        }

        removed
    }

    fn compact_peers(list: &mut [GroupSender]) {
        if list.is_empty() {
            return;
        }

        let size = list.len();
        for peer_index in 0..size {
            if list[peer_index].m_node_id != KUNDEFINED_NODE_ID {
                continue;
            }
            for i in ((peer_index+1)..=(size-1)).rev() {
                if list[i].m_node_id != KUNDEFINED_NODE_ID {
                    list.swap(peer_index, i);
                    break;
                }
            }
        }
    }

    fn remove_and_compact_fabric(table: &mut [GroupFabric], table_index: usize) {
        if let Some(fabric) = table.get_mut(table_index) {
            *fabric = GroupFabric::new();
        } else {
            return;
        }

        // To maintain logic integrity Fabric array cannot have empty slot in between data
        // Find the last non empty element
        for i in ((table_index + 1)..CHIP_CONFIG_MAX_FABRICS).rev() {
            if table[i].m_fabric_index != KUNDEFINED_FABRIC_INDEX {
                table.swap(i, table_index);
                break;
            }
        }
    }

    fn get_counter(&self, index: usize, is_control: bool) -> Option<u8> {
        if is_control {
            Some(self.m_group_fabrics.get(index)?.m_control_peer_count)
        } else {
            Some(self.m_group_fabrics.get(index)?.m_data_peer_count)
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
        let (key, value);
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

        let mut temp = [0u8; SIZE];

        match storage.sync_get_key_value(key.key_name_str(), &mut temp) {
            Ok(read_size) => {
                if read_size <= SIZE {
                    let mut temp = u32::from_le_bytes(temp[..read_size].try_into().map_err(|_| chip_error_internal!())?);
                    if temp == value {
                        temp = value + Self::GROUP_MSG_COUNTER_MIN_INCREMENT;
                        return storage.sync_set_key_value(key.key_name_str(), temp.to_le_bytes().as_slice());
                    }

                    return chip_ok!();
                } else {
                    return Err(chip_error_internal!());
                }
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    mod group_outgoing_counters {
        use super::super::*;
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

        #[test]
        fn increase_correctly() {
            let mut pa = TestPersistentStorage::default();
            let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

            assert!(gc.init().is_ok());

            let init_value = gc.get_counter(true);

            assert!(gc.increment_counter(true).is_ok());

            assert_eq!(init_value + 1, gc.get_counter(true));
        }

        #[test]
        fn increase_no_storage() {
            let mut pa = TestPersistentStorage::default();
            let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

            assert!(gc.increment_counter(true).is_err());
        }

        #[test]
        fn increase_corrupt_key() {
            let mut pa = TestPersistentStorage::default();
            let mut gc = GroupOutgoingCounters::new_with(NonNull::new(core::ptr::addr_of_mut!(pa)));

            assert!(gc.init().is_ok());

            // inject posion key to corrupt the storage
            pa.add_posion_key(
                DefaultStorageKeyAllocator::group_control_counter().key_name_str(),
            );

            assert!(gc.increment_counter(true).is_err());
        }
    } // end of mod group_outgoing_counters

    mod group_peer_table {
        use super::super::*;
        use crate::{
            chip::{
            },
        };

        #[test]
        fn add_control_peer_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, true).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, true).is_ok());
            assert!(table.get_counter(0, true).is_some_and(|c| c == 1));
        }

        #[test]
        fn find_with_invalid_fabric_index() {
            let mut table = GroupPeerTable::new();

            assert!(!table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX, KUNDEFINED_NODE_ID + 1, true).is_ok());
        }

        #[test]
        fn find_with_invalid_node_id() {
            let mut table = GroupPeerTable::new();

            assert!(!table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID, true).is_ok());
        }

        #[test]
        fn add_control_peer_with_same_fabric_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, true).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, true).is_ok());
            assert!(table.get_counter(0, true).is_some_and(|c| c == 1));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 2, true).is_ok());
            assert!(table.get_counter(0, true).is_some_and(|c| c == 2));
        }

        #[test]
        fn find_control_peer_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, true).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, true).is_ok());
            assert!(table.get_counter(0, true).is_some_and(|c| c == 1));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, true).is_ok());
            assert!(table.get_counter(0, true).is_some_and(|c| c == 1));
        }

        #[test]
        fn too_many_control_peer() {
            let mut table = GroupPeerTable::new();

            for i in 0..CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS {
                assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1 + i as u64, true).is_ok());
            }
            assert!(!table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1 + CHIP_CONFIG_MAX_GROUP_CONTROL_PEERS  as u64 + 1, true).is_ok());
        }

        #[test]
        fn add_data_peer_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, false).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, false).is_ok());
            assert!(table.get_counter(0, false).is_some_and(|c| c == 1));
        }

        #[test]
        fn add_data_peer_with_same_fabric_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, false).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, false).is_ok());
            assert!(table.get_counter(0, false).is_some_and(|c| c == 1));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 2, false).is_ok());
            assert!(table.get_counter(0, false).is_some_and(|c| c == 2));
        }

        #[test]
        fn find_data_peer_successfully() {
            let mut table = GroupPeerTable::new();

            assert!(table.get_counter(0, false).is_some_and(|c| c == 0));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, false).is_ok());
            assert!(table.get_counter(0, false).is_some_and(|c| c == 1));
            assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1, false).is_ok());
            assert!(table.get_counter(0, false).is_some_and(|c| c == 1));
        }

        #[test]
        fn too_many_data_peer() {
            let mut table = GroupPeerTable::new();

            for i in 0..CHIP_CONFIG_MAX_GROUP_DATA_PEERS {
                assert!(table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1 + i as u64, false).is_ok());
            }
            assert!(!table.find_or_add_peer(KUNDEFINED_FABRIC_INDEX + 1, KUNDEFINED_NODE_ID + 1 + CHIP_CONFIG_MAX_GROUP_DATA_PEERS  as u64 + 1, false).is_ok());
        }

        #[test]
        fn compact_list() {
            const SIZE: usize = 3;
            let mut list = [const { GroupSender::new() }; SIZE];
            list[0].m_node_id = 1;
            list[2].m_node_id = 2;
            
            GroupPeerTable::compact_peers(&mut list);

            assert_eq!(list[2].m_node_id, KUNDEFINED_NODE_ID);
        }

        #[test]
        fn remove_specific_peer() {
            const SIZE: usize = 5;
            let mut list = [const { GroupSender::new() }; SIZE];
            list[0].m_node_id = 1;
            list[2].m_node_id = 2;
            list[4].m_node_id = 3;

            assert_eq!(3,
                list.iter().filter(
                    |s| s.m_node_id != KUNDEFINED_NODE_ID).count());
            
            GroupPeerTable::remove_specific_peer(&mut list, 2);

            for i in 0..2 {
                assert_ne!(2, list[i].m_node_id);
            }

            for i in 2..5 {
                assert_eq!(KUNDEFINED_NODE_ID, list[i].m_node_id);
            }
        }

        #[test]
        fn remove_specific_fabric() {
            const SIZE: usize = CHIP_CONFIG_MAX_FABRICS;
            let mut list = [const { GroupFabric::new() }; SIZE];
            list[0].m_fabric_index = 1;
            list[1].m_fabric_index = 2;
            list[2].m_fabric_index = 3;
            
            GroupPeerTable::remove_and_compact_fabric(&mut list, 1);

            assert_eq!(1, list[0].m_fabric_index);
            assert_eq!(3, list[1].m_fabric_index);

            for i in 2..CHIP_CONFIG_MAX_FABRICS {
                assert_eq!(KUNDEFINED_FABRIC_INDEX, list[i].m_fabric_index);
            }
        }

        #[test]
        fn remove_specific_fabric_out_of_boundary() {
            const SIZE: usize = CHIP_CONFIG_MAX_FABRICS;
            let mut list = [const { GroupFabric::new() }; SIZE];
            list[0].m_fabric_index = 1;
            list[1].m_fabric_index = 2;
            list[2].m_fabric_index = 3;
            
            GroupPeerTable::remove_and_compact_fabric(&mut list, CHIP_CONFIG_MAX_FABRICS + 1);

            assert_eq!(1, list[0].m_fabric_index);
            assert_eq!(2, list[1].m_fabric_index);
            assert_eq!(3, list[2].m_fabric_index);
        }
    } // end of mod group_peer_rable
}// end of tess

