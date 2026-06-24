use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::{KeysetId, EndpointId, KUNDEFINED_FABRIC_INDEX},
                group_id::KUNDEFINED_GROUP_ID,
                tlv_writer::TlvWriter,
                tlv_reader::TlvReader,
                chip_persistent_storage_delegate::NopPersistentStorage,
            },
            support::{
                default_string::DefaultString,
                persistent_data::{PersistentData, DataAccessor},
                common_persistent_data::{stored_data_list::StoredDataList, fabric_list},
                default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
            },
        },
        credentials::group_data_provider::{GroupDataProvider, GroupListener, GroupInfo},
        crypto::{
            self, session_keystore::SessionKeystore,
        },
        GroupId, FabricIndex,
    },
    ChipError,
    ChipErrorResult,
    verify_or_return_error,
    verify_or_return_value,
};

use core::ptr::NonNull;

pub mod fabric_list_impl {
    use super::*;

    pub struct FabricList {
        m_first_entry: u16,
        m_entry_count: u16,
    }

    impl StoredDataList for FabricList {
        fn first_entry(&self) -> u16 {
            self.m_first_entry
        }
        fn entry_count(&self) -> u16 {
            self.m_entry_count
        }
        fn set_first_entry(&mut self, first_entry: u16) {
            self.m_first_entry = first_entry;
        }
        fn set_entry_count(&mut self, entry_count: u16) {
            self.m_entry_count = entry_count;
        }
    }

    impl fabric_list::FabricList for FabricList {}

    impl DataAccessor for FabricList {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            Ok(DefaultStorageKeyAllocator::group_fabric_list())
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            <Self as StoredDataList>::serialize(self, writer)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            <Self as StoredDataList>::deserialize(self, reader)
        }

        fn clear(&mut self) {
            <Self as fabric_list::FabricList>::clear(self)
        }
    }
}

pub type FabirList = PersistentData<fabric_list_impl::FabricList, { fabric_list::K_PERSISTENT_FABRIC_BUFFER_MAX }, NopPersistentStorage>;

struct GroupInfoIteratorImpl<Provider: GroupDataProvider>
{
    m_provider: Option<NonNull<Provider>>,
    m_fabric: FabricIndex,
    m_next_id: u16,
    m_count: usize,
    m_total: usize,
}

impl<Provider: GroupDataProvider> GroupInfoIteratorImpl<Provider> {
    pub const fn new() -> Self {
        Self {
            m_provider: None,
            m_fabric: KUNDEFINED_FABRIC_INDEX,
            m_next_id: 0,
            m_count: 0,
            m_total: 0,
        }
    }

    /*
    pub fn new_with(provider: Option<NonNull<Provider>>, fabric_index) -> Self {
    }
    */
}

impl<Provider: GroupDataProvider> Iterator for GroupInfoIteratorImpl<Provider> {
    type Item = GroupInfo;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}


pub struct GroupDataProviderImpl<PSD, SKS, LIS>
where
    PSD: PersistentStorageDelegate,
    SKS: SessionKeystore,
    LIS: GroupListener,
{
    m_storage: Option<NonNull<PSD>>,
    m_sesion_keystore: Option<NonNull<SKS>>,
    m_max_groups_per_fabric: u16,
    m_max_group_keys_per_fabric: u16,
    m_listener: Option<NonNull<LIS>>,
}
