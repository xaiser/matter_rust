#![allow(dead_code)]
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
    chip_core_error,
    chip_sdk_error,
    ChipError,
    ChipErrorResult,
    verify_or_return_error,
    verify_or_return_value,
};

use core::ptr::NonNull;

const K_PERSISTENT_BUFFER_MAX: usize = 128;

pub mod fabric_list_impl {
    use super::*;

    pub struct FabricList {
        pub m_first_entry: u16,
        pub m_entry_count: u16,
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

    impl FabricList {
        pub const fn new() -> Self {
            Self {
                m_first_entry: 0,
                m_entry_count: 0,
            }
        }
    }
}

pub mod linked_data {
    use super::*;

    const K_MIN_LINK_ID: u16 = 1;

    pub struct LinkedData {
        pub id: u16,
        pub index: u16,
        pub next: u16,
        pub prev: u16,
        pub max_id: u16,
        pub first: bool,
    }

    impl LinkedData {
        pub const fn new() -> Self {
            Self {
                id: K_MIN_LINK_ID,
                index: 0,
                next: 0,
                prev: 0,
                max_id: 0,
                first: false,
            }
        }

        pub const fn new_with(id: u16) -> Self {
            Self {
                id,
                index: 0,
                next: 0,
                prev: 0,
                max_id: 0,
                first: false,
            }
        }
    }
}

pub mod fabric_data {
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                    data_model_types::KINVALID_KEYSET_ID,
                },
            },
        },
        chip_error_invalid_fabric_index,
        chip_error_internal,
        chip_error_not_found,
        chip_ok,
    };
    use super::*;

    fn tag_first_group() -> Tag { context_tag(1) }
    fn tag_group_count() -> Tag { context_tag(2) }
    fn tag_first_map() -> Tag { context_tag(3) }
    fn tag_map_count() -> Tag { context_tag(4) }
    fn tag_first_keyset() -> Tag { context_tag(5) }
    fn tag_keyset_count() -> Tag { context_tag(6) }
    fn tag_next() -> Tag { context_tag(7) }

    pub struct FabricData {
        pub fabric_index: FabricIndex,
        pub first_group: GroupId,
        pub group_count: u16,
        pub first_map: u16,
        pub map_count: u16,
        pub first_keyset: KeysetId,
        pub keyset_count: u16,
        pub next: FabricIndex,
    }

    type PersistentFabricData = PersistentData<FabricData, K_PERSISTENT_BUFFER_MAX, NopPersistentStorage>;

    impl FabricData {
        pub const fn new() -> Self {
            Self {
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                first_group: KUNDEFINED_GROUP_ID,
                group_count: 0,
                first_map: 0,
                map_count: 0,
                first_keyset: KINVALID_KEYSET_ID,
                keyset_count: 0,
                next: KUNDEFINED_FABRIC_INDEX,
            }
        }

        pub const fn new_with(fabric_index: FabricIndex) -> Self {
            Self {
                fabric_index,
                first_group: KUNDEFINED_GROUP_ID,
                group_count: 0,
                first_map: 0,
                map_count: 0,
                first_keyset: KINVALID_KEYSET_ID,
                keyset_count: 0,
                next: KUNDEFINED_FABRIC_INDEX,
            }
        }

        pub fn register<Storage: PersistentStorageDelegate>(&mut self, storage: NonNull<Storage>) -> ChipErrorResult {
            let storage_ptr = storage.as_ptr();

            let mut fabric_list = FabirList::new(fabric_list_impl::FabricList::new(), None);
            let result = fabric_list.load_from(storage_ptr);
            if result.is_err_and(|e| e == chip_error_not_found!()) {
                {
                    // New fabric list
                    let list = fabric_list.as_mut();
                    list.set_first_entry(self.fabric_index as u16);
                    list.set_entry_count(1);
                }
                return fabric_list.save_to(storage_ptr);
            }

            result?;

            // Existing fabric list, search for existing entry
            let entry_count = fabric_list.as_ref().entry_count();
            let mut fabric = PersistentFabricData::new(Self::new_with(fabric_list.as_ref().first_entry() as FabricIndex), None);
            for _i in 0..entry_count {
                match fabric.load_from(storage_ptr) {
                    Ok(_) => {
                        if fabric.as_ref().fabric_index == self.fabric_index {
                            // Fabric already registered
                            return chip_ok!();
                        }
                        fabric.as_mut().fabric_index = fabric.as_ref().next;
                    },
                    Err(_) => {
                        break;
                    },
                }
            }

            // Add this fabric to the fabric list
            self.next = fabric_list.as_ref().first_entry() as FabricIndex;
            fabric_list.as_mut().set_first_entry(self.fabric_index.into());
            fabric_list.as_mut().set_entry_count(entry_count + 1);

            fabric_list.save_to(storage_ptr)
        }
    }

    impl DataAccessor for FabricData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            verify_or_return_error!(KUNDEFINED_FABRIC_INDEX != self.fabric_index, Err(chip_error_invalid_fabric_index!()));
            Ok(DefaultStorageKeyAllocator::fabric_groups(self.fabric_index))
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_u16(tag_first_group(), self.first_group)?;
            writer.put_u16(tag_group_count(), self.group_count)?;
            writer.put_u16(tag_first_map(), self.first_map)?;
            writer.put_u16(tag_map_count(), self.map_count)?;
            writer.put_u16(tag_first_keyset(), self.first_keyset)?;
            writer.put_u16(tag_keyset_count(), self.keyset_count)?;
            writer.put_u16(tag_next(), self.next as u16)?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;

            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            reader.next_tag(tag_first_group())?;
            self.first_group = reader.get_u16()?;

            reader.next_tag(tag_group_count())?;
            self.group_count = reader.get_u16()?;

            reader.next_tag(tag_first_map())?;
            self.first_map = reader.get_u16()?;

            reader.next_tag(tag_map_count())?;
            self.map_count = reader.get_u16()?;

            reader.next_tag(tag_first_keyset())?;
            self.first_keyset = reader.get_u16()?;

            reader.next_tag(tag_keyset_count())?;
            self.keyset_count = reader.get_u16()?;

            reader.next_tag(tag_next())?;
            self.next = reader.get_u16()? as FabricIndex;

            reader.exit_container(container)
        }

        fn clear(&mut self) {
            self.first_group = KUNDEFINED_GROUP_ID;
            self.group_count = 0;
            self.first_keyset = KINVALID_KEYSET_ID;
            self.keyset_count = 0;
            self.next = KUNDEFINED_FABRIC_INDEX;
        }
    }
} 

type FabirList = PersistentData<fabric_list_impl::FabricList, { fabric_list::K_PERSISTENT_FABRIC_BUFFER_MAX }, NopPersistentStorage>;
//type LinkedData = PersistentData<linked_data::LinkedData, K_PERSISTENT_BUFFER_MAX, NopPersistentStorage>;

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
