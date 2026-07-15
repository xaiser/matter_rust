#![allow(dead_code)]
use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::{KeysetId, EndpointId, KUNDEFINED_FABRIC_INDEX, KINVALID_ENDPOINT_ID},
                group_id::KUNDEFINED_GROUP_ID,
                tlv_writer::TlvWriter,
                tlv_reader::TlvReader,
                chip_persistent_storage_delegate::NopPersistentStorage,
            },
            support::{
                pool::{BitMapObjectPool, ObjectPool},
                default_string::DefaultString,
                persistent_data::{PersistentData, DataAccessor},
                common_persistent_data::{stored_data_list::StoredDataList, fabric_list},
                default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
            },
        },
        credentials::group_data_provider::{GroupDataProvider, GroupListener, GroupInfo, GroupKey, KeySet, GroupEndpoint, GroupSession},
        crypto::{
            self, session_keystore::SessionKeystore, Aes128KeyHandle, Symmetric128BitsKeyByteArray, SymmetricKeyContext,
        },
        GroupId, FabricIndex,
    },
    chip_core_error,
    chip_sdk_error,
    ChipError,
    ChipErrorResult,
    verify_or_return_error,
    verify_or_return_value,
    verify_or_die,
    chip_error_not_implemented,
    chip_error_incorrect_state,
    chip_error_internal,
    chip_error_invalid_fabric_index,
    chip_error_invalid_argument,
    chip_error_key_not_found,
    chip_error_not_found,
    chip_error_duplicate_key_id,
    chip_error_invalid_list_length,
    chip_ok,
};

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::{
    str::{self, FromStr},
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

type FabricList = PersistentData<fabric_list_impl::FabricList, { fabric_list::K_PERSISTENT_FABRIC_BUFFER_MAX }, NopPersistentStorage>;

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
        chip_error_not_found,
        chip_ok,
    };
    /*
    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use core::{
        str::{self, FromStr},
    };
    */
    use super::*;

    const fn tag_first_group() -> Tag { context_tag(1) }
    const fn tag_group_count() -> Tag { context_tag(2) }
    const fn tag_first_map() -> Tag { context_tag(3) }
    const fn tag_map_count() -> Tag { context_tag(4) }
    const fn tag_first_keyset() -> Tag { context_tag(5) }
    const fn tag_keyset_count() -> Tag { context_tag(6) }
    const fn tag_next() -> Tag { context_tag(7) }

    #[derive(Clone)]
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

    pub type PersistentFabricData<S: PersistentStorageDelegate> = PersistentData<FabricData, K_PERSISTENT_BUFFER_MAX, S>;

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

            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            let result = FabricList::load_from(&mut fabric_list, storage_ptr);
            if result.is_err_and(|e| e == chip_error_not_found!()) {
                {
                    // New fabric list
                    let list = fabric_list.as_mut();
                    list.set_first_entry(self.fabric_index as u16);
                    list.set_entry_count(1);
                }
                return FabricList::save_to(&mut fabric_list, storage_ptr);
            }

            result?;

            // Existing fabric list, search for existing entry
            let entry_count = fabric_list.entry_count();
            let mut fabric = PersistentFabricData::<Storage>::new(Self::new_with(fabric_list.first_entry() as FabricIndex), None);
            for _i in 0..entry_count {
                match PersistentFabricData::<Storage>::load_from(&mut fabric, storage_ptr) {
                    Ok(_) => {
                        if fabric.fabric_index == self.fabric_index {
                            // Fabric already registered
                            return chip_ok!();
                        }
                        fabric.fabric_index = fabric.next;
                    },
                    Err(_) => {
                        break;
                    },
                }
            }

            // Add this fabric to the fabric list
            self.next = fabric_list.first_entry() as FabricIndex;
            fabric_list.set_first_entry(self.fabric_index.into());
            fabric_list.set_entry_count(entry_count + 1);

            //fabric_list.save_to(storage_ptr)
            FabricList::save_to(&mut fabric_list, storage_ptr)
        }

        pub fn unregister<Storage: PersistentStorageDelegate>(&mut self, storage: NonNull<Storage>) -> ChipErrorResult {
            let storage_ptr = storage.as_ptr();

            //let mut fabric_list = FabirList::new(fabric_list_impl::FabricList::new(), None);
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            //let result = fabric_list.load_from(storage_ptr);
            let result = FabricList::load_from(&mut fabric_list, storage_ptr);
            if result.is_err_and(|e| e != chip_error_not_found!()) {
                return result;
            }
            // Existing fabric list, search for existing entry
            let entry_count = fabric_list.entry_count();
            let mut fabric = PersistentFabricData::<Storage>::new(Self::new_with(fabric_list.first_entry() as FabricIndex), None);
            let mut prev = PersistentFabricData::<Storage>::new(Self::new(), None);

            for i in 0..entry_count {
                //match fabric.load_from(storage_ptr) {
                match PersistentFabricData::<Storage>::load_from(&mut fabric, storage_ptr) {
                    Ok(_) => {
                        if fabric.fabric_index == self.fabric_index {
                            if i == 0 {
                                // Remove first fabric
                                fabric_list.set_first_entry(self.next.into());
                            } else {
                                // Remove intermediate fabric
                                prev.next = self.next;
                                //prev.save_to(storage_ptr)?;
                                PersistentFabricData::<Storage>::save_to(&mut prev, storage_ptr)?;
                            }
                            // entry_count must > 0 here otherwise we won't get in this loop
                            fabric_list.set_entry_count(entry_count - 1);
                            //return fabric_list.save_to(storage_ptr);
                            return FabricList::save_to(&mut fabric_list, storage_ptr);
                        }

                        prev = fabric.clone();
                        fabric.fabric_index = fabric.next;
                    },
                    Err(_) => {
                        break;
                    }
                }
            }

            // Fabric not in the list
            Err(chip_error_not_found!())
        }

        pub fn validate<Storage: PersistentStorageDelegate>(&self, storage: NonNull<Storage>) -> ChipErrorResult {
            let storage_ptr = storage.as_ptr();
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            FabricList::load_from(&mut fabric_list, storage_ptr)?;

            let entry_count = fabric_list.entry_count();
            let mut fabric = PersistentFabricData::<Storage>::new(Self::new_with(fabric_list.first_entry() as FabricIndex), None);
            for _i in 0..entry_count {
                PersistentFabricData::<Storage>::load_from(&mut fabric, storage_ptr)?;
                if fabric.fabric_index == self.fabric_index {
                    return chip_ok!();
                }
                fabric.fabric_index = self.fabric_index;
            }

            // Fabric not in the list
            Err(chip_error_not_found!())
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

    pub const fn new<Storage: PersistentStorageDelegate>() -> PersistentFabricData<Storage> {
        PersistentFabricData::<Storage>::new(FabricData::new(), None)
    }

    pub const fn new_with<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex) -> PersistentFabricData<Storage> {
        PersistentFabricData::<Storage>::new(FabricData::new_with(fabric_index), None)
    }

    pub fn save<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(data: &mut PersistentFabricData<S>, storage: NonNull<PSD>) -> ChipErrorResult {
        data.register(storage)?;

        PersistentFabricData::<S>::save_to(data, storage.as_ptr())
    }

    pub fn delete<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(data: &mut PersistentFabricData<S>, storage: NonNull<PSD>) -> ChipErrorResult {
        data.unregister(storage)?;

        PersistentFabricData::<S>::delete_from(data, storage.as_ptr())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    support::{
                        test_persistent_storage::TestPersistentStorage,
                    },
                },
            },
        };
        use core::ptr;

        type TestFabricData = PersistentFabricData<NopPersistentStorage>;

        #[test]
        fn register_as_first_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            assert!(!data.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(data.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(1, fabric_list.as_ref().entry_count());
        }

        #[test]
        fn register_twice_successfully() {
            let pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
        }

        #[test]
        fn register_two_same_data_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            let mut data_2: TestFabricData = new_with(1);
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(save(&mut data_2, NonNull::from_ref(&pa)).is_ok());
            assert!(data_2.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(1, fabric_list.as_ref().entry_count());
        }

        #[test]
        fn register_two_data_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            let mut data_2: TestFabricData = new_with(2);
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(save(&mut data_2, NonNull::from_ref(&pa)).is_ok());
            assert!(data_2.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(2, fabric_list.as_ref().entry_count());
        }

        #[test]
        fn unregister_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(data.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            assert!(delete(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(!data.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(0, fabric_list.as_ref().entry_count());
        }

        #[test]
        fn unregister_not_found() {
            let pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            assert!(!delete(&mut data, NonNull::from_ref(&pa)).is_ok());
        }

        #[test]
        fn unregister_one_of_two_data_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestFabricData = new_with(1);
            let mut data_2: TestFabricData = new_with(2);
            assert!(save(&mut data, NonNull::from_ref(&pa)).is_ok());
            assert!(save(&mut data_2, NonNull::from_ref(&pa)).is_ok());
            assert!(data_2.as_ref().validate(NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(2, fabric_list.as_ref().entry_count());
            assert!(delete(&mut data, NonNull::from_ref(&pa)).is_ok());
            let mut fabric_list = FabricList::new(fabric_list_impl::FabricList::new(), None);
            assert!(FabricList::load_from(&mut fabric_list, ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(1, fabric_list.as_ref().entry_count());
        }
    } // end of tests
}  // end of fabric_data

pub mod group_data {
    use super::*;
    use super::fabric_data::FabricData;
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                    data_model_types::KINVALID_ENDPOINT_ID,
                },
            },
        },
        chip_error_invalid_fabric_index,
        chip_error_internal,
        chip_error_not_found,
        chip_ok,
    };
    /*
    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use core::{
        str::{self, FromStr},
    };
    */

    const fn tag_name() -> Tag { context_tag(1) }
    const fn tag_first_endpoint() -> Tag { context_tag(2) }
    const fn tag_endpoint_count() -> Tag { context_tag(3) }
    const fn tag_next() -> Tag { context_tag(4) }

    pub struct GroupData {
        pub fabric_index: FabricIndex,
        pub first_endpoint: EndpointId,
        pub endpoint_count: u16,
        pub index: u16,
        pub next: GroupId,
        pub prev: GroupId,
        pub first: bool,
        pub group_info: GroupInfo,
    }

    pub type PersistentGroupData<PSD> = PersistentData<GroupData, K_PERSISTENT_BUFFER_MAX, PSD>;

    impl GroupData {
        pub const fn new() -> Self {
            Self {
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                first_endpoint: KINVALID_ENDPOINT_ID,
                endpoint_count: 0,
                index: 0,
                next: 0,
                prev: 0,
                first: true,
                group_info: GroupInfo::new(),
            }
        }

        pub const fn new_with(fabric_index: FabricIndex) -> Self {
            let mut g = Self::new();
            g.fabric_index = fabric_index;

            g
        }

        pub fn new_with_ids(fabric_index: FabricIndex, group: GroupId) -> Self {
            let mut g = Self::new();
            g.fabric_index = fabric_index;
            g.group_info = GroupInfo::new_with(group, "");

            g
        }

        #[inline]
        pub fn set_name(&mut self, group_name: Option<&str>) {
            self.group_info.set_name(group_name)
        }

        #[inline]
        pub fn group_info(&mut self) -> &mut GroupInfo {
            &mut self.group_info
        }
    }

    impl DataAccessor for GroupData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            verify_or_return_error!(KUNDEFINED_FABRIC_INDEX != self.fabric_index, Err(chip_error_invalid_fabric_index!()));
            Ok(DefaultStorageKeyAllocator::fabric_group(self.fabric_index, self.group_info.group_id))
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_string(tag_name(), self.group_info.name.str().ok_or(chip_error_internal!())?)?;
            writer.put_u16(tag_first_endpoint(), self.first_endpoint)?;
            writer.put_u16(tag_endpoint_count(), self.endpoint_count)?;
            writer.put_u16(tag_next(), self.next)?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;

            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            reader.next_tag(tag_name())?;
            self.set_name(reader.get_string()?);

            reader.next_tag(tag_first_endpoint())?;
            self.first_endpoint = reader.get_u16()?;

            reader.next_tag(tag_endpoint_count())?;
            self.endpoint_count = reader.get_u16()?;

            reader.next_tag(tag_next())?;
            self.next = reader.get_u16()?;

            reader.exit_container(container)
        }

        fn clear(&mut self) {
            self.set_name(None);
            self.first_endpoint = KINVALID_ENDPOINT_ID;
            self.endpoint_count = 0;
            self.next = 0;
        }
    }

    pub fn get<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(group_data: &mut PersistentGroupData<S>, storage: NonNull<PSD>, fabric: &FabricData, target_index: usize) -> bool {
        group_data.fabric_index = fabric.fabric_index;
        group_data.group_info.group_id = fabric.first_group;
        group_data.index = 0;
        group_data.first = true;

        while group_data.index < fabric.group_count {
            if PersistentGroupData::<S>::load_from(group_data, storage.as_ptr()).is_ok() {
                if usize::from(group_data.index) == target_index {
                    return true;
                }
                group_data.first = false;
                group_data.prev = group_data.group_info.group_id;
                group_data.group_info.group_id = group_data.next;
                group_data.index += 1;
            } else {
                break;
            }
        }

        false
    }

    pub fn find<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(group_data: &mut PersistentGroupData<S>,
        storage: NonNull<PSD>, fabric: &FabricData, target_group: GroupId) -> bool {

        group_data.fabric_index = fabric.fabric_index;
        group_data.group_info.group_id = fabric.first_group;
        group_data.index = 0;
        group_data.first = true;

        while group_data.index < fabric.group_count {
            if PersistentGroupData::<S>::load_from(group_data, storage.as_ptr()).is_ok() {
                if group_data.group_info.group_id == target_group {
                    return true;
                }
                group_data.first = false;
                group_data.prev = group_data.group_info.group_id;
                group_data.group_info.group_id = group_data.next;
                group_data.index += 1;
            } else {
                break;
            }
        }

        false
    }

    pub const fn new<Storage: PersistentStorageDelegate>() -> PersistentGroupData<Storage> {
        PersistentGroupData::<Storage>::new(GroupData::new(), None)
    }

    pub const fn new_with<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex) -> PersistentGroupData<Storage> {
        PersistentGroupData::<Storage>::new(GroupData::new_with(fabric_index), None)
    }

    pub fn new_with_ids<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex, group: GroupId) -> PersistentGroupData<Storage> {
        PersistentGroupData::<Storage>::new(GroupData::new_with_ids(fabric_index, group), None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    support::{
                        test_persistent_storage::TestPersistentStorage,
                    },
                },
            },
        };
        use core::ptr;

        type TestPersistentGroupData = PersistentGroupData<NopPersistentStorage>;

        #[test]
        fn save_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentGroupData = new_with(1);

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn load_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentGroupData = new_with(1);

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());

            let mut data_2: TestPersistentGroupData = new_with(1);

            assert!(TestPersistentGroupData::load_from(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn get_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(get(&mut data, NonNull::from_ref(&pa), &fabric_data, 0));
        }

        #[test]
        fn get_2_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let group_2: GroupId = 2;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            data.next = group_2;
            let mut data_2: TestPersistentGroupData = new_with_ids(fabric_index, group_2);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 2;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(TestPersistentGroupData::save_to(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
            assert!(get(&mut data, NonNull::from_ref(&pa), &fabric_data, 1));
        }

        #[test]
        fn get_no_group_count_0() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 0;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, 0));
        }

        #[test]
        fn get_no_index() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, 1));
        }

        #[test]
        fn get_no_group() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            //assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, 0));
        }

        #[test]
        fn find_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find(&mut data, NonNull::from_ref(&pa), &fabric_data, group));
        }

        #[test]
        fn find_2_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let group_2: GroupId = 2;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            data.next = group_2;
            let mut data_2: TestPersistentGroupData = new_with_ids(fabric_index, group_2);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 2;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(TestPersistentGroupData::save_to(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find(&mut data, NonNull::from_ref(&pa), &fabric_data, group_2));
        }

        #[test]
        fn find_group_count_0() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 0;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, group));
        }

        #[test]
        fn find_no_group() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            //assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, group));
        }

        #[test]
        fn find_no_group_id() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group: GroupId = 1;
            let mut data: TestPersistentGroupData = new_with_ids(fabric_index, group);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_group = group;
            fabric_data.group_count = 1;

            assert!(TestPersistentGroupData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, group + 1));
        }
    } // end of tests
} // end of group_data

pub mod key_map_data {
    use super::*;
    use super::{
        linked_data::LinkedData,
        fabric_data::FabricData,
    };
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                    data_model_types::KINVALID_KEYSET_ID,
                },
            },
            credentials::group_data_provider::GroupKey,
        },
        chip_error_invalid_fabric_index,
        chip_error_internal,
        /*
        chip_error_not_found,
        chip_ok,
        */
    };
    const fn tag_group_id() -> Tag { context_tag(1) }
    const fn tag_keyset_id() -> Tag { context_tag(2) }
    const fn tag_next() -> Tag { context_tag(3) }

    pub struct KeyMapData {
        pub group_key: GroupKey,
        pub linked_data: LinkedData,
        pub fabric_index: FabricIndex,
        pub group_id: GroupId,
        pub keyset_id: KeysetId,
    }

    type PersistentKeyMapData<S> = PersistentData<KeyMapData, K_PERSISTENT_BUFFER_MAX, S>;

    impl KeyMapData {
        pub const fn new() -> Self {
            Self {
                group_key: GroupKey::new(),
                linked_data: LinkedData::new(),
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                group_id: KUNDEFINED_GROUP_ID,
                keyset_id: KINVALID_KEYSET_ID,
            }
        }

        pub const fn new_with_fabric(fabric: FabricIndex) -> Self {
            Self {
                group_key: GroupKey::new(),
                linked_data: LinkedData::new(),
                fabric_index: fabric,
                group_id: KUNDEFINED_GROUP_ID,
                keyset_id: KINVALID_KEYSET_ID,
            }
        }

        pub const fn new_with(fabric: FabricIndex, link_id: u16, group: GroupId, keyset: KeysetId) -> Self {
            Self {
                group_key: GroupKey::new_with(group, keyset),
                linked_data: LinkedData::new_with(link_id),
                fabric_index: fabric,
                group_id: KUNDEFINED_GROUP_ID,
                keyset_id: KINVALID_KEYSET_ID,
            }
        }
    }

    impl DataAccessor for KeyMapData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            verify_or_return_error!(KUNDEFINED_FABRIC_INDEX != self.fabric_index, Err(chip_error_invalid_fabric_index!()));
            Ok(DefaultStorageKeyAllocator::fabric_group_key(self.fabric_index, self.linked_data.id))
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_u16(tag_group_id(), self.group_key.group_id)?;
            writer.put_u16(tag_keyset_id(), self.group_key.keyset_id)?;
            writer.put_u16(tag_next(), self.linked_data.next)?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;

            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            reader.next_tag(tag_group_id())?;
            self.group_key.group_id = reader.get_u16()?;

            reader.next_tag(tag_keyset_id())?;
            self.group_key.keyset_id = reader.get_u16()?;

            reader.next_tag(tag_next())?;
            self.linked_data.next = reader.get_u16()?;

            reader.exit_container(container)
        }

        fn clear(&mut self) { }
    }

    pub const fn new<Storage: PersistentStorageDelegate>() -> PersistentKeyMapData<Storage> {
        PersistentKeyMapData::<Storage>::new(KeyMapData::new(), None)
    }

    pub const fn new_with_fabric<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex) -> PersistentKeyMapData<Storage> {
        PersistentKeyMapData::<Storage>::new(KeyMapData::new_with_fabric(fabric_index), None)
    }

    pub const fn new_with<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex, link_id: u16, group: GroupId, keyset: KeysetId) -> PersistentKeyMapData<Storage> {
        PersistentKeyMapData::<Storage>::new(KeyMapData::new_with(fabric_index, link_id, group, keyset), None)
    }

    pub fn get<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(key_map_data: &mut PersistentKeyMapData<S>, storage: NonNull<PSD>, fabric: &FabricData, target_index: usize) -> bool {
        key_map_data.fabric_index = fabric.fabric_index;
        key_map_data.linked_data.id = fabric.first_map;
        key_map_data.linked_data.max_id = 0;
        key_map_data.linked_data.index = 0;
        key_map_data.linked_data.first = true;

        while key_map_data.linked_data.index < fabric.map_count {
            if PersistentKeyMapData::<S>::load_from(key_map_data, storage.as_ptr()).is_ok() {
                if usize::from(key_map_data.linked_data.index) == target_index {
                    return true;
                }
                key_map_data.linked_data.max_id = key_map_data.linked_data.max_id.max(key_map_data.linked_data.id);
                key_map_data.linked_data.first = false;
                key_map_data.linked_data.prev = key_map_data.linked_data.id;
                key_map_data.linked_data.id = key_map_data.linked_data.next;
                key_map_data.linked_data.index += 1;
            } else {
                break;
            }
        }

        key_map_data.linked_data.id = key_map_data.linked_data.max_id.wrapping_add(1);

        false
    }

    pub fn find_by_key<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(key_map_data: &mut PersistentKeyMapData<S>, storage: NonNull<PSD>, fabric: &FabricData, map: &GroupKey) -> bool {
        key_map_data.fabric_index = fabric.fabric_index;
        key_map_data.linked_data.id = fabric.first_map;
        key_map_data.linked_data.max_id = 0;
        key_map_data.linked_data.index = 0;
        key_map_data.linked_data.first = true;

        while key_map_data.linked_data.index < fabric.map_count {
            if PersistentKeyMapData::<S>::load_from(key_map_data, storage.as_ptr()).is_ok() {
                if key_map_data.group_key == *map {
                    return true;
                }
                key_map_data.linked_data.max_id = key_map_data.linked_data.max_id.max(key_map_data.linked_data.id);
                key_map_data.linked_data.first = false;
                key_map_data.linked_data.prev = key_map_data.linked_data.id;
                key_map_data.linked_data.id = key_map_data.linked_data.next;
                key_map_data.linked_data.index += 1;
            } else {
                break;
            }
        }

        key_map_data.linked_data.id = key_map_data.linked_data.max_id.wrapping_add(1);

        false
    }

    pub fn find_by_id<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(key_map_data: &mut PersistentKeyMapData<S>, storage: NonNull<PSD>, fabric: &FabricData, find_id: &KeysetId) -> Option<usize> {
        key_map_data.fabric_index = fabric.fabric_index;
        key_map_data.linked_data.id = fabric.first_map;
        key_map_data.linked_data.max_id = 0;
        key_map_data.linked_data.index = 0;
        key_map_data.linked_data.first = true;

        while key_map_data.linked_data.index < fabric.map_count {
            if PersistentKeyMapData::<S>::load_from(key_map_data, storage.as_ptr()).is_ok() {
                if key_map_data.group_key.keyset_id == *find_id {
                    return Some(key_map_data.linked_data.index.into());
                }
                key_map_data.linked_data.max_id = key_map_data.linked_data.max_id.max(key_map_data.linked_data.id);
                key_map_data.linked_data.first = false;
                key_map_data.linked_data.prev = key_map_data.linked_data.id;
                key_map_data.linked_data.id = key_map_data.linked_data.next;
                key_map_data.linked_data.index += 1;
            } else {
                break;
            }
        }

        key_map_data.linked_data.id = key_map_data.linked_data.max_id.wrapping_add(1);

        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    support::{
                        test_persistent_storage::TestPersistentStorage,
                    },
                },
            },
        };
        use core::ptr;

        type TestPersistentKeyMapData = PersistentKeyMapData<NopPersistentStorage>;

        #[test]
        fn save_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentKeyMapData = new_with_fabric(1);

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn load_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentKeyMapData = new_with_fabric(1);

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());

            let mut data_2: TestPersistentKeyMapData = new_with_fabric(1);

            assert!(TestPersistentKeyMapData::load_from(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn get_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(get(&mut data, NonNull::from_ref(&pa), &fabric_data, 0));
        }

        #[test]
        fn get_no_index() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, 1));
        }

        #[test]
        fn get_no_load() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;

            //assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, 0));
        }

        #[test]
        fn get_by_key_successfully() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;
            let group_key = GroupKey::new_with(group_id, keyset_id);

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find_by_key(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_key));
        }

        #[test]
        fn get_by_key_incorrect_key() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;
            let group_key = GroupKey::new_with(group_id + 1, keyset_id);

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find_by_key(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_key));
        }

        #[test]
        fn get_by_key_no_key() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;
            let group_key = GroupKey::new_with(group_id, keyset_id);

            //assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find_by_key(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_key));
        }

        #[test]
        fn get_by_id_successfully() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find_by_id(&mut data, NonNull::from_ref(&pa), &fabric_data, &keyset_id).is_some_and(|i| i == 0));
        }

        #[test]
        fn get_by_id_incorrect_id() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;
            // incorrect keset id
            let keyset_id = keyset_id + 1;

            assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find_by_id(&mut data, NonNull::from_ref(&pa), &fabric_data, &keyset_id).is_none());
        }

        #[test]
        fn get_by_id_no_id() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let id: u16 = 1;
            let group_id: GroupId = 1;
            let keyset_id: KeysetId = 1;
            let mut data: TestPersistentKeyMapData = new_with(fabric_index, id, group_id, keyset_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_map = id;
            fabric_data.map_count = 1;

            //assert!(TestPersistentKeyMapData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find_by_id(&mut data, NonNull::from_ref(&pa), &fabric_data, &keyset_id).is_none());
        }
    } // end of tests
} // end of key_map_data

pub mod endpoint_data {
    use super::*;
    use super::{
        group_data::GroupData,
        fabric_data::FabricData,
    };
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                    data_model_types::KINVALID_ENDPOINT_ID,
                },
            },
            credentials::group_data_provider::GroupEndpoint,
        },
        chip_error_invalid_fabric_index,
        chip_error_internal,
        /*
        chip_error_not_found,
        chip_ok,
        */
    };
    const fn tag_endpoint() -> Tag { context_tag(1) }
    const fn tag_next() -> Tag { context_tag(2) }

    pub struct EndpointData {
        pub group_endpoint: GroupEndpoint,
        pub fabric_index: FabricIndex,
        pub index: u16,
        pub next: EndpointId,
        pub prev: EndpointId,
        pub first: bool,
    }

    pub type PersistentEndpointData<S> = PersistentData<EndpointData, K_PERSISTENT_BUFFER_MAX, S>;

    impl EndpointData {
        pub const fn new() -> Self {
            Self {
                group_endpoint: GroupEndpoint::new(),
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                index: 0,
                next: 0,
                prev: 0,
                first: true,
            }
        }

        pub const fn new_with(fabric: FabricIndex, group: GroupId, endpoint: EndpointId) -> Self {
            Self {
                group_endpoint: GroupEndpoint::new_with(group, endpoint),
                fabric_index: fabric,
                index: 0,
                next: 0,
                prev: 0,
                first: true,
            }
        }

        pub const fn new_with_fabric(fabric: FabricIndex) -> Self {
            Self::new_with(fabric, KUNDEFINED_GROUP_ID, KINVALID_ENDPOINT_ID)
        }
    }

    impl DataAccessor for EndpointData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            verify_or_return_error!(KUNDEFINED_FABRIC_INDEX != self.fabric_index, Err(chip_error_invalid_fabric_index!()));
            Ok(DefaultStorageKeyAllocator::fabric_group_endpoint(self.fabric_index, self.group_endpoint.group_id, self.group_endpoint.endpoint_id))
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_u16(tag_endpoint(), self.group_endpoint.endpoint_id)?;
            writer.put_u16(tag_next(), self.next)?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;

            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            reader.next_tag(tag_endpoint())?;
            self.group_endpoint.endpoint_id = reader.get_u16()?;

            reader.next_tag(tag_next())?;
            self.next = reader.get_u16()?;

            reader.exit_container(container)
        }

        fn clear(&mut self) {
            self.next = KINVALID_ENDPOINT_ID;
        }
    }

    pub const fn new<Storage: PersistentStorageDelegate>() -> PersistentEndpointData<Storage> {
        PersistentEndpointData::<Storage>::new(EndpointData::new(), None)
    }

    pub const fn new_with_fabric<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex) -> PersistentEndpointData<Storage> {
        PersistentEndpointData::<Storage>::new(EndpointData::new_with_fabric(fabric_index), None)
    }

    pub const fn new_with<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex, group: GroupId, endpoint: EndpointId) -> PersistentEndpointData<Storage> {
        PersistentEndpointData::<Storage>::new(EndpointData::new_with(fabric_index, group, endpoint), None)
    }

    pub fn get<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(endpoint_data: &mut PersistentEndpointData<S>, storage: NonNull<PSD>, fabric: &FabricData, group: &GroupData, target_id: EndpointId) -> bool {
        endpoint_data.fabric_index = fabric.fabric_index;
        endpoint_data.group_endpoint.group_id = group.group_info.group_id;
        endpoint_data.group_endpoint.endpoint_id = group.first_endpoint;
        endpoint_data.index = 0;
        endpoint_data.first = true;

        while endpoint_data.index < group.endpoint_count {
            if PersistentEndpointData::<S>::load_from(endpoint_data, storage.as_ptr()).is_ok() {
                if endpoint_data.group_endpoint.endpoint_id == target_id {
                    return true;
                }
                endpoint_data.first = false;
                endpoint_data.prev = endpoint_data.group_endpoint.endpoint_id;
                endpoint_data.group_endpoint.endpoint_id = endpoint_data.next;
                endpoint_data.index += 1;
            } else {
                break;
            }
        }

        false
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    support::{
                        test_persistent_storage::TestPersistentStorage,
                    },
                },
            },
        };
        use core::ptr;

        type TestPersistentEndpointData = PersistentEndpointData<NopPersistentStorage>;

        #[test]
        fn save_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentEndpointData = new_with_fabric(1);

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn load_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentEndpointData = new_with_fabric(1);

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());

            let mut data_2: TestPersistentEndpointData = new_with_fabric(1);

            assert!(TestPersistentEndpointData::load_from(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn get_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group_id: GroupId = 1;
            let endpoint_id: EndpointId = 1;
            let mut data: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;

            let mut group_data = super::group_data::GroupData::new();
            group_data.group_info.group_id = group_id;
            group_data.first_endpoint = endpoint_id;
            group_data.endpoint_count = 1;

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(get(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_data, endpoint_id));
        }

        #[test]
        fn get_count_0() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group_id: GroupId = 1;
            let endpoint_id: EndpointId = 1;
            let mut data: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;

            let mut group_data = super::group_data::GroupData::new();
            group_data.group_info.group_id = group_id;
            group_data.first_endpoint = endpoint_id;
            group_data.endpoint_count = 0;

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_data, endpoint_id));
        }

        #[test]
        fn get_no_data() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group_id: GroupId = 1;
            let endpoint_id: EndpointId = 1;
            let mut data: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;

            let mut group_data = super::group_data::GroupData::new();
            group_data.group_info.group_id = group_id;
            group_data.first_endpoint = endpoint_id;
            group_data.endpoint_count = 1;

            //assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_data, endpoint_id));
        }

        #[test]
        fn get_no_id() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group_id: GroupId = 1;
            let endpoint_id: EndpointId = 1;
            let mut data: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;

            let mut group_data = super::group_data::GroupData::new();
            group_data.group_info.group_id = group_id;
            group_data.first_endpoint = endpoint_id;
            group_data.endpoint_count = 1;

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!get(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_data, endpoint_id + 1));
        }

        #[test]
        fn get_second_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let group_id: GroupId = 1;
            let endpoint_id: EndpointId = 1;
            let endpoint_id_2: EndpointId = 2;
            let mut data: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id);
            data.next = endpoint_id_2;
            let mut data_2: TestPersistentEndpointData = new_with(fabric_index, group_id, endpoint_id_2);
            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;

            let mut group_data = super::group_data::GroupData::new();
            group_data.group_info.group_id = group_id;
            group_data.first_endpoint = endpoint_id;
            group_data.endpoint_count = 2;

            assert!(TestPersistentEndpointData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(TestPersistentEndpointData::save_to(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
            assert!(get(&mut data, NonNull::from_ref(&pa), &fabric_data, &group_data, endpoint_id_2));
        }
    } // enf of tests
} // end of endpoint_data

pub mod key_set_data {
    use super::*;
    use super::{
        fabric_data::FabricData,
    };
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                    data_model_types::KINVALID_KEYSET_ID,
                },
            },
            credentials::group_data_provider::{SecurityPolicy, key_set},
            crypto::GroupOperationalCredentials,
        },
        chip_error_invalid_fabric_index,
        chip_error_invalid_key_id,
        chip_error_internal,
        /*
        chip_error_not_found,
        chip_ok,
        */
    };

    /*
    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use core::{
        str::{self, FromStr},
    };
    */
    const fn tag_policy() -> Tag { context_tag(1) }
    const fn tag_num_keys() -> Tag { context_tag(2) }
    const fn tag_group_credentials() -> Tag { context_tag(3) }
    const fn tag_start_time() -> Tag { context_tag(4) }
    const fn tag_key_hash() -> Tag { context_tag(5) }
    const fn tag_key_value() -> Tag { context_tag(6) }
    const fn tag_next() -> Tag { context_tag(7) }

    pub struct KeySetData {
        pub fabric_index: FabricIndex,
        pub next: KeysetId,
        pub prev: KeysetId,
        pub first: bool,
        pub keyset_id: KeysetId,
        pub policy: SecurityPolicy,
        pub keys_count: u8,
        pub operational_keys: [GroupOperationalCredentials; key_set::KEPOCH_KEYS_MAX],
    }

    type PersistentKeySetData<S> = PersistentData<KeySetData, K_PERSISTENT_BUFFER_MAX, S>;

    impl KeySetData {
        pub const fn new() -> Self {
            Self {
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                next: KINVALID_KEYSET_ID,
                prev: KINVALID_KEYSET_ID,
                first: true,
                keyset_id: 0,
                policy: SecurityPolicy::KcacheAndSync,
                keys_count: 0,
                operational_keys: [ const { GroupOperationalCredentials::new() }; key_set::KEPOCH_KEYS_MAX],
            }
        }

        pub const fn new_with_fabric_keyset(fabric: FabricIndex, id: KeysetId) -> Self {
            Self {
                fabric_index: fabric,
                next: KINVALID_KEYSET_ID,
                prev: KINVALID_KEYSET_ID,
                first: true,
                keyset_id: id,
                policy: SecurityPolicy::KcacheAndSync,
                keys_count: 0,
                operational_keys: [ const { GroupOperationalCredentials::new() }; key_set::KEPOCH_KEYS_MAX],
            }
        }

        pub const fn new_with(fabric: FabricIndex, id: KeysetId, policy_id: SecurityPolicy, num_keys: u8) -> Self {
            Self {
                fabric_index: fabric,
                next: KINVALID_KEYSET_ID,
                prev: KINVALID_KEYSET_ID,
                first: true,
                keyset_id: id,
                policy: policy_id,
                keys_count: num_keys,
                operational_keys: [ const { GroupOperationalCredentials::new() }; key_set::KEPOCH_KEYS_MAX],
            }
        }

        pub fn get_current_group_credentials(&mut self) -> Option<&mut GroupOperationalCredentials> {
            match self.keys_count {
                0 | 1 => {
                    Some(&mut self.operational_keys[0])
                },
                2 => {
                    Some(&mut self.operational_keys[1])
                },
                _ => {
                    None
                }
            }
        }
    }

    impl DataAccessor for KeySetData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            verify_or_return_error!(KUNDEFINED_FABRIC_INDEX != self.fabric_index, Err(chip_error_invalid_fabric_index!()));
            verify_or_return_error!(KINVALID_KEYSET_ID != self.keyset_id, Err(chip_error_invalid_key_id!()));
            Ok(DefaultStorageKeyAllocator::fabric_keyset(self.fabric_index, self.keyset_id))
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_u16(tag_policy(), self.policy as u16)?;
            writer.put_u16(tag_num_keys(), self.keys_count.into())?;

            {
                let mut array_container = TlvType::KtlvTypeNotSpecified;
                writer.start_container(tag_group_credentials(), TlvType::KtlvTypeArray, &mut array_container)?;
                let mut key_count = 0u8;
                for key in &self.operational_keys {
                    let mut start_time = 0u64;
                    let mut hash = 0u16;
                    let mut encryption_key = [0u8; crate::chip::crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
                    let mut item_container = TlvType::KtlvTypeNotSpecified;
                    writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut item_container)?;
                    if key_count < self.keys_count {
                        start_time = key.m_start_time;
                        hash = key.m_hash;
                        encryption_key.copy_from_slice(&key.m_encryption_key);
                    }
                    key_count += 1;

                    writer.put_u64(tag_start_time(), start_time)?;
                    writer.put_u16(tag_key_hash(), hash)?;
                    writer.put_bytes(tag_key_value(), &encryption_key)?;

                    writer.end_container(item_container)?;
                }

                writer.end_container(array_container)?;
            }

            writer.put_u16(tag_next(), self.next)?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;

            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            reader.next_tag(tag_policy())?;
            self.policy = SecurityPolicy::try_from(reader.get_u16()?).map_err(|_| chip_error_internal!())?;

            reader.next_tag(tag_num_keys())?;
            self.keys_count = reader.get_u16()? as u8;

            {
                reader.next_tag(tag_group_credentials())?;
                verify_or_return_error!(TlvType::KtlvTypeArray == reader.get_type(), Err(chip_error_internal!()));
                let array_container = reader.enter_container()?;

                for key in &mut self.operational_keys {
                    reader.next_tag(anonymous_tag())?;
                    verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

                    let item_container = reader.enter_container()?;

                    reader.next_tag(tag_start_time())?;
                    key.m_start_time = reader.get_u64()?;

                    reader.next_tag(tag_key_hash())?;
                    key.m_hash = reader.get_u16()?;

                    reader.next_tag(tag_key_value())?;
                    key.m_encryption_key.copy_from_slice(reader.get_bytes()?);

                    crate::chip::crypto::derive_group_privacy_key(&key.m_encryption_key, &mut key.m_privacy_key)?;

                    reader.exit_container(item_container)?;
                }
                reader.exit_container(array_container)?;
            }

            reader.next_tag(tag_next())?;
            self.next = reader.get_u16()?;

            reader.exit_container(container)
        }

        fn clear(&mut self) {
            self.policy = SecurityPolicy::KcacheAndSync;
            self.keys_count= 0;
            self.operational_keys = [ const { GroupOperationalCredentials::new() }; key_set::KEPOCH_KEYS_MAX ];
            self.next = KINVALID_KEYSET_ID;
        }
    }


    pub const fn new<Storage: PersistentStorageDelegate>() -> PersistentKeySetData<Storage> {
        PersistentKeySetData::<Storage>::new(KeySetData::new(), None)
    }

    pub const fn new_with_fabric_keyset<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex, id: KeysetId) -> PersistentKeySetData<Storage> {
        PersistentKeySetData::<Storage>::new(KeySetData::new_with_fabric_keyset(fabric_index, id), None)
    }

    pub const fn new_with<Storage: PersistentStorageDelegate>(fabric_index: FabricIndex, id: KeysetId, policy_id: SecurityPolicy, num_keys: u8) -> PersistentKeySetData<Storage> {
        PersistentKeySetData::<Storage>::new(KeySetData::new_with(fabric_index, id, policy_id, num_keys), None)
    }

    pub fn find<PSD: PersistentStorageDelegate, S: PersistentStorageDelegate>(keyset_data: &mut PersistentKeySetData<S>, storage: NonNull<PSD>, fabric: &FabricData, target_id: usize) -> bool {
        let mut count = 0u16;

        keyset_data.fabric_index = fabric.fabric_index;
        keyset_data.keyset_id = fabric.first_keyset;
        keyset_data.first = true;

        while count < fabric.keyset_count {
            count += 1;
            if PersistentKeySetData::<S>::load_from(keyset_data, storage.as_ptr()).is_ok() {
                if usize::from(keyset_data.keyset_id) == target_id {
                    return true;
                }
                keyset_data.first = false;
                keyset_data.prev = keyset_data.keyset_id;
                keyset_data.keyset_id = keyset_data.next;
            } else {
                break;
            }
        }

        false
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    support::{
                        test_persistent_storage::TestPersistentStorage,
                    },
                },
            },
        };
        use core::ptr;

        type TestPersistentKeySetData = PersistentKeySetData<NopPersistentStorage>;

        #[test]
        fn save_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentKeySetData = new_with_fabric_keyset(1, 2);

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn load_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut data: TestPersistentKeySetData = new_with_fabric_keyset(1, 2);

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());

            let mut data_2: TestPersistentKeySetData = new_with_fabric_keyset(1, 2);

            assert!(TestPersistentKeySetData::load_from(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
        }

        #[test]
        fn find_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let keyset_id: KeysetId = 2;
            let policy_id = SecurityPolicy::KcacheAndSync;
            let num_keys = 3u8;
            let mut data: TestPersistentKeySetData = new_with(fabric_index, keyset_id, policy_id, num_keys);

            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_keyset = keyset_id;
            fabric_data.keyset_count = num_keys as u16;

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find(&mut data, NonNull::from_ref(&pa), &fabric_data, keyset_id.into()));
        }

        #[test]
        fn find_second_ok() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let keyset_id: KeysetId = 2;
            let keyset_id_2: KeysetId = 3;
            let policy_id = SecurityPolicy::KcacheAndSync;
            let num_keys = 3u8;
            let mut data: TestPersistentKeySetData = new_with(fabric_index, keyset_id, policy_id, num_keys);
            let mut data_2: TestPersistentKeySetData = new_with(fabric_index, keyset_id_2, policy_id, num_keys);

            data.next = keyset_id_2;

            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_keyset = keyset_id;
            fabric_data.keyset_count = num_keys as u16;

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(TestPersistentKeySetData::save_to(&mut data_2, ptr::addr_of_mut!(pa)).is_ok());
            assert!(find(&mut data, NonNull::from_ref(&pa), &fabric_data, keyset_id_2.into()));
        }

        #[test]
        fn find_key_count_zero() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let keyset_id: KeysetId = 2;
            let policy_id = SecurityPolicy::KcacheAndSync;
            let num_keys = 3u8;
            let mut data: TestPersistentKeySetData = new_with(fabric_index, keyset_id, policy_id, num_keys);

            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_keyset = keyset_id;
            fabric_data.keyset_count = 0;

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, keyset_id.into()));
        }

        #[test]
        fn find_load_failed() {
            let pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let keyset_id: KeysetId = 2;
            let policy_id = SecurityPolicy::KcacheAndSync;
            let num_keys = 3u8;
            let mut data: TestPersistentKeySetData = new_with(fabric_index, keyset_id, policy_id, num_keys);

            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_keyset = keyset_id;
            fabric_data.keyset_count = num_keys as u16;

            //assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, keyset_id.into()));
        }

        #[test]
        fn find_no_key() {
            let mut pa = TestPersistentStorage::default();
            let fabric_index: FabricIndex = 1;
            let keyset_id: KeysetId = 2;
            let policy_id = SecurityPolicy::KcacheAndSync;
            let num_keys = 3u8;
            let mut data: TestPersistentKeySetData = new_with(fabric_index, keyset_id, policy_id, num_keys);

            let mut fabric_data = super::fabric_data::FabricData::new();
            fabric_data.fabric_index = fabric_index;
            fabric_data.first_keyset = keyset_id;
            fabric_data.keyset_count = num_keys as u16;

            assert!(TestPersistentKeySetData::save_to(&mut data, ptr::addr_of_mut!(pa)).is_ok());
            assert!(!find(&mut data, NonNull::from_ref(&pa), &fabric_data, (keyset_id + 1).into()));
        }
    } // end of tests
} // end of key_set_data

pub mod iter_impl {
    use super::*;

    use crate::{
        chip::{
            crypto::{
                SymmetricEncryptResult, SymmetricDecryptResult,
            },
        },
    };

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use core::{
        str::{self, FromStr},
    };

    use core::marker::PhantomData;

    pub struct GroupInfoIteratorImpl<Provider: GroupDataProvider>
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
    }

    impl<Provider: GroupDataProvider> Iterator for GroupInfoIteratorImpl<Provider> {
        type Item = GroupInfo;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    pub struct GroupKeyIteratorImpl<Provider: GroupDataProvider>
    {
        m_provider: Option<NonNull<Provider>>,
        m_fabric: FabricIndex,
        m_next_id: u16,
        m_count: usize,
        m_total: usize,
    }

    impl<Provider: GroupDataProvider> GroupKeyIteratorImpl<Provider> {
        pub const fn new() -> Self {
            Self {
                m_provider: None,
                m_fabric: KUNDEFINED_FABRIC_INDEX,
                m_next_id: 0,
                m_count: 0,
                m_total: 0,
            }
        }
    }

    impl<Provider: GroupDataProvider> Iterator for GroupKeyIteratorImpl<Provider> {
        type Item = GroupKey;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    pub struct EndpointIteratorImpl<Provider: GroupDataProvider>
    {
        m_provider: Option<NonNull<Provider>>,
        m_fabric: FabricIndex,
        m_first_group: GroupId,
        m_group: u16,
        m_group_index: usize,
        m_group_count: usize,
        m_endpoint: u16,
        m_endpoint_index: usize,
        m_endpoint_count: usize,
        m_first_endpoint: bool,
    }

    impl<Provider: GroupDataProvider> EndpointIteratorImpl<Provider> {
        pub const fn new() -> Self {
            Self {
                m_provider: None,
                m_fabric: KUNDEFINED_FABRIC_INDEX,
                m_first_group: KUNDEFINED_GROUP_ID,
                m_group: 0,
                m_group_index: 0,
                m_group_count: 0,
                m_endpoint: 0,
                m_endpoint_index: 0,
                m_endpoint_count: 0,
                m_first_endpoint: true,
            }
        }
    }

    impl<Provider: GroupDataProvider> Iterator for EndpointIteratorImpl<Provider> {
        type Item = GroupEndpoint;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    pub struct GroupKeyContext<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        m_provider: Option<NonNull<Provider>>,
        m_key_hash: u16,
        m_encryption_key: Aes128KeyHandle,
        m_privacy_key: Aes128KeyHandle,
        m_phantom: PhantomData<SKS>,
    }

    impl<SKS, Provider> GroupKeyContext<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        pub const fn new() -> Self {
            Self {
                m_provider: None,
                m_key_hash: 0,
                m_encryption_key: Aes128KeyHandle::new(),
                m_privacy_key: Aes128KeyHandle::new(),
                m_phantom: PhantomData,
            }
        }

        pub fn new_with_provider(provider: Option<NonNull<Provider>>) -> Self {
            Self {
                m_provider: provider,
                m_key_hash: 0,
                m_encryption_key: Aes128KeyHandle::new(),
                m_privacy_key: Aes128KeyHandle::new(),
                m_phantom: PhantomData,
            }
        }

        pub fn new_with(provider: Option<NonNull<Provider>>, encryption_key: &Symmetric128BitsKeyByteArray, hash: u16, 
            privacy_key: &Symmetric128BitsKeyByteArray) -> Self {
            let mut s = Self {
                m_provider: provider,
                m_key_hash: 0,
                m_encryption_key: Aes128KeyHandle::new(),
                m_privacy_key: Aes128KeyHandle::new(),
                m_phantom: PhantomData,
            };

            s.initialize(encryption_key, hash, privacy_key);

            s
        }

        pub fn initialize(&mut self, encryption_key: &Symmetric128BitsKeyByteArray, hash: u16, privacy_key: &Symmetric128BitsKeyByteArray) {
            self.release_keys();
            self.m_key_hash = hash;
            // TODO: Load group keys to the session keystore upon loading from persistent storage
            //
            // Group keys should be transformed into a key handle as soon as possible or even
            // the key storage should be taken over by SessionKeystore interface, but this looks
            // like more work, so let's use the transitional code below for now.
            unsafe {
                if let Some(mut provider) = self.m_provider &&
                 let Some(mut session_keystore_ptr) = provider.as_mut().get_session_keystore() {
                     let session_keystore = session_keystore_ptr.as_mut();
                     match session_keystore.create_key_aes128(encryption_key) {
                         Ok(key) => {
                             self.m_encryption_key = key;
                         },
                         Err(e) => {
                            chip_log_error!(
                                SecureChannel,
                                "group key contexet failed to create key 1"
                            );
                         }
                     }
                     match session_keystore.create_key_aes128(privacy_key) {
                         Ok(key) => {
                             self.m_privacy_key = key;
                         },
                         Err(e) => {
                            chip_log_error!(
                                SecureChannel,
                                "group key contexet failed to create key 2"
                            );
                         }
                     }
                } else {
                    chip_log_error!(
                        SecureChannel,
                        "group key contexet no group data key store"
                    );
                }
            }
        }

        pub fn release_keys(&mut self) {
            unsafe {
                if let Some(mut provider) = self.m_provider &&
                 let Some(mut session_keystore_ptr) = provider.as_mut().get_session_keystore() {
                     let session_keystore = session_keystore_ptr.as_mut();
                     session_keystore.destroy_key_128bits(&mut self.m_encryption_key);
                     session_keystore.destroy_key_128bits(&mut self.m_privacy_key);
                } else {
                    chip_log_error!(
                        SecureChannel,
                        "group key contexet no group data key store"
                    );
                }
            }
        }
    }

    impl<SKS, Provider> SymmetricKeyContext for GroupKeyContext<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        fn get_key_hash(&mut self) -> u16 {
            self.m_key_hash
        }

        fn message_encrypt(&self, _plaintext: &[u8], _aad: &[u8], _nonce: &[u8], _mic: &mut [u8], _ciphertext: &mut [u8]) -> Result<SymmetricEncryptResult, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn message_decrypt(&self, _ciphertext: &[u8], _aad: &[u8], _nonce: &[u8], _mic: &[u8], _plaintext: &mut [u8]) -> Result<SymmetricDecryptResult, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn privacy_encrypt(&self, _input: &[u8], _nonce: &[u8], _output: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn privacy_decrypt(&self, _input: &[u8], _nonce: &[u8], _output: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn release(&mut self) {
        }
    }

    pub struct KeySetIteratorImpl<Provider: GroupDataProvider>
    {
        m_provider: Option<NonNull<Provider>>,
        m_fabric: FabricIndex,
        m_next_id: u16,
        m_count: usize,
        m_total: usize,
    }

    impl<Provider: GroupDataProvider> KeySetIteratorImpl<Provider> {
        pub const fn new() -> Self {
            Self {
                m_provider: None,
                m_fabric: KUNDEFINED_FABRIC_INDEX,
                m_next_id: 0,
                m_count: 0,
                m_total: 0,
            }
        }
    }

    impl<Provider: GroupDataProvider> Iterator for KeySetIteratorImpl<Provider> {
        type Item = KeySet;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    pub struct GroupSessionIteratorImpl<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        m_provider: Option<NonNull<Provider>>,
        m_first_fabric: FabricIndex,
        m_fabric: FabricIndex,
        m_fabric_count: u16,
        m_fabric_total: u16,
        m_mapping: u16,
        m_map_count: u16,
        m_key_index: u16,
        m_key_count: u16,
        m_first_map: bool,
        m_group_key_context: GroupKeyContext<SKS, Provider>,
    }

    impl<SKS, Provider> GroupSessionIteratorImpl<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        pub const fn new() -> Self {
            Self {
                m_provider: None,
                m_first_fabric: KUNDEFINED_FABRIC_INDEX,
                m_fabric: KUNDEFINED_FABRIC_INDEX,
                m_fabric_count: 0,
                m_fabric_total: 0,
                m_mapping: 0,
                m_map_count: 0,
                m_key_index: 0,
                m_key_count: 0,
                m_first_map: true,
                m_group_key_context: GroupKeyContext::<SKS, Provider>::new(),
            }
        }
    }

    impl<SKS, Provider> Iterator for GroupSessionIteratorImpl<SKS, Provider>
    where
        SKS: SessionKeystore,
        Provider: GroupDataProvider + UpdateSessionKeystore<SKS>,
    {
        type Item = GroupSession<GroupKeyContext<SKS, Provider>>;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }
} // end of iter_impl

/*
struct GroupKeyIteratorImpl
{
    m_provider: Option<NonNull<GroupDataProviderImpl>>,
    m_fabric: FabricIndex,
    m_next_id: u16,
    m_count: usize,
    m_total: usize,
}

impl GroupKeyIteratorImpl {
    pub const fn new() -> Self {
        Self {
            m_provider: None,
            m_fabric: KUNDEFINED_FABRIC_INDEX,
            m_next_id: 0,
            m_count: 0,
            m_total: 0,
        }
    }
}

impl Iterator for GroupKeyIteratorImpl {
    type Item = GroupKey;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

struct EndpointIteratorImpl
{
    m_provider: Option<NonNull<GroupDataProviderImpl>>,
    m_fabric: FabricIndex,
    m_first_group: GroupId,
    m_group: u16,
    m_group_index: usize,
    m_group_count: usize,
    m_endpoint: u16,
    m_endpoint_index: usize,
    m_endpoint_count: usize,
    m_first_endpoint: bool,
}

impl EndpointIteratorImpl {
    pub const fn new() -> Self {
        Self {
            m_provider: None,
            m_fabric: KUNDEFINED_FABRIC_INDEX,
            m_first_group: KUNDEFINED_GROUP_ID,
            m_group: 0,
            m_group_index: 0,
            m_group_count: 0,
            m_endpoint: 0,
            m_endpoint_index: 0,
            m_endpoint_count: 0,
            m_first_endpoint: true,
        }
    }
}

impl Iterator for EndpointIteratorImpl {
    type Item = GroupEndpoint;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
*/

type GroupInfoIterator<PSD, SKS, LIS> = iter_impl::GroupInfoIteratorImpl<GroupDataProviderImpl<PSD, SKS, LIS>>;
type GroupInfoIteratorPool<PSD, SKS, LIS> = BitMapObjectPool<GroupInfoIterator<PSD, SKS, LIS>, 2>;

type GroupKeyIterator<PSD, SKS, LIS> = iter_impl::GroupKeyIteratorImpl<GroupDataProviderImpl<PSD, SKS, LIS>>;
type GroupKeyIteratorPool<PSD, SKS, LIS> = BitMapObjectPool<GroupKeyIterator<PSD, SKS, LIS>, 2>;

type EndpointIterator<PSD, SKS, LIS> = iter_impl::EndpointIteratorImpl<GroupDataProviderImpl<PSD, SKS, LIS>>;
type EndpointIteratorPool<PSD, SKS, LIS> = BitMapObjectPool<EndpointIterator<PSD, SKS, LIS>, 2>;

type KeySetIterator<PSD, SKS, LIS> = iter_impl::KeySetIteratorImpl<GroupDataProviderImpl<PSD, SKS, LIS>>;
type KeySetIteratorPool<PSD, SKS, LIS> = BitMapObjectPool<KeySetIterator<PSD, SKS, LIS>, 2>;

type GroupSessionIterator<PSD, SKS, LIS> = iter_impl::GroupSessionIteratorImpl<SKS, GroupDataProviderImpl<PSD, SKS, LIS>>;
type GroupSessionIteratorPool<PSD, SKS, LIS> = BitMapObjectPool<GroupSessionIterator<PSD, SKS, LIS>, 2>;

type FabricData = fabric_data::PersistentFabricData<NopPersistentStorage>;
type GroupData = group_data::PersistentGroupData<NopPersistentStorage>;
type EndpointData = endpoint_data::PersistentEndpointData<NopPersistentStorage>;

pub trait UpdateSessionKeystore<SKS>
where
    SKS: SessionKeystore,
{
    fn get_session_keystore(&mut self) -> Option<NonNull<SKS>>;
    fn set_session_keystore(&mut self, store: Option<NonNull<SKS>>);
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
    m_group_info_iterators: GroupInfoIteratorPool<PSD, SKS, LIS>,
    m_group_key_iterators: GroupKeyIteratorPool<PSD, SKS, LIS>,
    m_endpoint_iterators: EndpointIteratorPool<PSD, SKS, LIS>,
    m_key_set_iterators: KeySetIteratorPool<PSD, SKS, LIS>,
    m_group_session_iterators: GroupSessionIteratorPool<PSD, SKS, LIS>,
}

impl<PSD, SKS, LIS> UpdateSessionKeystore<SKS> for GroupDataProviderImpl<PSD, SKS, LIS>
where
    PSD: PersistentStorageDelegate,
    SKS: SessionKeystore,
    LIS: GroupListener,
{
    fn get_session_keystore(&mut self) -> Option<NonNull<SKS>> {
        self.m_sesion_keystore.clone()
    }

    fn set_session_keystore(&mut self, store: Option<NonNull<SKS>>) {
        self.m_sesion_keystore = store;
    }
}

impl<PSD, SKS, LIS> GroupDataProviderImpl<PSD, SKS, LIS>
where
    PSD: PersistentStorageDelegate,
    SKS: SessionKeystore,
    LIS: GroupListener,
{
    pub const fn new() -> Self {
        Self {
            m_storage: None,
            m_sesion_keystore: None,
            m_max_groups_per_fabric: 0,
            m_max_group_keys_per_fabric: 0,
            m_listener: None,
            m_group_info_iterators: GroupInfoIteratorPool::<PSD, SKS, LIS>::new(),
            m_group_key_iterators: GroupKeyIteratorPool::<PSD, SKS, LIS>::new(),
            m_endpoint_iterators: EndpointIteratorPool::<PSD, SKS, LIS>::new(),
            m_key_set_iterators: KeySetIteratorPool::<PSD, SKS, LIS>::new(),
            m_group_session_iterators: GroupSessionIteratorPool::<PSD, SKS, LIS>::new(),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.m_storage.is_some()
    }

    pub fn set_storage_delegate(&mut self, storage: Option<NonNull<PSD>>) {
        verify_or_die!(storage.is_some());
        self.m_storage = storage;
    }

    pub fn remove_endpoints(&mut self, fabric_index: FabricIndex, group_id: GroupId) -> ChipErrorResult {
        unsafe {
            let storage_ptr = self.m_storage.as_ref().ok_or(chip_error_internal!())?.as_ptr();

            let mut fabric: FabricData = fabric_data::new_with(fabric_index);
            let mut group: GroupData = group_data::new();

            verify_or_return_error!(FabricData::load_from(&mut fabric, storage_ptr).is_ok(), Err(chip_error_invalid_fabric_index!()));
            verify_or_return_error!(group_data::find(&mut group, NonNull::new_unchecked(storage_ptr), &fabric, group_id), Err(chip_error_key_not_found!()));

            let mut endpoint: EndpointData = endpoint_data::new_with(fabric_index, group.group_info.group_id, group.first_endpoint);

            for endpoint_index in 0..group.endpoint_count {
                EndpointData::load_from(&mut endpoint, storage_ptr)?;
                EndpointData::delete_from(&mut endpoint, storage_ptr)?;
                endpoint.group_endpoint.endpoint_id = endpoint.next;
            }

            group.first_endpoint = KINVALID_ENDPOINT_ID;
            group.endpoint_count = 0;
            return GroupData::save_to(&mut group, storage_ptr);
        }
    }

    fn group_added(&mut self, fabric_index: FabricIndex, new_group: &GroupInfo) {
        if let Some(mut listener_ptr) = self.m_listener {
            unsafe {
                listener_ptr.as_mut().on_group_added(fabric_index, new_group);
            }
        }
    }

    fn group_removed(&mut self, fabric_index: FabricIndex, old_group: &GroupInfo) {
        if let Some(mut listener_ptr) = self.m_listener {
            unsafe {
                listener_ptr.as_mut().on_group_removed(fabric_index, old_group);
            }
        }
    }
}

impl<PSD, SKS, LIS> GroupDataProvider for GroupDataProviderImpl<PSD, SKS, LIS>
where
    PSD: PersistentStorageDelegate,
    SKS: SessionKeystore,
    LIS: GroupListener,
{
    type GroupInfoIterator = GroupInfoIterator<PSD, SKS, LIS>;
    type GroupKeyIterator = GroupKeyIterator<PSD, SKS, LIS>;
    type EndpointIterator = EndpointIterator<PSD, SKS, LIS>;
    type KeySetIterator = KeySetIterator<PSD, SKS, LIS>;
    type GroupSessionIterator = GroupSessionIterator<PSD, SKS, LIS>;
    type Listener = LIS;

    fn new_with(max_group_per_fabric: u16, max_group_keys_per_fabric: u16) -> Self {
        Self {
            m_storage: None,
            m_sesion_keystore: None,
            m_max_groups_per_fabric: max_group_per_fabric,
            m_max_group_keys_per_fabric: max_group_keys_per_fabric,
            m_listener: None,
            m_group_info_iterators: GroupInfoIteratorPool::<PSD, SKS, LIS>::new(),
            m_group_key_iterators: GroupKeyIteratorPool::<PSD, SKS, LIS>::new(),
            m_endpoint_iterators: EndpointIteratorPool::<PSD, SKS, LIS>::new(),
            m_key_set_iterators: KeySetIteratorPool::<PSD, SKS, LIS>::new(),
            m_group_session_iterators: GroupSessionIteratorPool::<PSD, SKS, LIS>::new(),
        }
    }

    fn get_max_groups_per_fabric(&self) -> u16 {
        0
    }

    fn get_max_group_keys_per_fabric(&self) -> u16 {
        0
    }

    fn init(&mut self) -> ChipErrorResult {
        if self.m_storage.is_none() || self.m_sesion_keystore.is_none() {
            return Err(chip_error_incorrect_state!());
        }

        chip_ok!()
    }

    fn finish(&mut self) {
        self.m_group_info_iterators.release_all();
        self.m_group_key_iterators.release_all();
        self.m_endpoint_iterators.release_all();
        self.m_key_set_iterators.release_all();
        self.m_group_session_iterators.release_all();
    }

    // By id
    fn set_group_info(&mut self, fabric_index: FabricIndex, info: &GroupInfo) -> ChipErrorResult {
        let storage_ptr = unsafe {
            self.m_storage.as_ref().ok_or(chip_error_internal!())?.as_ptr()
        };

        let mut fabric: FabricData = fabric_data::new_with(fabric_index);
        let mut group: GroupData = group_data::new();

        match FabricData::load_from(&mut fabric, storage_ptr) {
            Err(e) if e != chip_error_not_found!() => return Err(e),
            _ => {}
        }

        unsafe {
            if group_data::find(&mut group, NonNull::new_unchecked(storage_ptr), &fabric, info.group_id) {
                // Existing group_id
                group.set_name(info.name.str());
                return GroupData::save_to(&mut group, storage_ptr);
            }
        }

        // New group_id
        group.group_info.group_id = info.group_id;
        group.set_name(info.name.str());
        
        self.set_group_info_at(fabric_index, fabric.group_count.into(), info)
    }

    fn get_group_info(&self, fabric_index: FabricIndex) -> Result<GroupInfo, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn remove_group_info(&mut self, fabric_index: FabricIndex, group_id: GroupId) -> ChipErrorResult {
        chip_ok!()
    }

    // By index
    fn set_group_info_at(&mut self, fabric_index: FabricIndex, index: usize, info: &GroupInfo) -> ChipErrorResult {
        unsafe {
            let storage_ptr = self.m_storage.as_ref().ok_or(chip_error_internal!())?.as_ptr();

            let mut fabric: FabricData = fabric_data::new_with(fabric_index);
            let mut group: GroupData = group_data::new();

            match FabricData::load_from(&mut fabric, storage_ptr) {
                Ok(()) => {
                    // do nothing
                }
                Err(e) => {
                    if e != chip_error_not_found!() {
                        return Err(e);
                    }
                }
            }

            let found = group_data::find(&mut group, NonNull::new_unchecked(storage_ptr), &fabric, info.group_id);

            verify_or_return_error!(!found || (usize::from(group.index) == index), Err(chip_error_duplicate_key_id!()));

            group.group_info.group_id = info.group_id;
            group.endpoint_count = 0;
            group.set_name(info.name.str());

            if found {
                // Update existing entry
                return GroupData::save_to(&mut group, storage_ptr);
            }

            if index < fabric.group_count.into() {
                // Replace existing entry with a new group
                let mut old_group: GroupData = group_data::new();
                group_data::get(&mut old_group, NonNull::new_unchecked(storage_ptr), &fabric, index);
                group.first = old_group.first;
                group.prev = old_group.prev;
                group.next = old_group.next;

                self.remove_endpoints(fabric_index, old_group.group_info.group_id)?;
                GroupData::delete_from(&mut old_group, storage_ptr)?;
                self.group_removed(fabric_index, &old_group.group_info);
            } else {
                // Insert last
                verify_or_return_error!(usize::from(fabric.group_count) == index, Err(chip_error_invalid_argument!()));
                verify_or_return_error!(fabric.group_count < self.m_max_groups_per_fabric, Err(chip_error_invalid_list_length!()));
                fabric.group_count += 1;
            }

            GroupData::save_to(&mut group, storage_ptr)?;

            if group.first {
                // First group, update fabric
                fabric.first_group = group.group_info.group_id;
            } else {
                // Second to last group, update previous
                let mut prev_group: GroupData = group_data::new_with_ids(fabric_index, group.prev);
                GroupData::load_from(&mut prev_group, storage_ptr)?;
                prev_group.next = group.group_info.group_id;
                GroupData::save_to(&mut prev_group, storage_ptr)?;
            }

            // Update fabric
            FabricData::save_to(&mut fabric, storage_ptr)?;
            self.group_added(fabric_index, &group.group_info);
        }
        chip_ok!()
    }

    fn get_group_info_at(&self, fabric_index: FabricIndex, index: usize) -> Result<GroupInfo, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn remove_group_info_at(&mut self, fabric_index: FabricIndex, index: usize, group_id: GroupId) -> ChipErrorResult {
        chip_ok!()
    }

    // Endpoints
    fn has_endpoint(&self, fabric_index: FabricIndex, group_id: GroupId, endpoint_id: EndpointId) -> bool {
        true
    }

    fn add_endpoint(&mut self, fabric_index: FabricIndex, group_id: GroupId, endpoint_id: EndpointId) -> ChipErrorResult {
        chip_ok!()
    }

    fn remove_endpoint(&mut self, fabric_index: FabricIndex, group_id: Option<GroupId>, endpoint_id: EndpointId) -> ChipErrorResult {
        chip_ok!()
    }

    // Iterators
    fn iter_group_info(&self, fabric_index: FabricIndex) -> Option<Self::GroupInfoIterator> {
        None
    }

    fn iter_endpoints(&self, fabric_index: FabricIndex, group_id: Option<GroupId>) -> Option<Self::EndpointIterator> {
        None
    }

    //
    // Group-Key map
    //
    fn set_group_key_at(&mut self, fabric_index: FabricIndex, index: usize, info: &GroupKey) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_group_key_at(&self, fabric_index: FabricIndex, index: usize) -> Result<GroupKey, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn remove_group_key_at(&mut self, fabric_index: FabricIndex, index: usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn remove_group_keys(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        chip_ok!()
    }

    fn iter_group_keys(&self, fabric_index: FabricIndex) -> Option<Self::GroupKeyIterator> {
        None
    }

    //
    // Key Sets
    //
    fn set_key_set(&mut self, fabric_index: FabricIndex, compressed_fabric_id: &[u8], keys: &KeySet) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_key_set(&self, fabric_index: FabricIndex, keyset_id: KeysetId) -> Result<KeySet, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn remove_key_set(&mut self, fabric_index: FabricIndex, keyset_id: KeysetId) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_ipk_key_set(&self, fabric_index: FabricIndex) -> Result<&KeySet, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn iter_key_sets(&self, fabric_index: FabricIndex) -> Option<Self::KeySetIterator> {
        None
    }

    fn remove_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        chip_ok!()
    }

    fn iter_group_session(&self, session_id: u16) -> Option<Self::GroupSessionIterator> {
        None
    }

    fn get_key_context<C: crate::chip::crypto::SymmetricKeyContext>(&mut self, fabric_index: FabricIndex, group_id: GroupId) -> Result<&C, ChipError> {
        Err(chip_error_not_implemented!())
    }

    fn set_listener(&mut self, listener: Option<NonNull<LIS>>) {
        self.m_listener = listener;
    }

    fn remove_listener(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                support::{
                    test_persistent_storage::TestPersistentStorage,
                },
            },
            crypto::{
                raw_session_keystore::RawKeySessionKeystore,
            },
        },
    };

    struct TestGroupListener {
        pub last_add: Option<(FabricIndex, GroupInfo)>,
        pub last_remove: Option<(FabricIndex, GroupInfo)>,
    }

    impl TestGroupListener {
        const fn new() -> Self {
            Self {
                last_add: None,
                last_remove: None,
            }
        }
    }

    impl GroupListener for TestGroupListener {
        fn on_group_added(&mut self, fabric_index: FabricIndex, new_group: &GroupInfo) {
            self.last_add = Some((fabric_index, new_group.clone()));
        }
        fn on_group_removed(&mut self, fabric_index: FabricIndex, old_group: &GroupInfo) {
            self.last_remove = Some((fabric_index, old_group.clone()));
        }
    }

    type TestGroupDataProvider = GroupDataProviderImpl<TestPersistentStorage, RawKeySessionKeystore, TestGroupListener>;

    #[test]
    fn init() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let mut p = TestGroupDataProvider::new();
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        assert!(p.init().is_ok());
    }

    #[test]
    fn set_group_info_at_successfully() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        let fabric_index: FabricIndex = 1;
        let group_id: GroupId = 1;
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(group_id, "tg");
        assert!(p.set_group_info_at(fabric_index, 0, &group_info).is_ok());
        assert!(l.last_add.is_some_and(|(f, g)| f == fabric_index && g.group_id == group_id));
    }

    #[test]
    fn set_group_info_no_storage() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        //p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        //assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(1, "tg");
        assert!(!p.set_group_info_at(1, 0, &group_info).is_ok());
    }

    #[test]
    fn set_group_info_index_mismatched() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(1, "tg");
        assert!(p.set_group_info_at(1, 0, &group_info).is_ok());
        assert!(!p.set_group_info_at(1, 1, &group_info).is_ok());
    }

    #[test]
    fn set_group_info_set_twice() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(1, "tg");
        assert!(p.set_group_info_at(1, 0, &group_info).is_ok());
        assert!(p.set_group_info_at(1, 0, &group_info).is_ok());
    }

    #[test]
    fn set_group_info_set_different_group() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        let fabric_index: FabricIndex = 1;
        let group_id: GroupId = 1;
        let group_id_2: GroupId = 2;
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(group_id, "tg");
        let group_info_2 = GroupInfo::new_with(group_id_2, "tg");
        assert!(p.set_group_info_at(fabric_index, 0, &group_info).is_ok());
        assert!(p.set_group_info_at(fabric_index, 1, &group_info_2).is_ok());
    }

    #[test]
    fn set_group_info_replace_old_one() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        let fabric_index: FabricIndex = 1;
        let group_id: GroupId = 1;
        let group_id_2: GroupId = 2;
        let group_id_3: GroupId = 3;
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(group_id, "tg");
        let group_info_2 = GroupInfo::new_with(group_id_2, "tg");
        let group_info_3 = GroupInfo::new_with(group_id_3, "tg");
        assert!(p.set_group_info_at(fabric_index, 0, &group_info).is_ok());
        assert!(p.set_group_info_at(fabric_index, 1, &group_info_2).is_ok());
        assert!(p.set_group_info_at(fabric_index, 0, &group_info_3).is_ok());
        assert!(l.last_add.is_some_and(|(f, g)| f == fabric_index && g.group_id == group_id_3));
        assert!(l.last_remove.is_some_and(|(f, g)| f == fabric_index && g.group_id == group_id));
    }

    #[test]
    fn set_group_info_at_index_too_big() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        let fabric_index: FabricIndex = 1;
        let group_id: GroupId = 1;
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        let group_info = GroupInfo::new_with(group_id, "tg");
        assert!(!p.set_group_info_at(fabric_index, 1, &group_info).is_ok());
    }

    #[test]
    fn set_group_info_at_too_much_group() {
        let pa = TestPersistentStorage::default();
        let ks = RawKeySessionKeystore::new();
        let l = TestGroupListener::new();
        let mut p = <TestGroupDataProvider as GroupDataProvider>::new();
        let fabric_index: FabricIndex = 1;
        let group_id: GroupId = 1;
        p.set_session_keystore(Some(NonNull::from_ref(&ks)));
        p.set_storage_delegate(Some(NonNull::from_ref(&pa)));
        p.set_listener(Some(NonNull::from_ref(&l)));
        assert!(p.init().is_ok());
        for index in 0..=p.m_max_groups_per_fabric {
            let group_info = GroupInfo::new_with(group_id + index, "tg");
            if index < p.m_max_groups_per_fabric {
                assert!(p.set_group_info_at(fabric_index, index.into(), &group_info).is_ok());
            } else {
                assert!(!p.set_group_info_at(fabric_index, index.into(), &group_info).is_ok());
            }
        }
    }
} // end of tests
