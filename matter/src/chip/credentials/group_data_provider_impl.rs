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

    type PersistentFabricData<S: PersistentStorageDelegate> = PersistentData<FabricData, K_PERSISTENT_BUFFER_MAX, S>;

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

    type PersistentGroupData<PSD> = PersistentData<GroupData, K_PERSISTENT_BUFFER_MAX, PSD>;

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

    type PersistentEndpointData<S> = PersistentData<EndpointData, K_PERSISTENT_BUFFER_MAX, S>;

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
        chip_error_internal,
        /*
        chip_error_not_found,
        chip_ok,
        */
    };
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

        pub const fn new_with_fabic_keyset(fabric: FabricIndex, id: KeysetId) -> Self {
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
    }
} // end of key_set_data

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
