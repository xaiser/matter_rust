use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
            },
            support::default_storage_key_allocator::StorageKeyName,
        },
    },
    ChipError,
    ChipErrorResult,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_invalid_argument,
    chip_error_not_found,
    chip_error_persisted_storage_value_not_found,
    verify_or_return_error,
    verify_or_return_value,
};

use core::ptr::NonNull;
use core::ops::{Deref, DerefMut};

/// @brief Data accessor allowing data to be persisted by PersistentStore to be accessed
pub trait DataAccessor {
    fn update_key(&self) -> Result<StorageKeyName, ChipError>;
    fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult;
    fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult;
    fn clear(&mut self);
}

type BufferWriter = TlvContiguousBufferWriter;
type BufferReader = TlvContiguousBufferReader;

/// @brief Interface to PersistentStorageDelegate allowing storage of data of variable size such as TLV, delegating data access
/// to DataAccessor
/// @tparam kMaxSerializedSize size of the mBuffer necessary to retrieve an entry from the storage. Varies with the type of data
/// stored. Will be allocated on the stack so the implementation needs to be aware of this when choosing this value.
#[derive(Clone)]
pub struct PersistentStore<const KMAX_SERIALIZED_SIZE: usize> {
    m_buffer: [u8; KMAX_SERIALIZED_SIZE],
}

impl<const KMAX_SERIALIZED_SIZE: usize> PersistentStore<KMAX_SERIALIZED_SIZE> {
    pub const fn new() -> Self {
        Self {
            m_buffer: [0u8; KMAX_SERIALIZED_SIZE],
        }
    }

    fn save<T: DataAccessor, PSD: PersistentStorageDelegate>(&mut self, persistent: &T, storage: * mut PSD) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        // Serialize the data
        let mut writer = BufferWriter::default();
        writer.init(self.m_buffer.as_mut_ptr(), self.m_buffer.len() as u32);

        persistent.serialize(&mut writer)?;

        unsafe {
            return storage.as_mut().unwrap().sync_set_key_value(key.key_name_str(), &self.m_buffer[..writer.get_length_written()]);
        }
    }

    fn load<T: DataAccessor, PSD: PersistentStorageDelegate>(&mut self, persistent: &mut T, storage: * mut PSD) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        // Set data to defaults
        persistent.clear();

        let mut read_len: usize = 0;

        // Load the serialized data
        unsafe {
            read_len = storage.as_ref().unwrap().sync_get_key_value(key.key_name_str(), &mut self.m_buffer).map_err(|e| {
                if e == chip_error_persisted_storage_value_not_found!() {
                    chip_error_not_found!()
                } else {
                    e
                }
            })?;
        }

        // Decode serialized data
        let mut reader = BufferReader::default();
        reader.init(self.m_buffer.as_mut_ptr(), read_len);

        persistent.deserialize(&mut reader)
    }

    fn delete<T: DataAccessor, PSD: PersistentStorageDelegate>(&self, persistent: &T, storage: * mut PSD) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        unsafe {
            return storage.as_mut().unwrap().sync_delete_key_value(key.key_name_str());
        }
    }
}

pub struct PersistentData<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> {
    m_storage: Option<NonNull<PSD>>,
    m_store: PersistentStore<KMAX_SERIALIZED_SIZE>,
    m_value: T,
}

impl<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> Deref for PersistentData<T, KMAX_SERIALIZED_SIZE, PSD> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.m_value
    }
}

impl<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> DerefMut for PersistentData<T, KMAX_SERIALIZED_SIZE, PSD> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.m_value
    }
}

impl<T: DataAccessor + Clone, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> Clone for PersistentData<T, KMAX_SERIALIZED_SIZE, PSD> {
    fn clone(&self) -> Self {
        Self {
            m_storage: self.m_storage,
            m_store: self.m_store.clone(),
            m_value: self.m_value.clone(),
        }
    }
}

impl<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> PersistentData<T, KMAX_SERIALIZED_SIZE, PSD> {
    pub const fn new(value: T, storage: Option<NonNull<PSD>>) -> Self {
        Self {
            m_storage: storage,
            m_store: PersistentStore::<KMAX_SERIALIZED_SIZE>::new(),
            m_value: value,
        }
    }

    pub fn save(this: &mut Self) -> ChipErrorResult {
        if let Some(mut storage) = this.m_storage {
            unsafe {
                Self::save_to(this, storage.as_mut())
            }
        } else {
            Err(chip_error_invalid_argument!())
        }
    }

    pub fn save_to<S: PersistentStorageDelegate>(this: &mut Self, storage: * mut S) -> ChipErrorResult {
        this.m_store.save(&this.m_value, storage)
    }

    pub fn load(this: &mut Self) -> ChipErrorResult {
        if let Some(mut storage) = this.m_storage {
            unsafe {
                Self::load_from(this, storage.as_mut())
            }
        } else {
            Err(chip_error_invalid_argument!())
        }
    }

    pub fn load_from<S: PersistentStorageDelegate>(this: &mut Self, storage: * mut S) -> ChipErrorResult {
        this.m_store.load(&mut this.m_value, storage)
    }

    pub fn delete_from<S: PersistentStorageDelegate>(this: &mut Self, storage: * mut S) -> ChipErrorResult {
        this.m_store.delete(&mut this.m_value, storage)
    }

    pub fn as_ref(&self) -> &T {
        &self.m_value
    }

    pub fn as_mut(&mut self) -> &mut T {
        &mut self.m_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, common_tag},
                },
                support::{
                    test_persistent_storage::TestPersistentStorage,
                },
            },
        },
    };

    use core::ptr;

    const MAX_TEST_DATA_SIZE: usize = 64;

    type TestPersistentStore = PersistentStore<MAX_TEST_DATA_SIZE>;
    type TestPersistentData = PersistentData<TestData, MAX_TEST_DATA_SIZE, TestPersistentStorage>;

    struct TestData {
        pub key: Option<StorageKeyName>,
        pub d1: u32,
        pub d2: i8,
    }

    impl TestData {
        const NAME: &str = "123";
        const TAG_NUM: u32 = 0x01;

        pub const fn new() -> Self {
            Self {
                key: None,
                d1: 0,
                d2: 0,
            }
        }

        pub fn new_with(key: &str, d1: u32, d2: i8) -> Self {
            Self {
                key: Some(StorageKeyName::from(key)),
                d1,
                d2,
            }
        }

        pub fn get_tag() -> Tag {
            common_tag(Self::TAG_NUM)
        }
    }

    impl PartialEq for TestData {
        fn eq(&self, other: &Self) -> bool {
            if let (Some(a), Some(b)) = (self.key.as_ref(), other.key.as_ref()) {
                if a.key_name_str() == b.key_name_str() &&
                    self.d1 == other.d1 &&
                        self.d2 == other.d2 {
                            return true;
                }
            }
            false
        }
    }

    impl Eq for TestData {}

    impl DataAccessor for TestData {
        fn update_key(&self) -> Result<StorageKeyName, ChipError> {
            self.key.clone().ok_or(chip_error_invalid_argument!())
        }

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let tag = TestData::get_tag();
            writer.put_string(tag, self.key.as_ref().ok_or(chip_error_invalid_argument!())?.key_name_str())?;
            writer.put_u32(tag, self.d1)?;
            writer.put_i8(tag, self.d2)?;
            chip_ok!()
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            let tag = TestData::get_tag();
            reader.next_tag(tag)?;
            if let Some(name) = reader.get_string()? {
                self.key = Some(StorageKeyName::from(name));
            } else {
                self.key = None;
            }

            reader.next_tag(tag)?;
            self.d1 = reader.get_u32()?;

            reader.next_tag(tag)?;
            self.d2 = reader.get_i8()?;

            chip_ok!()
        }

        fn clear(&mut self) {
            self.key = None;
            self.d1 = 0;
            self.d2 = 0;
        }
    }

    mod persistent_store {
        use super::*;
        use super::super::*;

        #[test]
        fn save_successfully() {
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn save_null_storage() {
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(!store.save(&data, ptr::null_mut::<TestPersistentStorage>()).is_ok());
        }

        #[test]
        fn save_not_key() {
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new();
            assert!(!store.save(&data, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn save_buffer_too_small() {
            let mut storage = TestPersistentStorage::default();
            let mut store = PersistentStore::<1>::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(!store.save(&data, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn load_successfully() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());

            let mut data_2 = TestData::new_with(TestData::NAME, 3, 4);

            assert!(store.load(&mut data_2, ptr::addr_of_mut!(storage)).is_ok());
            assert!(data == data_2);
        }

        #[test]
        fn load_no_storage() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());

            let mut data_2 = TestData::new_with(TestData::NAME, 3, 4);

            assert!(!store.load(&mut data_2, ptr::null_mut::<TestPersistentStorage>()).is_ok());
        }

        #[test]
        fn load_no_key() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());

            let mut data_2 = TestData::new();

            assert!(!store.load(&mut data_2, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn load_not_found() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();

            let mut data_2 = TestData::new_with(TestData::NAME, 3, 4);

            assert!(!store.load(&mut data_2, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn delete_successfully() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());

            assert!(store.delete(&data, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn delete_no_key() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut store = TestPersistentStore::new();
            let data = TestData::new_with(TestData::NAME, 1, 2);
            assert!(store.save(&data, ptr::addr_of_mut!(storage)).is_ok());

            let data = TestData::new();
            assert!(!store.delete(&data, ptr::addr_of_mut!(storage)).is_ok());
        }
    } // end of persistent_store
    
    mod persistent_data {
        use super::*;
        use super::super::*;

        #[test]
        fn save_successfully() {
            let mut storage = TestPersistentStorage::default();
            let mut data = TestPersistentData::new(
                TestData::new_with("123", 1, 2),
                Some(NonNull::from_ref(&storage)),
                );

            assert!(TestPersistentData::save(&mut data).is_ok());
        }

        #[test]
        fn save_to_successfully() {
            let mut storage = TestPersistentStorage::default();
            let mut data = TestPersistentData::new(
                TestData::new_with("123", 1, 2),
                None,
                );

            assert!(TestPersistentData::save_to(&mut data, ptr::addr_of_mut!(storage)).is_ok());
        }

        #[test]
        fn load_successfully() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut data = TestPersistentData::new(
                TestData::new_with("123", 1, 2),
                Some(NonNull::from_ref(&storage)),
                );

            assert!(TestPersistentData::save(&mut data).is_ok());

            let mut data_2 = TestPersistentData::new(
                TestData::new_with("123", 3, 4),
                Some(NonNull::from_ref(&storage)),
                );

            //assert!(data_2.load().is_ok());
            assert!(TestPersistentData::load(&mut data_2).is_ok());

            assert!(*data.as_ref() == *data_2.as_ref());
        }

        #[test]
        fn delete_successfully() {
            // save first
            let mut storage = TestPersistentStorage::default();
            let mut data = TestPersistentData::new(
                TestData::new_with("123", 1, 2),
                Some(NonNull::from_ref(&storage)),
                );

            assert!(TestPersistentData::save(&mut data).is_ok());
            assert!(TestPersistentData::delete_from(&mut data, ptr::addr_of_mut!(storage)).is_ok());
        }
    } // end of persistent data
} // end of tests
