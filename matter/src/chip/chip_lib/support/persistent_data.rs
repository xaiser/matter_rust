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

    fn delete<T: DataAccessor, PSD: PersistentStorageDelegate>(&self, persistent: &mut T, storage: * mut PSD) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        unsafe {
            return storage.as_mut().unwrap().sync_delete_key_value(key.key_name_str());
        }
    }
}

pub struct PersistentData<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> {
    m_storage: Option<NonNull<PSD>>,
    //m_buffer: [u8; KMAX_SERIALIZED_SIZE],
    m_store: PersistentStore<KMAX_SERIALIZED_SIZE>,
    m_value: T,
}

impl<T: DataAccessor, const KMAX_SERIALIZED_SIZE: usize, PSD: PersistentStorageDelegate> PersistentData<T, KMAX_SERIALIZED_SIZE, PSD> {
    pub const fn new(value: T, storage: Option<NonNull<PSD>>) -> Self {
        Self {
            m_storage: storage,
            m_store: PersistentStore::<KMAX_SERIALIZED_SIZE>::new(),
            m_value: value,
        }
    }

    pub fn save(&mut self) -> ChipErrorResult {
        if let Some(mut storage) = self.m_storage {
            unsafe {
                self.save_to(storage.as_mut())
            }
        } else {
            Err(chip_error_invalid_argument!())
        }
    }

    pub fn save_to(&mut self, storage: * mut PSD) -> ChipErrorResult {
        //Self::save_common(&self.m_value, storage, &mut self.m_store)
        self.m_store.save(&self.m_value, storage)
    }

    pub fn load(&mut self) -> ChipErrorResult {
        if let Some(mut storage) = self.m_storage {
            unsafe {
                self.load_from(storage.as_mut())
            }
        } else {
            Err(chip_error_invalid_argument!())
        }
    }

    pub fn load_from(&mut self, storage: * mut PSD) -> ChipErrorResult {
        //Self::load_common(&mut self.m_value, storage, &mut self.m_store)
        self.m_store.load(&mut self.m_value, storage)
    }

    pub fn delete_from(&mut self, storage: * mut PSD) -> ChipErrorResult {
        //Self::delete_common(&mut self.m_value, storage)
        self.m_store.delete(&mut self.m_value, storage)
    }

    pub fn as_ref(&self) -> &T {
        &self.m_value
    }

    pub fn as_mut(&mut self) -> &mut T {
        &mut self.m_value
    }

    /*
    fn save_common(persistent: &T, storage: * mut PSD, buffer: &mut [u8]) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        // Serialize the data
        let mut writer = BufferWriter::default();
        writer.init(buffer.as_mut_ptr(), buffer.len() as u32);

        persistent.serialize(&mut writer)?;

        unsafe {
            return storage.as_mut().unwrap().sync_set_key_value(key.key_name_str(), &buffer[..writer.get_length_written()]);
        }
    }

    fn load_common(persistent: &mut T, storage: * mut PSD, buffer: &mut [u8]) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        // Set data to defaults
        persistent.clear();

        // Load the serialized data
        unsafe {
            storage.as_ref().unwrap().sync_get_key_value(key.key_name_str(), buffer).map_err(|e| {
                if e == chip_error_persisted_storage_value_not_found!() {
                    chip_error_not_found!()
                } else {
                    e
                }
            })?;
        }

        // Decode serialized data
        let mut reader = BufferReader::default();
        reader.init(buffer.as_mut_ptr(), buffer.len());

        persistent.deserialize(&mut reader)
    }

    fn delete_common(persistent: &mut T, storage: * mut PSD) -> ChipErrorResult {
        verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));

        let key = persistent.update_key()?;

        unsafe {
            return storage.as_mut().unwrap().sync_delete_key_value(key.key_name_str());
        }
    }
    */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init() {
        assert!(false);
    }
} // end of tests
