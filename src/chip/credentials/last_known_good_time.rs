use crate::chip::{
    system::system_clock::Seconds32,
    chip_lib::{
        core::{
            chip_persistent_storage_delegate::PersistentStorageDelegate,
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
            tlv_types::TlvType,
            tlv_tags,
        },
        support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
    }
};

use crate::chip_core_error;
use crate::chip_error_buffer_too_small;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;
use crate::chip_error_incorrect_state;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::tlv_estimate_struct_overhead;

use core::ptr;

const LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE: usize = tlv_estimate_struct_overhead!(core::mem::size_of::<u32>(), core::mem::size_of::<u32>());

fn k_last_known_good_chip_epoch_seconds_tag() -> tlv_tags::Tag {
    tlv_tags::context_tag(0)
}

struct LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate,
{
    m_storage: *mut PS,
    m_last_known_good_chip_epoch_time: Option<Seconds32>,
}


impl<PS> Default for LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate
{
    fn default() -> Self {
        Self::<PS>::const_default()
    }
}


impl<PS> LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate
{
    pub const fn const_default() -> Self {
        Self {
            m_storage: ptr::mut_null(),
            m_last_known_good_chip_epoch_time = None;
        }
    }

    pub fn init(&mut self, storage: * mut PS) -> ChipErrorResult {
        // TODO: get build time
        // 3.5.6.1 Last Known Good UTC Time:
        //
        // "A Node’s initial out-of-box Last Known Good UTC time SHALL be the
        // compile-time of the firmware."
    }

    pub fn get_last_known_good_chip_epoch_time(&self) -> Result<Seconds32, ChipError> {
        verify_or_return_error!(self.m_last_known_good_chip_epoch_time.is_some(), Err(chip_error_incorrect_state!()));
        return Ok(self.m_last_known_good_chip_epoch_time.clone().unwrap());
    }

    fn load_last_known_good_chip_epoch_time(&mut self) -> Result<Seconds32, ChipError> {
        verify_or_return_error!(!self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        let buf: [u8; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE] = [0; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE];
        let storage: &PS;
        unsafe {
            storage = self.m_storage.as_ref().unwrap();
        }
        let size = storage.sync_get_key_value(DefaultStorageKeyAllocator::last_known_good_time_key().key_name_str(), &mut buf)?;
        let reader = TlvContiguousBufferReader::default();
        reader.init(buf.as_ptr(), size);
        reader.next_type_tag(TlvType::KtlvTypeStructure, tlv_tags::anonymous_tag())?;
        let _container_type = reader.enter_container()?;
        reader.next_tag(k_last_known_good_chip_epoch_seconds_tag())?;
        let seconds = reader.get_u32()?;

        return Ok(Seconds32::from_secs(seconds as u64));
    }

    fn store_last_known_good_chip_epoch_time(&mut self, last_known_good_chip_epoch_time: Seconds32) -> ChipErrorResult {
        verify_or_return_error!(!self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        let mut buf: [u8; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE] = [0; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE];
        let writer = TlvContiguousBufferWriter::default();
        writer.init(buf.as_ptr_mut(), buf.len());
        let mut outer_type = TlvType::KtlvTypeNotSpecified;
        writer.start_container(tlv_tag::anonymous_tag(), TlvType::KtlvTypeStructure, &mut outer_type)?;
        writer.put_u32(k_last_known_good_chip_epoch_seconds_tag(), last_known_good_chip_epoch_time.as_secs() as u32)?;
        writer.end_container(outer_type)?;

        let length = writer.get_length_written();
        verify_or_return_error!(u16::from(length).is_ok(), Err(chip_error_buffer_too_small!()));

        unsafe {
            return self.m_storage.as_mut().unwrap().sync_set_key_value(DefaultStorageKeyAllocator::last_known_good_time_key().key_name_str(), &buf[0..length]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::chip::chip_lib::support::test_persistent_storage::TestPersistentStorage;

    type LKGT = LastKnownGoodTime<TestPersistentStorage>;

    fn setup(pa: *mut TestPersistentStorage) -> LKGT {
        let mut l = LKGT::default();
        //let _ = store.init(pa);
        l
    }

    #[test]
    fn init() {
        let mut pa = TestPersistentStorage::default();
        let mut store = Store::default();
        assert_eq!(true, store.init(ptr::addr_of_mut!(pa)).is_ok());
    }
} // end of mod tests
