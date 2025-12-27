use crate::chip::{
    chip_lib::{
        core::{
            chip_persistent_storage_delegate::PersistentStorageDelegate,
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_tags,
            tlv_types::TlvType,
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        },
        support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
    },
    system::system_clock::Seconds32,
};

use crate::chip_core_error;
use crate::chip_error_buffer_too_small;
use crate::chip_error_incorrect_state;
use crate::chip_error_invalid_argument;
use crate::chip_error_persisted_storage_value_not_found;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_progress;
use core::str::FromStr;

use crate::tlv_estimate_struct_overhead;
use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::ptr;

const LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE: usize =
    tlv_estimate_struct_overhead!(core::mem::size_of::<u32>(), core::mem::size_of::<u32>());

fn k_last_known_good_chip_epoch_seconds_tag() -> tlv_tags::Tag {
    tlv_tags::context_tag(0)
}

pub struct LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate,
{
    m_storage: *mut PS,
    m_last_known_good_chip_epoch_time: Option<Seconds32>,
}

impl<PS> Default for LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate,
{
    fn default() -> Self {
        LastKnownGoodTime::<PS>::const_default()
    }
}

impl<PS> LastKnownGoodTime<PS>
where
    PS: PersistentStorageDelegate,
{
    pub const fn const_default() -> Self {
        Self {
            m_storage: ptr::null_mut(),
            m_last_known_good_chip_epoch_time: None,
        }
    }

    pub fn init(&mut self, storage: *mut PS) -> ChipErrorResult {
        self.m_storage = storage;
        // TODO: get build time
        // 3.5.6.1 Last Known Good UTC Time:
        //
        // "A Node’s initial out-of-box Last Known Good UTC time SHALL be the
        // compile-time of the firmware."
        let build_time = Seconds32::from_secs(0);
        let err = self.load_last_known_good_chip_epoch_time();
        let mut stored_last_known_good_chip_epoch_time = Seconds32::from_secs(0);
        match &err {
            Ok(time) => {
                chip_log_progress!(TimeService, "Last Known Good Time {}", time.as_secs());
                stored_last_known_good_chip_epoch_time = *time;
            }
            Err(e) => {
                if *e == chip_error_persisted_storage_value_not_found!() {
                    chip_log_progress!(TimeService, "Last Known Good Time [unknown]");
                } else {
                    chip_log_progress!(
                        TimeService,
                        "Failed to init Last Known Good Time {}",
                        e.format()
                    );
                    return Err(*e);
                }
            }
        }

        if err.is_err_and(|e| e == chip_error_persisted_storage_value_not_found!())
            || build_time > stored_last_known_good_chip_epoch_time
        {
            // If we have no value in persistence, or the firmware build time is
            // later than the value in persistence, set last known good time to the
            // firmware build time and write back.
            chip_log_progress!(
                TimeService,
                "Setting Last Known Good Time to firmware build time {}",
                build_time.as_secs()
            );
            self.m_last_known_good_chip_epoch_time = Some(build_time);
            self.store_last_known_good_chip_epoch_time(build_time)
                .inspect_err(|e| {
                    chip_log_progress!(
                        TimeService,
                        "Failed to init Last Known Good Time {}",
                        e.format()
                    );
                });
        } else {
            self.m_last_known_good_chip_epoch_time = Some(stored_last_known_good_chip_epoch_time);
        }

        chip_ok!()
    }

    pub fn set_last_known_good_chip_epoch_time(
        &mut self,
        last_known_good_chip_epoch_time: Seconds32,
        not_before: Seconds32,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            self.m_last_known_good_chip_epoch_time.is_some(),
            Err(chip_error_incorrect_state!())
        );
        chip_log_progress!(
            TimeService,
            "Last Known Good Time {}",
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .as_secs()
        );
        chip_log_progress!(
            TimeService,
            "New proposed Last Known Good Time {}",
            last_known_good_chip_epoch_time.as_secs()
        );

        // TODO: uncomment this after we have build time
        //VerifyOrExit(lastKnownGoodChipEpochTime >= buildTime, err = CHIP_ERROR_INVALID_ARGUMENT);

        verify_or_return_error!(
            last_known_good_chip_epoch_time >= not_before,
            Err(chip_error_invalid_argument!())
        );

        self.store_last_known_good_chip_epoch_time(last_known_good_chip_epoch_time)
            .inspect_err(|e| {
                chip_log_progress!(
                    TimeService,
                    "Failed to update Last Known Good Time {}",
                    e.format()
                );
            })?;

        self.m_last_known_good_chip_epoch_time = Some(last_known_good_chip_epoch_time);

        chip_log_progress!(
            TimeService,
            "Updating Last Known Good Time {}",
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .as_secs()
        );

        chip_ok!()
    }

    pub fn update_pending_last_known_good_chip_epoch_time(
        &mut self,
        last_known_good_chip_epoch_time: Seconds32,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            self.m_last_known_good_chip_epoch_time.is_some(),
            Err(chip_error_incorrect_state!())
        );
        chip_log_progress!(
            TimeService,
            "Last Known Good Time {}",
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .as_secs()
        );
        chip_log_progress!(
            TimeService,
            "New proposed Last Known Good Time {}",
            last_known_good_chip_epoch_time.as_secs()
        );

        if last_known_good_chip_epoch_time
            > *self.m_last_known_good_chip_epoch_time.as_ref().unwrap()
        {
            chip_log_progress!(
                TimeService,
                "Updating pending Last Known Good Time to {}",
                last_known_good_chip_epoch_time.as_secs()
            );
            self.m_last_known_good_chip_epoch_time = Some(last_known_good_chip_epoch_time);
        } else {
            chip_log_progress!(TimeService, "Retaing current Last Known Good Time");
        }

        chip_ok!()
    }

    pub fn commit_last_known_good_chip_epoch_time(&mut self) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            self.m_last_known_good_chip_epoch_time.is_some(),
            Err(chip_error_incorrect_state!())
        );
        chip_log_progress!(
            TimeService,
            "Commit Last Known Good Time to storage: {}",
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .as_secs()
        );

        self.store_last_known_good_chip_epoch_time(
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .clone(),
        )
        .inspect_err(|e| {
            chip_log_progress!(
                TimeService,
                "Failed to commit Last Known Good Time {}",
                e.format()
            );
        })?;

        chip_ok!()
    }

    pub fn revert_pending_last_known_good_chip_epoch_time(&mut self) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_last_known_good_chip_epoch_time.is_some(),
            Err(chip_error_incorrect_state!())
        );
        chip_log_progress!(
            TimeService,
            "Pending Last Known Good Time {}",
            self.m_last_known_good_chip_epoch_time
                .as_ref()
                .unwrap()
                .as_secs()
        );

        match self.load_last_known_good_chip_epoch_time() {
            Ok(stored_time) => {
                chip_log_progress!(
                    TimeService,
                    "Reverted Last Known Good Time to previsou value {}",
                    stored_time.as_secs()
                );
                self.m_last_known_good_chip_epoch_time = Some(stored_time);

                chip_ok!()
            }
            Err(e) => {
                chip_log_progress!(
                    TimeService,
                    "Clearing Last Known Good Time; failed to load a previous value {}",
                    e.format()
                );
                self.m_last_known_good_chip_epoch_time = Some(Seconds32::from_secs(0));

                Err(e)
            }
        }
    }

    pub fn get_last_known_good_chip_epoch_time(&self) -> Result<Seconds32, ChipError> {
        verify_or_return_error!(
            self.m_last_known_good_chip_epoch_time.is_some(),
            Err(chip_error_incorrect_state!())
        );
        return Ok(self.m_last_known_good_chip_epoch_time.clone().unwrap());
    }

    fn load_last_known_good_chip_epoch_time(&mut self) -> Result<Seconds32, ChipError> {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        let mut buf: [u8; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE] =
            [0; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE];
        let storage: &PS;
        unsafe {
            storage = self.m_storage.as_ref().unwrap();
        }
        let size = storage.sync_get_key_value(
            DefaultStorageKeyAllocator::last_known_good_time_key().key_name_str(),
            &mut buf,
        )?;
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(buf.as_ptr(), size);
        reader.next_type_tag(TlvType::KtlvTypeStructure, tlv_tags::anonymous_tag())?;
        let _container_type = reader.enter_container()?;
        reader.next_tag(k_last_known_good_chip_epoch_seconds_tag())?;
        let seconds = reader.get_u32()?;

        return Ok(Seconds32::from_secs(seconds as u64));
    }

    fn store_last_known_good_chip_epoch_time(
        &mut self,
        last_known_good_chip_epoch_time: Seconds32,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        let mut buf: [u8; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE] =
            [0; LAST_KNOWN_GOOD_TIME_TLV_MAX_SIZE];
        let mut writer = TlvContiguousBufferWriter::const_default();
        writer.init(buf.as_mut_ptr(), buf.len() as u32);
        let mut outer_type = TlvType::KtlvTypeNotSpecified;
        writer.start_container(
            tlv_tags::anonymous_tag(),
            TlvType::KtlvTypeStructure,
            &mut outer_type,
        )?;
        writer.put_u32(
            k_last_known_good_chip_epoch_seconds_tag(),
            last_known_good_chip_epoch_time.as_secs() as u32,
        )?;
        writer.end_container(outer_type)?;

        let length = writer.get_length_written();
        verify_or_return_error!(
            u16::try_from(length).is_ok(),
            Err(chip_error_buffer_too_small!())
        );

        unsafe {
            return self.m_storage.as_mut().unwrap().sync_set_key_value(
                DefaultStorageKeyAllocator::last_known_good_time_key().key_name_str(),
                &buf[0..length],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::chip_lib::support::test_persistent_storage::TestPersistentStorage;
    use core::ptr;

    type LKGT = LastKnownGoodTime<TestPersistentStorage>;

    fn setup(pa: *mut TestPersistentStorage) -> LKGT {
        let mut l = LKGT::default();
        let _ = l.init(pa);
        l
    }

    #[test]
    fn init_with_empty_storeage() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = LKGT::default();
        assert_eq!(true, good_time.init(ptr::addr_of_mut!(pa)).is_ok());
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| 0 == d.as_secs())
        );
    }

    #[test]
    fn store_and_load() {
        // since the init method uses the load&store, it doesn't make sense to test the
        // store&load while we assume they are ok to use.
        // So, just assign the storage pointer directly in this test
        let mut pa = TestPersistentStorage::default();
        let mut good_time = LKGT::default();
        good_time.m_storage = ptr::addr_of_mut!(pa);

        assert_eq!(
            true,
            good_time
                .store_last_known_good_chip_epoch_time(Seconds32::from_secs(123))
                .is_ok()
        );

        let expected_output = Seconds32::from_secs(123);

        assert_eq!(
            true,
            good_time
                .load_last_known_good_chip_epoch_time()
                .is_ok_and(|t| t == expected_output)
        );
    }

    #[test]
    fn load_empty() {
        // since the init method uses the load&store, it doesn't make sense to test the
        // store&load while we assume they are ok to use.
        // So, just assign the storage pointer directly in this test
        let mut pa = TestPersistentStorage::default();
        let mut good_time = LKGT::default();
        good_time.m_storage = ptr::addr_of_mut!(pa);

        assert_eq!(
            false,
            good_time.load_last_known_good_chip_epoch_time().is_ok()
        );
    }

    #[test]
    fn init_with_pre_load_time() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = LKGT::default();

        // pre load the time
        good_time.m_storage = ptr::addr_of_mut!(pa);
        assert_eq!(
            true,
            good_time
                .store_last_known_good_chip_epoch_time(Seconds32::from_secs(123))
                .is_ok()
        );
        let expected_output = Seconds32::from_secs(123);

        assert_eq!(true, good_time.init(ptr::addr_of_mut!(pa)).is_ok());
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| expected_output == d)
        );
    }

    #[test]
    fn set_time() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let expected_output = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(123);

        assert_eq!(
            true,
            good_time
                .set_last_known_good_chip_epoch_time(expected_output.clone(), not_before.clone())
                .is_ok()
        );
    }

    #[test]
    fn set_time_last_than_before() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let expected_output = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(124);

        assert_eq!(
            false,
            good_time
                .set_last_known_good_chip_epoch_time(expected_output.clone(), not_before.clone())
                .is_ok()
        );
    }

    #[test]
    fn update_pending_time() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let first_time = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(123);
        // set first
        assert_eq!(
            true,
            good_time
                .set_last_known_good_chip_epoch_time(first_time.clone(), not_before.clone())
                .is_ok()
        );
        // update
        let expected_output = Seconds32::from_secs(124);
        assert_eq!(
            true,
            good_time
                .update_pending_last_known_good_chip_epoch_time(expected_output.clone())
                .is_ok()
        );
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| expected_output == d)
        );
    }

    #[test]
    fn failed_to_update_pending_time() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let first_time = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(123);
        // set first
        assert_eq!(
            true,
            good_time
                .set_last_known_good_chip_epoch_time(first_time.clone(), not_before.clone())
                .is_ok()
        );
        // update
        let expected_output = Seconds32::from_secs(123);
        // event if the update is not success, the reuslt is ok
        assert_eq!(
            true,
            good_time
                .update_pending_last_known_good_chip_epoch_time(expected_output.clone())
                .is_ok()
        );
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| first_time == d)
        );
    }

    #[test]
    fn revert_to_previous_time() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let first_time = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(123);
        // set first
        assert_eq!(
            true,
            good_time
                .set_last_known_good_chip_epoch_time(first_time.clone(), not_before.clone())
                .is_ok()
        );

        // update
        let expected_output = Seconds32::from_secs(124);
        assert_eq!(
            true,
            good_time
                .update_pending_last_known_good_chip_epoch_time(expected_output.clone())
                .is_ok()
        );

        // revert
        assert_eq!(
            true,
            good_time
                .revert_pending_last_known_good_chip_epoch_time()
                .is_ok()
        );
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| first_time == d)
        );
    }

    #[test]
    fn revert_to_previous_time_failed_to_load() {
        let mut pa = TestPersistentStorage::default();
        let mut good_time = setup(ptr::addr_of_mut!(pa));

        let first_time = Seconds32::from_secs(123);
        let not_before = Seconds32::from_secs(123);
        // set first
        assert_eq!(
            true,
            good_time
                .set_last_known_good_chip_epoch_time(first_time.clone(), not_before.clone())
                .is_ok()
        );

        // update
        let expected_output = Seconds32::from_secs(124);
        assert_eq!(
            true,
            good_time
                .update_pending_last_known_good_chip_epoch_time(expected_output.clone())
                .is_ok()
        );

        // posion the storage
        pa.add_posion_key(DefaultStorageKeyAllocator::last_known_good_time_key().key_name_str());

        // revert
        assert_eq!(
            false,
            good_time
                .revert_pending_last_known_good_chip_epoch_time()
                .is_ok()
        );
        assert_eq!(
            true,
            good_time
                .m_last_known_good_chip_epoch_time
                .is_some_and(|d| 0 == d.as_secs())
        );
    }
} // end of mod tests
