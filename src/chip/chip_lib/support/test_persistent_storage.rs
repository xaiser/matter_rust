// A RAM implementation for unit test.

use crate::chip::chip_lib::core::chip_persistent_storage_delegate::PersistentStorageDelegate;

use crate::chip_core_error;
use crate::chip_error_internal;
use crate::chip_no_error;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_error_buffer_too_small;
use crate::chip_error_invalid_argument;
use crate::chip_error_persisted_storage_failed;
use crate::chip_error_persisted_storage_value_not_found;

use crate::verify_or_die;
use crate::verify_or_return_error;
use crate::verify_or_return_value;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;

use std::collections::{HashMap, HashSet};

#[derive(Default)]
struct TestPersistentStorage {
    m_storage: HashMap<String, Vec<u8>>,
    m_poison_keys: HashSet<String>,
    m_reject_writes: bool,
}

impl TestPersistentStorage {
    fn sync_set_key_value_raw_internal(
        &mut self,
        key_string: &str,
        buffer: *const u8,
        size: usize,
    ) -> ChipErrorResult {
        let key = key_string.to_string();
        if self.m_reject_writes || self.m_poison_keys.get(&key).is_some() {
            return Err(chip_error_persisted_storage_failed!());
        }

        // Handle empty values
        if buffer.is_null() {
            if size == 0 {
                if let Some(value) = self.m_storage.get_mut(&key) {
                    value.clear();
                }
                return chip_ok!();
            }

            return Err(chip_error_invalid_argument!());
        }
        // Handle non-empty values
        self.m_storage.insert(key.clone(), Vec::new());
        unsafe {
            if let Some(value) = self.m_storage.get_mut(&key) {
                for i in 0..size {
                    value.push(buffer.add(i).read());
                }
            }
        }

        chip_ok!()
    }

    fn sync_get_key_value_raw_internal(
        &self,
        key_string: &str,
        buffer: *mut u8,
        size: &mut usize,
    ) -> ChipErrorResult {
        // if the size is 0, the buffer must be null, this is equal to
        // if buffer.is_null() && size != 0 { return errror }
        verify_or_return_error!(
            !buffer.is_null() || *size == 0,
            Err(chip_error_invalid_argument!())
        );

        let key = key_string.to_string();

        // Making sure poison keys are not accessed
        if self.m_poison_keys.get(&key).is_some() {
            return Err(chip_error_persisted_storage_failed!());
        }

        if let Some(value) = self.m_storage.get(&key) {
            let value_size = value.len();
            if u16::try_from(value_size).is_err() {
                return Err(chip_error_persisted_storage_failed!());
            }
            let value_size_unit16 = value_size as u16;
            if *size == 0 && value_size_unit16 == 0 {
                return chip_ok!();
            }
            verify_or_return_error!(!buffer.is_null(), Err(chip_error_buffer_too_small!()));
            let size_to_copy = std::cmp::min(*size, value_size_unit16 as usize);
            *size = size_to_copy;
            unsafe {
                for i in 0..size_to_copy {
                    buffer.add(i).write(value[i]);
                }
            }
            if *size < value_size_unit16 as usize {
                return Err(chip_error_buffer_too_small!());
            }
            return chip_ok!();
        } else {
            return Err(chip_error_persisted_storage_value_not_found!());
        }
    }

    fn sync_delete_key_value_internal(&mut self, key_string: &str) -> ChipErrorResult {
        let key = key_string.to_string();
        if self.m_reject_writes || self.m_poison_keys.get(&key).is_some() {
            return Err(chip_error_persisted_storage_failed!());
        }

        if let Some(value) = self.m_storage.get(&key) {
            self.m_storage.remove(&key);
            return chip_ok!();
        } else {
            return Err(chip_error_persisted_storage_value_not_found!());
        }
    }

    pub fn add_posion_key(&mut self, key_string: &str) {
        self.m_poison_keys.insert(key_string.to_string());
    }

    pub fn clear_posion_key(&mut self) {
        self.m_poison_keys.clear();
    }
}

impl PersistentStorageDelegate for TestPersistentStorage {
    fn sync_get_key_value_raw(
        &self,
        key: &str,
        buffer: *mut u8,
        size: &mut usize,
    ) -> ChipErrorResult {
        chip_log_detail!(Test, "test peresisted storage: get key value {}", key);
        return self.sync_get_key_value_raw_internal(key, buffer, size);
    }

    fn sync_get_key_value(&self, key: &str, buffer: &mut [u8]) -> Result<usize, ChipError> {
        let mut size = buffer.len();
        self.sync_get_key_value_raw(key, buffer.as_mut_ptr(), &mut size)
            .map_err(|e| e)?;

        return Ok(size);
    }

    fn sync_set_key_value_raw(
        &mut self,
        key: &str,
        buffer: *const u8,
        size: usize,
    ) -> ChipErrorResult {
        chip_log_detail!(Test, "test peresisted storage: set key value {}", key);

        return self.sync_set_key_value_raw_internal(key, buffer, size);
    }

    fn sync_set_key_value(&mut self, key: &str, buffer: &[u8]) -> ChipErrorResult {
        return self.sync_set_key_value_raw(key, buffer.as_ptr(), buffer.len());
    }

    fn sync_delete_key_value(&mut self, key: &str) -> ChipErrorResult {
        chip_log_detail!(Test, "test peresisted storage: delete key value {}", key);
        return self.sync_delete_key_value_internal(key);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    fn setup() -> TestPersistentStorage {
        TestPersistentStorage::default()
    }

    #[test]
    fn set_key_value_not_existed() {
        let mut p = TestPersistentStorage::default();
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
    }

    #[test]
    fn set_key_value_not_existed_twice() {
        let mut p = TestPersistentStorage::default();
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
        assert_eq!(true, p.sync_set_key_value("k2", &[2]).is_ok());
    }

    #[test]
    fn set_key_value_existed() {
        let mut p = TestPersistentStorage::default();
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
        assert_eq!(true, p.sync_set_key_value("k1", &[2]).is_ok());
    }

    #[test]
    fn get_key_value_not_existed() {
        let p = TestPersistentStorage::default();
        let mut buffer: [u8; 10] = [0; 10];
        assert_eq!(true, p.sync_get_key_value("k1", &mut buffer[..1]).is_err());
    }

    #[test]
    fn get_key_value_existed() {
        let mut p = TestPersistentStorage::default();
        let mut buffer: [u8; 10] = [0; 10];
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
        assert_eq!(true, p.sync_get_key_value("k1", &mut buffer[..1]).is_ok());
        assert_eq!(1, buffer[0]);
    }

    #[test]
    fn get_key_value_existed_twice() {
        let mut p = TestPersistentStorage::default();
        let mut buffer: [u8; 10] = [0; 10];
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
        assert_eq!(true, p.sync_get_key_value("k1", &mut buffer[..1]).is_ok());
        assert_eq!(1, buffer[0]);
        assert_eq!(true, p.sync_get_key_value("k1", &mut buffer[1..2]).is_ok());
        assert_eq!(1, buffer[1]);
    }

    #[test]
    fn delete_key_value_not_existed() {
        let mut p = TestPersistentStorage::default();
        let mut buffer: [u8; 10] = [0; 10];
        assert_eq!(true, p.sync_delete_key_value("k1").is_err());
    }

    #[test]
    fn delete_key_value_existed() {
        let mut p = TestPersistentStorage::default();
        let mut buffer: [u8; 10] = [0; 10];
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_ok());
        assert_eq!(true, p.sync_delete_key_value("k1").is_ok());
        assert_eq!(true, p.sync_get_key_value("k1", &mut buffer[..1]).is_err());
    }

    #[test]
    fn set_key_value_poisoned() {
        let mut p = TestPersistentStorage::default();
        p.add_posion_key("k1");
        assert_eq!(true, p.sync_set_key_value("k1", &[1]).is_err());
    }
}
