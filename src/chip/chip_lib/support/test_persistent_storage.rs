// A RAM implementation for unit test.

use crate::chip::chip_lib::core::chip_persistent_storage_delegate::PersistentStorageDelegate;

use crate::ChipErrorResult;
use crate::ChipError;
use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;
use crate::chip_no_error;

use crate::chip_error_invalid_argument;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::verify_or_die;

use std::collections::{HashMap, HashSet};

#[derive(Default)]
struct TestPersistentStorage
{
   m_storage: HashMap<String, Vec<u8>>,
   m_poison_keys: HashSet<String>,
   m_reject_writes: bool,
}

impl TestPersistentStorage {
    fn sync_get_key_value_raw_internal(&self, key: &str, buffer: * mut u8, size: &mut usize) -> ChipErrorResult {
        // if the size is 0, the buffer must be null, this is equal to 
        // if buffer.is_null() && size != 0 { return errror }
        verify_or_return_error!(!buffer.is_null() || size == 0, Err(chip_error_invalid_argument!()));

        // Making sure poison keys are not accessed
        if self.m_poison_keys.get(key.to_string().is_some() {
        }
        chip_ok!()
    }
}

impl PersistentStorageDelegate for TestPersistentStorage {
    fn sync_get_key_value_raw(&self, key: &str, buffer: * mut u8, size: &mut usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn sync_get_key_value(&self, key: &str, buffer: &mut [u8]) -> Result<usize, ChipError> {
        Err(chip_error_internal!())
    }

    fn sync_set_key_value_raw(&mut self, key: &str, buffer: * const u8, size: usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn sync_set_key_valule(&mut self, key: &str, buffer: &[u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn sync_delete_key_value(&mut self, key: &str) -> ChipErrorResult {
        chip_ok!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    #[test]
    fn init() {
        let p = TestPersistentStorage::default();
        assert!(true);
    }
}
