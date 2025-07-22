use crate::ChipErrorResult;
use crate::ChipError;
use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;
use crate::chip_no_error;

use crate::chip_error_buffer_too_small;

pub const KKEY_LENGTH_MAX: usize = 32;

pub trait PersistentStorageDelegate {
    fn sync_get_key_value_raw(&self, key: &str, buffer: * mut u8, size: &mut usize) -> ChipErrorResult;
    fn sync_get_key_value(&self, key: &str, buffer: &mut [u8]) -> Result<usize, ChipError>;
    fn sync_set_key_value_raw(&mut self, key: &str, buffer: * const u8, size: usize) -> ChipErrorResult;
    fn sync_set_key_value(&mut self, key: &str, buffer: &[u8]) -> ChipErrorResult;
    fn sync_delete_key_value(&mut self, key: &str) -> ChipErrorResult;
    fn sync_does_key_exist(&self, key: &str) -> bool {
        let mut buf: [u8; 1] = [0];
        let err = self.sync_get_key_value(key, &mut buf[..]);

        return (err.is_ok()) || (err.is_err_and(|e| e == chip_error_buffer_too_small!()));
    }
}
