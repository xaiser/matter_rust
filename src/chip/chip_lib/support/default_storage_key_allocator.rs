use crate::chip::chip_lib::core::chip_persistent_storage_delegate::KKEY_LENGTH_MAX;

use core::fmt::{self, Arguments, Write};

struct StorageKeyName{
    m_key_name_buffer: [u8; KKEY_LENGTH_MAX],
    pos: usize,
}

impl Drop for StorageKeyName {
    fn drop(&mut self) {
        self.m_key_name_buffer = [0; KKEY_LENGTH_MAX];
        self.pos = 0;
    }
}

impl StorageKeyName {
    fn key_name(&self) -> &[u8] {
        return &self.m_key_name_buffer[..];
    }

    fn key_name_raw(&self) -> * const u8 {
        return self.m_key_name_buffer.as_ptr();
    }

    fn is_initialized(&self) -> bool {
        self.m_key_name_buffer[0] != 0
    }

    fn is_uninitialized(&self) -> bool {
        self.m_key_name_buffer[0] == 0
    }
}

impl From<&[u8]> for StorageKeyName {
    fn from(value: &[u8]) -> Self {
        let mut name = StorageKeyName {
            m_key_name_buffer: [0; KKEY_LENGTH_MAX],
        };
        if value.len() == 0 {
            name.m_key_name_buffer[0] = b'\0';
        }

        let size = core::cmp::min(KKEY_LENGTH_MAX - 1, value.len());
        name.m_key_name_buffer[0..size].copy_from_slice(&value[0..size]);
        name.m_key_name_buffer[size] = b'\0';
        return name;
    }
}

impl Write for StorageKeyName {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let to_copy = bytes.len().min(KKEY_LENGTH_MAX);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        // break the build to know whwre to start next time.
        akldjfpoia
        Ok(())
    }
}
