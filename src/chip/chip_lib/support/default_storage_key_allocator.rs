use crate::chip::chip_lib::core::{
    chip_persistent_storage_delegate::KKEY_LENGTH_MAX, data_model_types::FabricIndex,
};

use core::fmt::{self, Arguments, Write};

pub struct StorageKeyName {
    m_key_name_buffer: [u8; KKEY_LENGTH_MAX],
    len: Option<usize>,
}

impl Default for StorageKeyName {
    fn default() -> Self {
        StorageKeyName {
            m_key_name_buffer: [0; KKEY_LENGTH_MAX],
            len: None,
        }
    }
}

impl Drop for StorageKeyName {
    fn drop(&mut self) {
        self.m_key_name_buffer = [0; KKEY_LENGTH_MAX];
        self.len = None;
    }
}

impl StorageKeyName {
    pub fn key_name(&self) -> &[u8] {
        if let Some(len) = self.len {
            return &self.m_key_name_buffer[..len];
        } else {
            return &[];
        }
    }

    pub fn key_name_str(&self) -> &str {
        str::from_utf8(self.key_name()).unwrap_or(&"")
    }

    pub fn key_name_raw(&self) -> (*const u8, usize) {
        if let Some(len) = self.len {
            return (self.m_key_name_buffer.as_ptr(), len);
        } else {
            return (core::ptr::null(), 0);
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.len.is_some()
    }

    pub fn is_uninitialized(&self) -> bool {
        !self.is_initialized()
    }

    pub fn formatted(arg: Arguments) -> Self {
        let mut name = Self::default();

        write!(&mut name, "{}", arg).unwrap();

        return name;
    }
}

impl From<&[u8]> for StorageKeyName {
    fn from(value: &[u8]) -> Self {
        let mut name = StorageKeyName::default();

        if value.len() == 0 {
            name.len = Some(0);
            return name;
        }

        let size = core::cmp::min(KKEY_LENGTH_MAX, value.len());
        name.m_key_name_buffer[0..size].copy_from_slice(&value[0..size]);
        name.len = Some(size);
        return name;
    }
}

impl From<&str> for StorageKeyName {
    fn from(value: &str) -> Self {
        let mut name = StorageKeyName::default();

        if value.len() == 0 {
            name.len = Some(0);
            return name;
        }

        let size = core::cmp::min(KKEY_LENGTH_MAX, value.len());
        name.m_key_name_buffer[0..size].copy_from_slice(&value.as_bytes()[0..size]);
        name.len = Some(size);
        return name;
    }
}

impl Write for StorageKeyName {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let current_len_ref = self.len.get_or_insert(0);
        let current_len = *current_len_ref;
        let bytes = s.as_bytes();
        let to_copy = bytes.len().min(self.m_key_name_buffer.len() - current_len);
        self.m_key_name_buffer[current_len..current_len + to_copy]
            .copy_from_slice(&bytes[..to_copy]);
        *current_len_ref += to_copy;
        Ok(())
    }
}

pub struct DefaultStorageKeyAllocator;

impl DefaultStorageKeyAllocator {
    pub fn fabric_index_info() -> StorageKeyName {
        StorageKeyName::from("g/fidx")
    }

    pub fn fabric_noc(index: FabricIndex) -> StorageKeyName {
        StorageKeyName::formatted(format_args!("f/{}/n", index))
    }

    pub fn fabric_op_key(index: FabricIndex) -> StorageKeyName {
        StorageKeyName::formatted(format_args!("f/{}/o", index))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod storage_key_name {
        use super::super::*;

        #[test]
        fn init() {
            let name = StorageKeyName::default();
            assert_eq!(true, name.is_uninitialized());
        }

        #[test]
        fn write_string() {
            let name = StorageKeyName::formatted(format_args!("{} is {}", 'a', 'b'));
            assert_eq!(b"a is b", name.key_name());
        }

        #[test]
        fn write_u8_array() {
            let name = StorageKeyName::from(&b"a is b"[..]);
            assert_eq!(b"a is b", name.key_name());
        }

        #[test]
        fn write_str() {
            let name = StorageKeyName::from("a is b");
            assert_eq!(b"a is b", name.key_name());
        }

        #[test]
        fn get_string() {
            let name = StorageKeyName::formatted(format_args!("{} is {}", 'a', 'b'));
            assert_eq!("a is b", name.key_name_str());
        }
    } // end of storage key name test

    mod default_storage_key_alloc {
        use super::super::*;

        #[test]
        fn fabric_noc() {
            let name = DefaultStorageKeyAllocator::fabric_noc(0);
            assert_eq!(b"f/0/n", name.key_name());
        }
    } // end of default_storage_key_alloc
}
