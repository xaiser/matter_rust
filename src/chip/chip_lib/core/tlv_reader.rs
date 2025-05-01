use super::tlv_types::{self, TlvType};
use super::tlv_tags::{self, Tag,TlvCommonProfiles,TLVTagControl};
use super::tlv_backing_store::TlvBackingStore;
use super::tlv_common;
use crate::ChipErrorResult;
use crate::ChipError;

use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;

use core::{fmt,ptr};

pub trait TlvReader {
    type BackingStoreType;

    fn init(&mut self, data: * const u8, data_len: usize);

    fn init_backing_store(&mut self, backing_store: * mut Self::BackingStoreType, max_len: u32) -> ChipErrorResult;

    fn next(&mut self) -> ChipErrorResult;

    fn next_tag(&mut self, expected_tag: Tag) -> ChipErrorResult;

    fn expect(&mut self, expected_tag: Tag) -> ChipErrorResult;

    fn next_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult;

    fn expect_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult;

    fn get_type(&self) -> TlvType;

    fn get_tag(&self) -> Tag;

    fn get_length(&self) -> usize;

    fn get_control_byte(&self) -> u16;

    fn get_boolean(&self) -> Result<bool, ChipError>;

    fn get_i64(&self) -> Result<i64, ChipError>;

    fn get_u64(&self) -> Result<u64, ChipError>;

    fn get_bytes(&mut self, bytes: &mut [u8]) -> ChipErrorResult;

    fn get_string(&mut self, bytes: &mut [u8]) -> ChipErrorResult;

    fn get_data_slice(&self) -> Result<&[u8], ChipError>;

    fn enter_container(&mut self) -> Result<TlvType, ChipError>;

    fn exit_container(&mut self, outer_container_type: TlvType) -> ChipErrorResult;

    fn open_container(&mut self) -> Result<Self, ChipError> where Self: Sized;

    fn close_container(&mut self, reader: Self) -> ChipErrorResult;

    fn get_container_type(&self) -> TlvType;

    fn verify_end_of_container(&mut self) -> ChipErrorResult;

    fn get_backing_store(&mut self) -> * mut Self::BackingStoreType;

    fn get_read_point(&self) -> * const u8;

    fn skip(&mut self) -> ChipErrorResult;

    fn count_remaining_in_container(&self) -> Result<usize, ChipError>;
}

pub struct TlvReaderBasic<BackingStoreType>
    where 
        BackingStoreType: TlvBackingStore,
{
    pub m_implicit_profile_id: u32,
    pub m_app_data: * mut u8,
    m_elem_tag: Tag,
    m_elem_len_or_val: u64,
    m_backing_store: * mut BackingStoreType,
    m_read_point: * const u8,
    m_buf_end: * const u8,
    m_len_read: usize,
    m_max_len: usize,
    m_container_type: TlvType,
    m_control_byte: u16,
    m_container_open: bool,
}

impl<BackingStoreType> TlvReaderBasic<BackingStoreType>
    where 
        BackingStoreType: TlvBackingStore,
{
    pub const fn const_default() -> Self {
        Self {
            m_implicit_profile_id: TlvCommonProfiles::KprofileIdNotSpecified as u32,
            m_app_data: ptr::null_mut(),
            m_elem_tag: tlv_tags::unknown_tag(),
            m_elem_len_or_val: 0,
            m_backing_store: ptr::null_mut(),
            m_read_point: ptr::null_mut(),
            m_buf_end: ptr::null_mut(),
            m_len_read: 0,
            m_max_len: 0,
            m_container_type: TlvType::KtlvTypeNotSpecified,
            m_control_byte: tlv_common::KTLVCONTROL_BYTE_NOT_SPECIFIED,
            m_container_open: false,
        }
    }

    fn clear_element_state(&mut self) {
        self.m_elem_tag = tlv_tags::anonymous_tag();
        self.m_control_byte = tlv_common::KTLVCONTROL_BYTE_NOT_SPECIFIED;
        self.m_elem_len_or_val = 0;
    }

    fn set_container_open(&mut self, open: bool) {
        self.m_container_open = open;
    }
}


impl<BackingStoreType> TlvReader for TlvReaderBasic<BackingStoreType>
    where 
        BackingStoreType: TlvBackingStore
{
    type BackingStoreType = BackingStoreType;

    fn init(&mut self, data: * const u8, data_len: usize) {
        self.m_backing_store = ptr::null_mut();
        self.m_read_point = data;
        unsafe {
            self.m_buf_end = data.add(data_len);
        }
        self.m_len_read = 0;
        self.m_max_len = data_len;
        self.clear_element_state();
        self.m_container_type = TlvType::KtlvTypeNotSpecified;
        self.set_container_open(false);
        self.m_implicit_profile_id = TlvCommonProfiles::KprofileIdNotSpecified as u32;
    }

    fn init_backing_store(&mut self, backing_store: * mut Self::BackingStoreType, max_len: u32) -> ChipErrorResult {
        chip_ok!()
    }

    fn next(&mut self) -> ChipErrorResult {
        chip_ok!()
    }

    fn next_tag(&mut self, expected_tag: Tag) -> ChipErrorResult {
        chip_ok!()
    }

    fn expect(&mut self, expected_tag: Tag) -> ChipErrorResult {
        chip_ok!()
    }

    fn next_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult {
        chip_ok!()
    }

    fn expect_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_type(&self) -> TlvType {
        TlvType::KtlvTypeNotSpecified
    }

    fn get_tag(&self) -> Tag {
        tlv_tags::anonymous_tag()
    }

    fn get_length(&self) -> usize {
        0
    }

    fn get_control_byte(&self) -> u16 {
        tlv_common::KTLVCONTROL_BYTE_NOT_SPECIFIED
    }

    fn get_boolean(&self) -> Result<bool, ChipError> {
        Ok(false)
    }

    fn get_i64(&self) -> Result<i64, ChipError> {
        Ok(0)
    }

    fn get_u64(&self) -> Result<u64, ChipError> {
        Ok(0)
    }

    fn get_bytes(&mut self, bytes: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_string(&mut self, bytes: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_data_slice(&self) -> Result<&[u8], ChipError> {
        Err(chip_error_internal!())
    }

    fn enter_container(&mut self) -> Result<TlvType, ChipError> {
        Ok(TlvType::KtlvTypeNotSpecified)
    }

    fn exit_container(&mut self, outer_container_type: TlvType) -> ChipErrorResult {
        chip_ok!()
    }

    fn open_container(&mut self) -> Result<Self, ChipError> where Self: Sized {
        Err(chip_error_internal!())
    }

    fn close_container(&mut self, reader: Self) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_container_type(&self) -> TlvType {
        TlvType::KtlvTypeNotSpecified
    }

    fn verify_end_of_container(&mut self) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_backing_store(&mut self) -> * mut Self::BackingStoreType {
        ptr::null_mut()
    }

    fn get_read_point(&self) -> * const u8 {
        self.m_read_point
    }

    fn skip(&mut self) -> ChipErrorResult {
        chip_ok!()
    }

    fn count_remaining_in_container(&self) -> Result<usize, ChipError> {
        Ok(0)
    }
}

#[cfg(test)]
mod test {
    use crate::chip::chip_lib::core::tlv_backing_store::TlvBackingStore;

    mod no_backing {
        use super::*;
        use super::super::*;
        use std::*;
        use crate::chip::chip_lib::core::tlv_writer::TlvWriter;

        struct DummyBackStore;
        impl TlvBackingStore for DummyBackStore {
            fn on_init_writer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, _buf: * mut * mut u8, _buf_len: * mut usize) -> ChipErrorResult {
                chip_ok!()
            }

            fn finalize_buffer<TlvWriterType: TlvWriter>(&mut self, _reader: * mut TlvWriterType, _buf: * mut u8, _buf_len: usize) -> ChipErrorResult {
                chip_ok!()
            }

            fn get_new_buffer<TlvWriterType: TlvWriter>(&mut self, _reader: * mut TlvWriterType, _buf: * mut * mut u8, _buf_len: &mut usize) -> ChipErrorResult {
                chip_ok!()
            }

            fn get_new_buffer_will_always_fail(&self) -> bool {
                false
            }
        }

        type TheTlvReader = TlvReaderBasic<DummyBackStore>;

        const THE_BUF_LEN: usize = 32;
        static mut BUFFER: [u8; THE_BUF_LEN] = [0; THE_BUF_LEN];

        fn setup() -> TheTlvReader {
            let mut reader = TheTlvReader::const_default();
            unsafe {
                BUFFER.fill(0);
                reader.init(BUFFER.as_ptr(), THE_BUF_LEN);
            }
            return reader;
        }

        #[test]
        fn init() {
            let reader = setup();
            assert_eq!(1,1);
        }
    }
}
