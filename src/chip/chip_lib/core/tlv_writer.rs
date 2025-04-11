use super::tlv_backing_store::TlvBackingStore;
use super::tlv_types::TlvType;
use super::tlv_tags::{Tag,TlvCommonProfiles};

use crate::ChipErrorResult;
use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;
use crate::chip_error_incorrect_state;
use crate::chip_error_tlv_container_open;
use crate::chip_error_no_memory;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::ptr;

pub trait TlvWriter {
}

pub struct TlvWriterBasic<BackingStoreType> 
where
    BackingStoreType: TlvBackingStore,
{
    pub m_app_data: * mut u8,
    pub m_implicit_profile_id: u32,
    m_backing_store: * mut BackingStoreType,
    m_buf_start: * mut u8,
    m_write_point: * mut u8,
    m_remaining_len: usize,
    m_len_written: usize,
    m_max_len: usize,
    m_reserved_size: usize,
    m_container_type: TlvType,
    m_initiialization_cookie: u16,
    m_container_open: bool,
    m_close_container_recerved: bool,
}

impl<BackingStoreType> TlvWriter for TlvWriterBasic<BackingStoreType>
where
    BackingStoreType: TlvBackingStore,
{}


impl<BackingStoreType> TlvWriterBasic<BackingStoreType> 
where
    BackingStoreType: TlvBackingStore,
{
    pub const KEXPECTED_INITIALIZATION_COOKIE: u16 = 0x52b1;

    pub const fn const_default() -> Self {
        Self {
            m_app_data: ptr::null_mut(),
            m_implicit_profile_id: TlvCommonProfiles::KprofileIdNotSpecified as u32,
            m_backing_store: ptr::null_mut(),
            m_buf_start: ptr::null_mut(),
            m_write_point: ptr::null_mut(),
            m_remaining_len: 0,
            m_len_written: 0,
            m_max_len: 0,
            m_reserved_size: 0,
            m_container_type: TlvType::KtlvTypeNotSpecified,
            m_initiialization_cookie: 0,
            m_container_open: false,
            m_close_container_recerved: true,
        }
    }

    pub fn init(&mut self, buf: * mut u8, max_len: u32) {
        let actual_max_len: usize = if max_len > u32::MAX { u32::MAX as usize } else { max_len as usize };

        self.m_buf_start = buf;
        self.m_initiialization_cookie = 0;
        self.m_backing_store = ptr::null_mut();
        self.m_write_point = buf;
        self.m_remaining_len = actual_max_len;
        self.m_len_written = 0;
        self.m_max_len = actual_max_len;
        self.m_container_type = TlvType::KtlvTypeNotSpecified;
        self.m_reserved_size = 0;
        self.m_implicit_profile_id = TlvCommonProfiles::KprofileIdNotSpecified.into();

        self.set_container_open(false);
        self.set_close_container_reserved(true);

        self.m_initiialization_cookie = Self::KEXPECTED_INITIALIZATION_COOKIE;
    }

    pub fn init_backing_store(&mut self, backing_store: * mut BackingStoreType, max_len: u32) -> ChipErrorResult {
        self.init(ptr::null_mut(), max_len);
        self.m_initiialization_cookie = 0;

        self.m_backing_store = backing_store;
        self.m_buf_start = ptr::null_mut();
        self.m_remaining_len = 0;
        unsafe {
            (*self.m_backing_store).on_init_writer(self as * mut Self, ptr::addr_of!(self.m_buf_start), ptr::addr_of_mut!(self.m_remaining_len))?;
        }

        verify_or_return_error!(self.m_buf_start.is_null() == false, Err(chip_error_internal!()));
        self.m_write_point = self.m_buf_start;
        self.m_initiialization_cookie = Self::KEXPECTED_INITIALIZATION_COOKIE;
        chip_ok!()
    }

    pub fn is_initialized(&self) -> bool {
        return self.m_initiialization_cookie == Self::KEXPECTED_INITIALIZATION_COOKIE;
    }

    pub fn finalize(&mut self) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        if self.is_container_open() {
            return Err(chip_error_tlv_container_open!());
        }
        if self.m_backing_store.is_null() == false {
            unsafe {
                return (*self.m_backing_store).finalize_buffer(self as * mut Self, self.m_buf_start, self.m_write_point.offset_from(self.m_buf_start).try_into().unwrap());
            }
        }
        chip_ok!()
    }

    pub fn reserve_buffer(&mut self, buffer_size: usize) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(self.m_remaining_len >= buffer_size, Err(chip_error_incorrect_state!()));

        if self.m_backing_store.is_null() == false {
            unsafe {
                verify_or_return_error!((*self.m_backing_store).get_new_buffer_will_always_fail(), Err(chip_error_incorrect_state!()));
            }
        }

        self.m_reserved_size += buffer_size;
        self.m_remaining_len -= buffer_size;

        chip_ok!()
    }

    pub fn put_boolean(&mut self, tag: Tag, v: bool) -> ChipErrorResult {
        chip_ok!()
    }

    fn is_container_open(&self) -> bool {
        self.m_container_open
    }

    fn set_container_open(&mut self, container_open: bool) {
        self.m_container_open = container_open;
    }

    fn set_close_container_reserved(&mut self, close_container_reserved: bool) {
        self.m_close_container_recerved = close_container_reserved;
    }
}
