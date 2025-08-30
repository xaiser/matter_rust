#![allow(dead_code)]

use super::tlv_backing_store::TlvBackingStore;
use super::tlv_tags;
use super::tlv_tags::{TLVTagControl, Tag, TlvCommonProfiles};
use super::tlv_types;
use super::tlv_types::{TLVFieldSize, TLVTypeMask, TlvElementType, TlvType};

use crate::chip::chip_lib::support::buffer_writer::little_endian::BufferWriter as LittleEndianBufferWriter;
use crate::chip::chip_lib::support::buffer_writer::BufferWriter;

use crate::chip_core_error;
use crate::chip_error_buffer_too_small;
use crate::chip_error_incorrect_state;
use crate::chip_error_internal;
use crate::chip_error_invalid_argument;
use crate::chip_error_invalid_tlv_tag;
use crate::chip_error_message_too_long;
use crate::chip_error_no_memory;
use crate::chip_error_tlv_container_open;
use crate::chip_error_wrong_tlv_type;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::ChipErrorResult;

use crate::verify_or_die;
use crate::verify_or_return_error;
use crate::verify_or_return_value;

/*
use core::str::FromStr;
use crate::chip_log_detail;
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
*/

use core::{fmt, ptr};

mod private {
    use core::fmt::{self, Write};

    pub const KEND_OF_CONTAINER_MARKER_SIZE: usize = 1;

    pub struct StrWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }

    impl<'a> Write for StrWriter<'a> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            if self.pos + bytes.len() > self.buf.len() {
                return Err(fmt::Error);
            }
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            Ok(())
        }
    }

    pub fn format_args_to_str<'a>(
        buf: &'a mut [u8],
        args: fmt::Arguments<'_>,
    ) -> Result<&'a str, fmt::Error> {
        let mut writer = StrWriter { buf, pos: 0 };
        write!(&mut writer, "{}", args)?;
        core::str::from_utf8(&writer.buf[..writer.pos]).map_err(|_| fmt::Error)
    }
}

pub struct TlvWriterInitParams<BackingStoreType> {
    pub m_implicit_profile_id: u32,
    pub m_backing_store: *mut BackingStoreType,
    pub m_buf_start: *mut u8,
    pub m_write_point: *mut u8,
    pub m_remaining_len: usize,
    pub m_len_written: usize,
    pub m_max_len: usize,
    pub m_container_type: TlvType,
    pub m_initiialization_cookie: u16,
    pub m_container_open: bool,
    pub m_close_container_recerved: bool,
}

impl<BackingStoreType> Default for TlvWriterInitParams<BackingStoreType> {
    fn default() -> Self {
        TlvWriterInitParams {
            m_implicit_profile_id: 0,
            m_backing_store: ptr::null_mut(),
            m_buf_start: ptr::null_mut(),
            m_write_point: ptr::null_mut(),
            m_remaining_len: 0,
            m_len_written: 0,
            m_max_len: 0,
            m_container_type: TlvType::KtlvTypeNotSpecified,
            m_initiialization_cookie: 0,
            m_container_open: false,
            m_close_container_recerved: true,
        }
    }
}

pub trait TlvWriter {
    type BackingStoreType;
    fn init_with_params(&mut self, params: TlvWriterInitParams<Self::BackingStoreType>);
    fn get_init_params(&self) -> TlvWriterInitParams<Self::BackingStoreType>;
    fn is_container_open(&self) -> bool;
    fn init(&mut self, buf: *mut u8, max_len: u32);
    fn get_length_written(&self) -> usize;
}

pub struct TlvWriterBasic<BackingStoreType>
where
    BackingStoreType: TlvBackingStore,
{
    pub m_app_data: *mut u8,
    pub m_implicit_profile_id: u32,
    m_backing_store: *mut BackingStoreType,
    m_buf_start: *mut u8,
    m_write_point: *mut u8,
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
{
    type BackingStoreType = BackingStoreType;

    fn init_with_params(&mut self, params: TlvWriterInitParams<Self::BackingStoreType>) {
        self.m_implicit_profile_id = params.m_implicit_profile_id;
        self.m_backing_store = params.m_backing_store as _;
        self.m_buf_start = params.m_buf_start;
        self.m_write_point = params.m_write_point;
        self.m_remaining_len = params.m_remaining_len;
        self.m_len_written = params.m_len_written;
        self.m_max_len = params.m_max_len;
        self.m_container_type = params.m_container_type;
        self.m_initiialization_cookie = params.m_initiialization_cookie;
        self.m_container_open = params.m_container_open;
        self.m_close_container_recerved = params.m_close_container_recerved;
    }

    fn get_init_params(&self) -> TlvWriterInitParams<Self::BackingStoreType> {
        TlvWriterInitParams {
            m_implicit_profile_id: self.m_implicit_profile_id,
            m_backing_store: self.m_backing_store as _,
            m_buf_start: self.m_buf_start,
            m_write_point: self.m_write_point,
            m_remaining_len: self.m_remaining_len,
            m_len_written: self.m_len_written,
            m_max_len: self.m_max_len,
            m_container_type: self.m_container_type,
            m_initiialization_cookie: self.m_initiialization_cookie,
            m_container_open: self.m_container_open,
            m_close_container_recerved: self.m_close_container_recerved,
        }
    }

    fn is_container_open(&self) -> bool {
        self.m_container_open
    }

    fn init(&mut self, buf: *mut u8, max_len: u32) {
        let actual_max_len: usize = if max_len > u32::MAX {
            u32::MAX as usize
        } else {
            max_len as usize
        };

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

    fn get_length_written(&self) -> usize {
        self.m_len_written
    }
}

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

    pub fn init_backing_store(
        &mut self,
        backing_store: *mut BackingStoreType,
        max_len: u32,
    ) -> ChipErrorResult {
        self.init(ptr::null_mut(), max_len);
        self.m_initiialization_cookie = 0;

        self.m_backing_store = backing_store;
        self.m_buf_start = ptr::null_mut();
        self.m_remaining_len = 0;
        unsafe {
            (*self.m_backing_store).on_init_writer(
                self as *mut Self,
                ptr::addr_of_mut!(self.m_buf_start),
                ptr::addr_of_mut!(self.m_remaining_len),
            )?;
        }

        verify_or_return_error!(
            self.m_buf_start.is_null() == false,
            Err(chip_error_internal!())
        );
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
                return (*self.m_backing_store).finalize_buffer(
                    self as *mut Self,
                    self.m_buf_start,
                    self.m_write_point
                        .offset_from(self.m_buf_start)
                        .try_into()
                        .unwrap(),
                );
            }
        }
        chip_ok!()
    }

    pub fn reserve_buffer(&mut self, buffer_size: usize) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(
            self.m_remaining_len >= buffer_size,
            Err(chip_error_incorrect_state!())
        );

        if self.m_backing_store.is_null() == false {
            unsafe {
                verify_or_return_error!(
                    (*self.m_backing_store).get_new_buffer_will_always_fail(),
                    Err(chip_error_incorrect_state!())
                );
            }
        }

        self.m_reserved_size += buffer_size;
        self.m_remaining_len -= buffer_size;

        chip_ok!()
    }

    pub fn put_boolean(&mut self, tag: Tag, v: bool) -> ChipErrorResult {
        let type_bool = if v == true {
            TlvElementType::BooleanTrue
        } else {
            TlvElementType::BooleanFalse
        };

        self.write_element_head(type_bool, tag, 0)
    }

    pub fn put_u8(&mut self, tag: Tag, v: u8) -> ChipErrorResult {
        return self.put_u64(tag, v as u64);
    }

    pub fn put_u16(&mut self, tag: Tag, v: u16) -> ChipErrorResult {
        self.put_u64(tag, v as u64)
    }

    pub fn put_u32(&mut self, tag: Tag, v: u32) -> ChipErrorResult {
        self.put_u64(tag, v as u64)
    }

    pub fn put_u8_preserve_size(
        &mut self,
        tag: Tag,
        v: u8,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            return self.write_element_head(TlvElementType::UInt8, tag, v as u64);
        }
        return self.put_u8(tag, v);
    }

    pub fn put_u16_preserve_size(
        &mut self,
        tag: Tag,
        v: u16,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::UInt16, tag, v as u64)
        } else {
            self.put_u16(tag, v)
        }
    }

    pub fn put_u32_preserve_size(
        &mut self,
        tag: Tag,
        v: u32,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::UInt32, tag, v as u64)
        } else {
            self.put_u32(tag, v)
        }
    }

    pub fn put_u64(&mut self, tag: Tag, v: u64) -> ChipErrorResult {
        let mut elem_type: TlvElementType;

        if v <= u8::MAX as u64 {
            elem_type = TlvElementType::UInt8;
        } else if v <= u16::MAX as u64 {
            elem_type = TlvElementType::UInt16;
        } else if v <= u32::MAX as u64 {
            elem_type = TlvElementType::UInt32;
        } else {
            elem_type = TlvElementType::UInt64;
        }

        return self.write_element_head(elem_type, tag, v);
    }

    pub fn put_u64_preserve_size(
        &mut self,
        tag: Tag,
        v: u64,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::UInt64, tag, v)
        } else {
            self.put_u64(tag, v)
        }
    }

    pub fn put_i8(&mut self, tag: Tag, v: i8) -> ChipErrorResult {
        self.put_i64(tag, v as i64)
    }

    pub fn put_i16(&mut self, tag: Tag, v: i16) -> ChipErrorResult {
        self.put_i64(tag, v as i64)
    }

    pub fn put_i32(&mut self, tag: Tag, v: i32) -> ChipErrorResult {
        self.put_i64(tag, v as i64)
    }

    pub fn put_i8_preserve_size(
        &mut self,
        tag: Tag,
        v: i8,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::Int8, tag, v as u64)
        } else {
            self.put_i8(tag, v)
        }
    }

    pub fn put_i16_preserve_size(
        &mut self,
        tag: Tag,
        v: i16,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::Int16, tag, v as u64)
        } else {
            self.put_i16(tag, v)
        }
    }

    pub fn put_i32_preserve_size(
        &mut self,
        tag: Tag,
        v: i32,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::Int32, tag, v as u64)
        } else {
            self.put_i32(tag, v)
        }
    }

    pub fn put_i64(&mut self, tag: Tag, v: i64) -> ChipErrorResult {
        let mut elem_type: TlvElementType;

        if v <= i8::MAX as i64 && v >= i8::MIN as i64 {
            elem_type = TlvElementType::Int8;
        } else if v <= i16::MAX as i64 && v >= i16::MIN as i64 {
            elem_type = TlvElementType::Int16;
        } else if v <= i32::MAX as i64 && v >= i32::MIN as i64 {
            elem_type = TlvElementType::Int32;
        } else {
            elem_type = TlvElementType::Int64;
        }

        return self.write_element_head(elem_type, tag, v as u64);
    }

    pub fn put_i64_preserve_size(
        &mut self,
        tag: Tag,
        v: i64,
        preserve_size: bool,
    ) -> ChipErrorResult {
        if preserve_size {
            self.write_element_head(TlvElementType::Int64, tag, v as u64)
        } else {
            self.put_i64(tag, v)
        }
    }

    pub fn put_bytes(&mut self, tag: Tag, buf: &[u8]) -> ChipErrorResult {
        verify_or_return_error!(
            buf.len() <= u32::MAX as usize,
            Err(chip_error_message_too_long!())
        );
        return self.write_element_with_data(TlvType::KtlvTypeByteString, tag, &buf[..]);
    }

    pub fn put_string(&mut self, tag: Tag, buf: &str) -> ChipErrorResult {
        // Rust str is UTF-8 encoded and doesn't have terminating null.
        return self.write_element_with_data(TlvType::KtlvTypeUTF8String, tag, buf.as_bytes());
    }

    pub fn put_string_f(&mut self, tag: Tag, args: fmt::Arguments) -> ChipErrorResult {
        // TODO: use heap??
        const MAX_STR_SIZE_BYTES: usize = 32;
        let mut tmp_buf: [u8; MAX_STR_SIZE_BYTES] = [0; MAX_STR_SIZE_BYTES];
        let the_str = private::format_args_to_str(&mut tmp_buf[..], args);
        if the_str.is_err() {
            return Err(chip_error_no_memory!());
        }
        let the_str = the_str.unwrap();

        return self.put_string(tag, the_str);
    }

    pub fn put_null(&mut self, tag: Tag) -> ChipErrorResult {
        return self.write_element_head(TlvElementType::Null, tag, 0);
    }

    pub fn copy_element(&mut self) -> ChipErrorResult {
        // TODO: wait for reader implement
        chip_ok!()
    }

    pub fn copy_element_tag(&mut self, tag: Tag) -> ChipErrorResult {
        // TODO: wait for reader implement
        chip_ok!()
    }

    pub fn open_container<WriterType: TlvWriter>(
        &mut self,
        tag: Tag,
        container_type: TlvType,
        container_writer: &mut WriterType,
    ) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(
            tlv_types::tlv_type_is_container(container_type),
            Err(chip_error_wrong_tlv_type!())
        );

        if self.is_close_container_reserved() {
            verify_or_return_error!(
                self.m_max_len >= private::KEND_OF_CONTAINER_MARKER_SIZE,
                Err(chip_error_buffer_too_small!())
            );
            self.m_max_len -= private::KEND_OF_CONTAINER_MARKER_SIZE;
        }

        self.write_element_head(TlvElementType::from_container_type(container_type), tag, 0)
            .map_err(|e| {
                if self.is_close_container_reserved() {
                    self.m_max_len += private::KEND_OF_CONTAINER_MARKER_SIZE;
                }
                e
            })?;

        container_writer.init_with_params(TlvWriterInitParams {
            m_implicit_profile_id: self.m_implicit_profile_id,
            m_backing_store: self.m_backing_store
                as *mut <WriterType as TlvWriter>::BackingStoreType,
            m_buf_start: self.m_buf_start,
            m_write_point: self.m_write_point,
            m_remaining_len: self.m_remaining_len,
            m_len_written: 0,
            m_max_len: self.m_max_len - self.m_len_written,
            m_container_type: container_type,
            m_initiialization_cookie: Self::KEXPECTED_INITIALIZATION_COOKIE,
            m_container_open: false,
            m_close_container_recerved: self.m_close_container_recerved,
        });

        self.set_container_open(true);

        chip_ok!()
    }

    pub fn close_container<WriterType: TlvWriter>(
        &mut self,
        container_writer: &mut WriterType,
    ) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        let params = container_writer.get_init_params();

        if false == tlv_types::tlv_type_is_container(params.m_container_type) {
            return Err(chip_error_incorrect_state!());
        }

        if container_writer.is_container_open() {
            return Err(chip_error_tlv_container_open!());
        }
        self.m_backing_store = params.m_backing_store as _;
        self.m_buf_start = params.m_buf_start;
        self.m_write_point = params.m_write_point;
        self.m_remaining_len = params.m_remaining_len;
        self.m_len_written = params.m_len_written;

        if self.is_close_container_reserved() {
            self.m_max_len += private::KEND_OF_CONTAINER_MARKER_SIZE;
        }

        self.set_container_open(false);

        container_writer.init(ptr::null_mut(), 0);

        return self.write_element_head(
            TlvElementType::EndOfContainer,
            tlv_tags::anonymous_tag(),
            0,
        );
    }

    pub fn start_container(
        &mut self,
        tag: Tag,
        container_type: TlvType,
        outer_container_type: &mut TlvType,
    ) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));

        verify_or_return_error!(
            tlv_types::tlv_type_is_container(container_type),
            Err(chip_error_incorrect_state!())
        );

        if self.is_close_container_reserved() {
            verify_or_return_error!(
                self.m_max_len >= private::KEND_OF_CONTAINER_MARKER_SIZE,
                Err(chip_error_incorrect_state!())
            );
            self.m_max_len -= private::KEND_OF_CONTAINER_MARKER_SIZE;
        }

        self.write_element_head(TlvElementType::from_container_type(container_type), tag, 0)
            .map_err(|e| {
                if self.is_close_container_reserved() {
                    self.m_max_len += private::KEND_OF_CONTAINER_MARKER_SIZE;
                }
                e
            })?;

        *outer_container_type = self.m_container_type;
        self.m_container_type = container_type;

        self.set_container_open(false);

        chip_ok!()
    }

    pub fn end_container(&mut self, outer_container_type: TlvType) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(
            tlv_types::tlv_type_is_container(self.m_container_type),
            Err(chip_error_incorrect_state!())
        );

        self.m_container_type = outer_container_type;

        if self.is_close_container_reserved() {
            self.m_max_len += private::KEND_OF_CONTAINER_MARKER_SIZE;
        }

        return self.write_element_head(
            TlvElementType::EndOfContainer,
            tlv_tags::anonymous_tag(),
            0,
        );
    }

    pub fn put_pre_encoded_container(
        &mut self,
        tag: Tag,
        container_type: TlvType,
        data: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(
            tlv_types::tlv_type_is_container(container_type),
            Err(chip_error_invalid_argument!())
        );

        self.write_element_head(TlvElementType::from_container_type(container_type), tag, 0)?;

        return self.write_data(data, data.len());
    }

    pub fn copy_container(&mut self) -> ChipErrorResult {
        // TODO: wait for reader implement
        chip_ok!()
    }

    fn is_close_container_reserved(&self) -> bool {
        self.m_close_container_recerved
    }

    fn write_element_head(
        &mut self,
        e_type: TlvElementType,
        tag: Tag,
        len_or_val: u64,
    ) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(
            !self.is_container_open(),
            Err(chip_error_tlv_container_open!())
        );

        let mut staging_buf: [u8; 17] = [0; 17];
        let tag_num: u32 = tlv_tags::tag_num_from_tag(&tag);

        let mut writer: LittleEndianBufferWriter =
            LittleEndianBufferWriter::default_with_buf(&mut staging_buf[..]);

        if tlv_tags::is_special_tag(&tag) {
            if tag_num <= tlv_tags::SpecialTagNumber::KContextTagMaxNum as u32 {
                if (self.m_container_type != TlvType::KtlvTypeStructure)
                    && (self.m_container_type != TlvType::KtlvTypeList)
                {
                    return Err(chip_error_invalid_tlv_tag!());
                }

                writer.put_u8(TLVTagControl::ContextSpecific as u8 | e_type as u8);
                writer.put_u8(tag_num as u8);
            } else {
                if (e_type != TlvElementType::EndOfContainer)
                    && (self.m_container_type != TlvType::KtlvTypeNotSpecified)
                    && (self.m_container_type != TlvType::KtlvTypeArray)
                    && (self.m_container_type != TlvType::KtlvTypeList)
                {
                    return Err(chip_error_invalid_tlv_tag!());
                }
                writer.put_u8(TLVTagControl::Anonymous as u8 | e_type as u8);
            }
        } else {
            let profile_id: u32 = tlv_tags::profile_id_from_tag(&tag);

            if (self.m_container_type != TlvType::KtlvTypeNotSpecified)
                && (self.m_container_type != TlvType::KtlvTypeStructure)
                && (self.m_container_type != TlvType::KtlvTypeList)
            {
                return Err(chip_error_invalid_tlv_tag!());
            }

            if profile_id == TlvCommonProfiles::KcommonProfileId as u32 {
                if tag_num <= u16::MAX.into() {
                    writer.put_u8(TLVTagControl::CommonProfile2Bytes as u8 | e_type as u8);
                    writer.put_u16(tag_num as u16);
                } else {
                    writer.put_u8(TLVTagControl::CommonProfile4Bytes as u8 | e_type as u8);
                    writer.put_u32(tag_num);
                }
            } else if profile_id == self.m_implicit_profile_id {
                if tag_num <= u16::MAX.into() {
                    writer.put_u8(TLVTagControl::ImplicitProfile2Bytes as u8 | e_type as u8);
                    writer.put_u16(tag_num as u16);
                } else {
                    writer.put_u8(TLVTagControl::ImplicitProfile4Bytes as u8 | e_type as u8);
                    writer.put_u32(tag_num);
                }
            } else {
                let vendor_id: u16 = (profile_id >> 16) as u16;
                let profile_num = (profile_id & 0x0000FFFF) as u16;
                if tag_num <= u16::MAX.into() {
                    writer.put_u8(TLVTagControl::FullyQualified6Bytes as u8 | e_type as u8);
                    writer.put_u16(vendor_id);
                    writer.put_u16(profile_num);
                    writer.put_u16(tag_num as u16);
                } else {
                    writer.put_u8(TLVTagControl::FullyQualified8Bytes as u8 | e_type as u8);
                    writer.put_u16(vendor_id);
                    writer.put_u16(profile_num);
                    writer.put_u32(tag_num);
                }
            }
        } // end of not special tag

        let length_size = tlv_types::tlv_field_size_to_bytes(tlv_types::get_tlv_field_size(e_type));

        if length_size > 0 {
            let _ = writer.endian_unsign_put(len_or_val, length_size as usize);
        }

        verify_or_die!(writer.is_fit());

        return self.write_data(writer.const_buffer(), writer.fit().unwrap());
    }

    pub fn write_element_with_data(
        &mut self,
        the_type: TlvType,
        tag: Tag,
        data: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        if (the_type as u64) & (TLVTypeMask::KTLVTypeSizeMask as u64) != 0 {
            return Err(chip_error_invalid_argument!());
        }

        let mut len_field_size: TLVFieldSize;

        let data_len = data.len();

        if data_len <= u8::MAX as usize {
            len_field_size = TLVFieldSize::KTLVFieldSize1Byte;
        } else if data_len <= u16::MAX as usize {
            len_field_size = TLVFieldSize::KTLVFieldSize2Byte;
        } else {
            len_field_size = TLVFieldSize::KTLVFieldSize4Byte;
        }

        self.write_element_head(
            TlvElementType::from((the_type as i8) | (len_field_size as i8)),
            tag,
            data_len as u64,
        )?;

        return self.write_data(data, data_len);
    }

    fn write_data(&mut self, buf: &[u8], mut len: usize) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(
            (self.m_len_written + len) <= self.m_max_len,
            Err(chip_error_buffer_too_small!())
        );
        let mut p_buf: *const u8 = buf.as_ptr();

        while len > 0 {
            if self.m_remaining_len == 0 {
                verify_or_return_error!(
                    self.m_backing_store.is_null() == false,
                    Err(chip_error_no_memory!())
                );
                unsafe {
                    verify_or_return_error!(
                        self.m_write_point.offset_from(self.m_buf_start) > 0,
                        Err(chip_error_incorrect_state!())
                    );
                    verify_or_return_error!(
                        (self.m_write_point.offset_from(self.m_buf_start) as u64)
                            < (u32::MAX as u64),
                        Err(chip_error_incorrect_state!())
                    );

                    (*self.m_backing_store).finalize_buffer(
                        self as *mut Self,
                        self.m_buf_start,
                        self.m_write_point.offset_from(self.m_buf_start) as usize,
                    )?;
                    (*self.m_backing_store).get_new_buffer(
                        self as *mut Self,
                        &mut self.m_buf_start,
                        &mut self.m_remaining_len,
                    )?;
                }

                verify_or_return_error!(self.m_remaining_len > 0, Err(chip_error_no_memory!()));

                self.m_write_point = self.m_buf_start;

                if self.m_remaining_len > (self.m_max_len - self.m_len_written) {
                    self.m_remaining_len = self.m_max_len - self.m_len_written;
                }
            }
            let mut write_len = len;
            if write_len > self.m_remaining_len {
                write_len = self.m_remaining_len;
            }

            unsafe {
                ptr::copy_nonoverlapping(p_buf, self.m_write_point, write_len);
                self.m_write_point = self.m_write_point.add(write_len);
                self.m_remaining_len -= write_len;
                self.m_len_written += write_len;
                p_buf = p_buf.add(write_len);
                len -= write_len;
            }
        }

        chip_ok!()
    }

    fn set_container_open(&mut self, container_open: bool) {
        self.m_container_open = container_open;
    }

    fn set_close_container_reserved(&mut self, close_container_reserved: bool) {
        self.m_close_container_recerved = close_container_reserved;
    }
}

pub struct DummyBackStore;
impl TlvBackingStore for DummyBackStore {
    fn get_new_buffer_will_always_fail(&self) -> bool {
        false
    }
}

pub type TlvContiguousBufferWriter = TlvWriterBasic<DummyBackStore>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::chip::chip_lib::core::tlv_backing_store::TlvBackingStore;
    use std::*;

    mod no_backing {
        use super::super::*;
        use super::*;
        use crate::chip::chip_lib::core::tlv_reader::TlvReader;
        use crate::chip::chip_lib::core::tlv_tags;
        use crate::chip::chip_lib::core::tlv_tags::TLVTagControl;
        use crate::chip::chip_lib::core::tlv_types::{TlvElementType, TlvType};
        use std::*;

        struct DummyBackStore;
        impl TlvBackingStore for DummyBackStore {
            fn on_init_writer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                _buf: *mut *mut u8,
                _buf_len: *mut usize,
            ) -> ChipErrorResult {
                chip_ok!()
            }

            fn finalize_buffer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                _buf: *mut u8,
                _buf_len: usize,
            ) -> ChipErrorResult {
                chip_ok!()
            }

            fn get_new_buffer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                _buf: *mut *mut u8,
                _buf_len: &mut usize,
            ) -> ChipErrorResult {
                chip_ok!()
            }

            fn get_new_buffer_will_always_fail(&self) -> bool {
                false
            }
        }

        type TheTlvWriter = TlvWriterBasic<DummyBackStore>;
        const THE_BUF_LEN: usize = 32;
        static mut BUFFER: [u8; THE_BUF_LEN] = [0; THE_BUF_LEN];

        fn setup_non_init() -> TheTlvWriter {
            TheTlvWriter::const_default()
        }

        fn setup() -> TheTlvWriter {
            let mut writer = TheTlvWriter::const_default();
            unsafe {
                BUFFER.fill(0);
                writer.init(BUFFER.as_mut_ptr(), THE_BUF_LEN as u32);
            }
            return writer;
        }

        #[test]
        fn init() {
            let mut writer = setup_non_init();
            assert_eq!(false, writer.is_initialized());
            let mut commit_buf: [u8; 8] = [0; 8];
            writer.init(commit_buf.as_mut_ptr(), 8);
            assert_eq!(true, writer.is_initialized());
        }

        #[test]
        fn write_element_head_context_tag() {
            let mut writer = setup();
            writer.m_container_type = TlvType::KtlvTypeStructure;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::context_tag(1), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::ContextSpecific as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(2, BUFFER[2]);
            }
        }

        #[test]
        fn write_element_head_context_tag_not_valid_tag() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::context_tag(1), 1)
                    .is_err()
            );
        }

        #[test]
        fn write_element_head_anonymous() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::anonymous_tag(), 1)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::Anonymous as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
            }
        }

        #[test]
        fn write_element_head_anonymous_tag_structure() {
            let mut writer = setup();
            writer.m_container_type = TlvType::KtlvTypeStructure;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::anonymous_tag(), 1)
                    .is_err()
            );
        }

        #[test]
        fn write_element_head_common_tag_but_container_array() {
            let mut writer = setup();
            writer.m_container_type = TlvType::KtlvTypeArray;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::profile_tag(0, 1), 2)
                    .is_err()
            );
        }

        #[test]
        fn write_element_head_common_tag_with_num_less_u16_max() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::common_tag(1), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::CommonProfile2Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
            }
        }

        #[test]
        fn write_element_head_common_tag_with_num_big_u16_max() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::common_tag(0x1FFFF), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::CommonProfile4Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(0xFF, BUFFER[1]);
                assert_eq!(0xFF, BUFFER[2]);
                assert_eq!(0x01, BUFFER[3]);
                assert_eq!(0x00, BUFFER[4]);
                assert_eq!(2, BUFFER[5]);
            }
        }

        #[test]
        fn write_element_head_implicit_tag_with_num_less_u16_max() {
            let mut writer = setup();
            writer.m_implicit_profile_id = 0x1;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::profile_tag(1, 2), 3)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::ImplicitProfile2Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(2, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(3, BUFFER[3]);
            }
        }

        #[test]
        fn write_element_head_implicit_tag_with_num_big_u16_max() {
            let mut writer = setup();
            writer.m_implicit_profile_id = 0x1;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::profile_tag(1, 0x1FFFF), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::ImplicitProfile4Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(0xFF, BUFFER[1]);
                assert_eq!(0xFF, BUFFER[2]);
                assert_eq!(0x01, BUFFER[3]);
                assert_eq!(0x00, BUFFER[4]);
                assert_eq!(2, BUFFER[5]);
            }
        }

        #[test]
        fn write_element_head_regular_tag_with_num_less_u16_max() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(
                        TlvElementType::UInt8,
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        4
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
                assert_eq!(4, BUFFER[7]);
            }
        }

        #[test]
        fn write_element_head_regular_tag_with_num_big_u16_max() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(
                        TlvElementType::UInt8,
                        tlv_tags::profile_tag_vendor_id(1, 2, 0x1FFFF),
                        4
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified8Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(0xFF, BUFFER[5]);
                assert_eq!(0xFF, BUFFER[6]);
                assert_eq!(0x01, BUFFER[7]);
                assert_eq!(0x00, BUFFER[8]);
                assert_eq!(4, BUFFER[9]);
            }
        }

        #[test]
        fn put_u8() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .put_u8(tlv_tags::profile_tag_vendor_id(1, 2, 0x1FFFF), 0x11)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified8Bytes as u8 | TlvElementType::UInt8 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(0xFF, BUFFER[5]);
                assert_eq!(0xFF, BUFFER[6]);
                assert_eq!(0x01, BUFFER[7]);
                assert_eq!(0x00, BUFFER[8]);
                assert_eq!(0x11, BUFFER[9]);
            }
        }

        #[test]
        fn put_u64() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .put_u64(
                        tlv_tags::profile_tag_vendor_id(1, 2, 0x1FFFF),
                        0x1122334444332211
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified8Bytes as u8 | TlvElementType::UInt64 as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(0xFF, BUFFER[5]);
                assert_eq!(0xFF, BUFFER[6]);
                assert_eq!(0x01, BUFFER[7]);
                assert_eq!(0x00, BUFFER[8]);
                assert_eq!(0x11, BUFFER[9]);
                assert_eq!(0x22, BUFFER[10]);
                assert_eq!(0x33, BUFFER[11]);
                assert_eq!(0x44, BUFFER[12]);
                assert_eq!(0x44, BUFFER[13]);
                assert_eq!(0x33, BUFFER[14]);
                assert_eq!(0x22, BUFFER[15]);
                assert_eq!(0x11, BUFFER[16]);
            }
        }

        #[test]
        fn write_element_head_regular_tag_with_no_value() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .write_element_head(
                        TlvElementType::BooleanFalse,
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        4
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8 | TlvElementType::BooleanFalse as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
            }
        }

        #[test]
        fn put_bytes() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .put_bytes(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        &[0x11, 0x12, 0x13, 0x14]
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8
                        | TlvElementType::ByteString1ByteLength as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
                assert_eq!(4, BUFFER[7]);
                assert_eq!(0x11, BUFFER[8]);
                assert_eq!(0x12, BUFFER[9]);
                assert_eq!(0x13, BUFFER[10]);
                assert_eq!(0x14, BUFFER[11]);
            }
        }

        #[test]
        fn put_string() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .put_string(tlv_tags::profile_tag_vendor_id(1, 2, 3), "abcd")
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8
                        | TlvElementType::UTF8String1ByteLength as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
                assert_eq!(4, BUFFER[7]);
                assert_eq!('a', BUFFER[8] as char);
                assert_eq!('b', BUFFER[9] as char);
                assert_eq!('c', BUFFER[10] as char);
                assert_eq!('d', BUFFER[11] as char);
            }
        }

        #[test]
        fn put_string_f() {
            let mut writer = setup();
            assert_eq!(
                true,
                writer
                    .put_string_f(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        format_args!("{}and{}", 1, 2)
                    )
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8
                        | TlvElementType::UTF8String1ByteLength as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
                assert_eq!(5, BUFFER[7]);
                assert_eq!('1', BUFFER[8] as char);
                assert_eq!('a', BUFFER[9] as char);
                assert_eq!('n', BUFFER[10] as char);
                assert_eq!('d', BUFFER[11] as char);
                assert_eq!('2', BUFFER[12] as char);
            }
        }

        #[test]
        fn end_tontainer() {
            let mut writer = setup();
            let mut outer_type: TlvType = TlvType::KtlvTypeNotSpecified;
            assert_eq!(
                true,
                writer
                    .start_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut outer_type
                    )
                    .is_ok()
            );
            assert_eq!(false, writer.is_container_open());
            assert_eq!(TlvType::KtlvTypeNotSpecified, outer_type);
            assert_eq!(true, writer.end_container(outer_type).is_ok());
            unsafe {
                assert_eq!(
                    TLVTagControl::FullyQualified6Bytes as u8 | TlvElementType::Array as u8,
                    BUFFER[0]
                );
                assert_eq!(1, BUFFER[1]);
                assert_eq!(0, BUFFER[2]);
                assert_eq!(2, BUFFER[3]);
                assert_eq!(0, BUFFER[4]);
                assert_eq!(3, BUFFER[5]);
                assert_eq!(0, BUFFER[6]);
                assert_eq!(
                    TLVTagControl::Anonymous as u8 | TlvElementType::EndOfContainer as u8,
                    BUFFER[7]
                );
            }
        }
    } // end of no_backing

    mod backing {
        use super::super::*;
        use super::*;
        use crate::chip::chip_lib::core::tlv_reader::TlvReader;
        use crate::chip::chip_lib::core::tlv_tags;
        use crate::chip::chip_lib::core::tlv_tags::TLVTagControl;
        use crate::chip::chip_lib::core::tlv_types::{TlvElementType, TlvType};
        use std::*;

        const TMP_BUF_LEN: usize = 4;

        struct VecBackingStore {
            pub m_back: Vec<Vec<u8>>,
            pub m_current: [u8; TMP_BUF_LEN],
            pub m_always_fail: bool,
        }

        impl VecBackingStore {
            pub fn reset(&mut self) {
                for row in self.m_back.iter_mut() {
                    row.clear();
                }
                self.m_back.clear();
                self.m_current.fill(0);
            }
        }

        impl Default for VecBackingStore {
            fn default() -> Self {
                Self {
                    m_back: Vec::new(),
                    m_current: [0; TMP_BUF_LEN],
                    m_always_fail: false,
                }
            }
        }

        impl TlvBackingStore for VecBackingStore {
            fn on_init_writer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                mut buf: *mut *mut u8,
                buf_len: *mut usize,
            ) -> ChipErrorResult {
                self.reset();

                unsafe {
                    *buf = self.m_current.as_mut_ptr();
                    *buf_len = TMP_BUF_LEN;
                }

                chip_ok!()
            }

            fn finalize_buffer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                buf: *mut u8,
                buf_len: usize,
            ) -> ChipErrorResult {
                self.m_back.push(Vec::<u8>::new());
                if let Some(last) = self.m_back.last_mut() {
                    for i in 0..buf_len {
                        unsafe {
                            last.push(*(buf.add(i)));
                        }
                    }
                } else {
                    return Err(chip_error_no_memory!());
                }
                chip_ok!()
            }

            fn get_new_buffer<TlvWriterType: TlvWriter>(
                &mut self,
                _writer: *mut TlvWriterType,
                buf: *mut *mut u8,
                buf_len: &mut usize,
            ) -> ChipErrorResult {
                self.m_current.fill(0);
                unsafe {
                    *buf = self.m_current.as_mut_ptr();
                    *buf_len = TMP_BUF_LEN;
                }
                chip_ok!()
            }

            fn get_new_buffer_will_always_fail(&self) -> bool {
                return self.m_always_fail;
            }
        }
        type TheTlvWriter = TlvWriterBasic<VecBackingStore>;

        #[derive(Default)]
        struct DummyOtherWrite {
            pub m_container_open: bool,
        }

        impl TlvWriter for DummyOtherWrite {
            type BackingStoreType = VecBackingStore;
            fn init_with_params(&mut self, _params: TlvWriterInitParams<VecBackingStore>) {}
            fn get_init_params(&self) -> TlvWriterInitParams<Self::BackingStoreType> {
                return TlvWriterInitParams::<Self::BackingStoreType>::default();
            }
            fn is_container_open(&self) -> bool {
                self.m_container_open
            }
            fn init(&mut self, _buf: *mut u8, _max_len: u32) {}
            fn get_length_written(&self) -> usize {
                0
            }
        }

        fn setup(backing: *mut VecBackingStore) -> TheTlvWriter {
            let mut writer = TheTlvWriter::const_default();
            // to allow max_len > remaining_len, so we need a + 32 here
            let _ = writer.init_backing_store(backing, (TMP_BUF_LEN + 32) as u32);

            writer
        }

        #[test]
        fn init() {
            let mut writer = TheTlvWriter::const_default();
            assert_eq!(false, writer.is_initialized());
            let mut backing = VecBackingStore::default();
            assert_eq!(
                true,
                writer
                    .init_backing_store(ptr::addr_of_mut!(backing), TMP_BUF_LEN as u32)
                    .is_ok()
            );
            assert_eq!(true, writer.is_initialized());
        }

        #[test]
        fn write_element_head_context_tag() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            writer.m_container_type = TlvType::KtlvTypeStructure;
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::context_tag(1), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::ContextSpecific as u8 | TlvElementType::UInt8 as u8,
                    backing.m_current[0]
                );
                assert_eq!(1, backing.m_current[1]);
                assert_eq!(2, backing.m_current[2]);
            }
        }

        #[test]
        fn write_element_head_common_tag_with_num_big_u16_max() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            assert_eq!(
                true,
                writer
                    .write_element_head(TlvElementType::UInt8, tlv_tags::common_tag(0x1FFFF), 2)
                    .is_ok()
            );
            unsafe {
                assert_eq!(
                    TLVTagControl::CommonProfile4Bytes as u8 | TlvElementType::UInt8 as u8,
                    backing.m_back[0][0]
                );
                assert_eq!(0xFF, backing.m_back[0][1]);
                assert_eq!(0xFF, backing.m_back[0][2]);
                assert_eq!(0x01, backing.m_back[0][3]);
                assert_eq!(0x00, backing.m_current[0]);
                assert_eq!(2, backing.m_current[1]);
            }
        }

        #[test]
        fn open_container_wrong_type() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut container_writer = DummyOtherWrite::default();
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeNotSpecified,
                        &mut container_writer
                    )
                    .is_err()
            );
        }

        #[test]
        fn open_container_buffer_too_small() {
            let mut backing = VecBackingStore::default();
            let mut writer = TheTlvWriter::const_default();
            let _ = writer.init_backing_store(ptr::addr_of_mut!(backing), 0);
            let mut container_writer = DummyOtherWrite::default();
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut container_writer
                    )
                    .is_err()
            );
        }

        #[test]
        fn open_container() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut container_writer = DummyOtherWrite::default();
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut container_writer
                    )
                    .is_ok()
            );
            assert_eq!(true, writer.is_container_open());
        }

        #[test]
        fn close_tontainer() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut backing_1 = VecBackingStore::default();
            let mut container_writer = setup(ptr::addr_of_mut!(backing_1));
            //let mut container_writer = DummyOtherWrite::default();
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut container_writer
                    )
                    .is_ok()
            );
            assert_eq!(true, writer.close_container(&mut container_writer).is_ok());
            assert_eq!(false, writer.is_container_open());
        }

        #[test]
        fn close_tontainer_wrong_type() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut backing_1 = VecBackingStore::default();
            let mut container_writer = setup(ptr::addr_of_mut!(backing_1));
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut container_writer
                    )
                    .is_ok()
            );
            container_writer.m_container_type = TlvType::KtlvTypeNotSpecified;
            assert_eq!(true, writer.close_container(&mut container_writer).is_err());
        }

        #[test]
        fn close_tontainer_nested_open() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut backing_1 = VecBackingStore::default();
            let mut container_writer = setup(ptr::addr_of_mut!(backing_1));
            assert_eq!(
                true,
                writer
                    .open_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut container_writer
                    )
                    .is_ok()
            );
            container_writer.set_container_open(true);
            assert_eq!(true, writer.close_container(&mut container_writer).is_err());
        }

        #[test]
        fn start_tontainer() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut outer_type: TlvType = TlvType::KtlvTypeNotSpecified;
            assert_eq!(
                true,
                writer
                    .start_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeArray,
                        &mut outer_type
                    )
                    .is_ok()
            );
            assert_eq!(false, writer.is_container_open());
            assert_eq!(TlvType::KtlvTypeNotSpecified, outer_type);
        }

        #[test]
        fn start_tontainer_wrong_type() {
            let mut backing = VecBackingStore::default();
            let mut writer = setup(ptr::addr_of_mut!(backing));
            let mut outer_type: TlvType = TlvType::KtlvTypeNotSpecified;
            assert_eq!(
                true,
                writer
                    .start_container(
                        tlv_tags::profile_tag_vendor_id(1, 2, 3),
                        TlvType::KtlvTypeBoolean,
                        &mut outer_type
                    )
                    .is_err()
            );
        }
    }
}
