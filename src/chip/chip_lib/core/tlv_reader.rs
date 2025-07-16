use super::tlv_types::{self, TlvType, TlvElementType, TLVTypeMask};
use super::tlv_tags::{self, Tag,TlvCommonProfiles,TLVTagControl,TLVTagControlMS};
use super::tlv_backing_store::TlvBackingStore;
use super::tlv_common;
use super::chip_encoding::little_endian;
use crate::ChipErrorResult;
use crate::ChipError;

use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;
use crate::chip_no_error;

use crate::chip_error_wrong_tlv_type;
use crate::chip_error_tlv_underrun;
use crate::chip_error_invalid_integer_value;
use crate::chip_error_buffer_too_small;
use crate::chip_error_incorrect_state;
use crate::chip_error_end_of_tlv;
use crate::chip_error_invalid_tlv_element;
use crate::chip_error_invalid_tlv_tag;
use crate::chip_error_not_implemented;
use crate::chip_error_unexpected_tlv_element;
use crate::chip_error_unknown_implicit_tlv_tag;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::verify_or_die;

use core::str::FromStr;
use crate::chip_log_detail;
use crate::chip_internal_log;
use crate::chip_internal_log_impl;

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

    fn get_i8(&self) -> Result<i8, ChipError>;
    fn get_i16(&self) -> Result<i16, ChipError>;
    fn get_i32(&self) -> Result<i32, ChipError>;
    fn get_u8(&self) -> Result<u8, ChipError>;
    fn get_u16(&self) -> Result<u16, ChipError>;
    fn get_u32(&self) -> Result<u32, ChipError>;

    fn get_i64(&self) -> Result<i64, ChipError>;

    fn get_u64(&self) -> Result<u64, ChipError>;

    fn get_bytes(&mut self) -> Result<&[u8], ChipError>;

    fn get_bytes_raw(&mut self, buf: * mut u8, buf_len: usize) -> ChipErrorResult;

    fn get_string(&mut self) -> Result<Option<&str>, ChipError>;
    
    fn get_string_raw(&mut self, buf: * mut u8, buf_size: usize) -> ChipErrorResult;

    fn enter_container(&mut self) -> Result<TlvType, ChipError>;

    fn exit_container(&mut self, outer_container_type: TlvType) -> ChipErrorResult;

    //fn open_container(&mut self) -> Result<Self, ChipError> where Self: Sized;
    fn open_container(&mut self, reader: &mut Self) -> ChipErrorResult;

    fn close_container(&mut self, reader: &mut Self) -> ChipErrorResult;

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

impl<BackingStoreType> Clone for TlvReaderBasic<BackingStoreType>
    where 
        BackingStoreType: TlvBackingStore,
{
    fn clone(&self) -> Self {
        let reader = Self {
            m_implicit_profile_id: self.m_implicit_profile_id,
            m_app_data: self.m_app_data,
            m_elem_tag: self.m_elem_tag,
            m_elem_len_or_val: self.m_elem_len_or_val,
            m_backing_store: self.m_backing_store,
            m_read_point: self.m_read_point,
            m_buf_end: self.m_buf_end,
            m_len_read: self.m_len_read,
            m_max_len: self.m_max_len,
            m_container_type: self.m_container_type,
            m_control_byte: self.m_control_byte,
            m_container_open: self.m_container_open,
        };

        return reader;
    }
}

impl<BackingStoreType> TlvReaderBasic<BackingStoreType>
    where 
        BackingStoreType: TlvBackingStore,
{
    const TAG_SIZES: [u8; 8] = [0, 1, 2, 4, 2, 4, 6, 8];

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

    fn get_element_type(&self) -> TlvElementType {
        if self.m_control_byte == tlv_common::KTLVCONTROL_BYTE_NOT_SPECIFIED {
            return TlvElementType::NotSpecified;
        }

        return TlvElementType::from(self.m_control_byte & (TLVTypeMask::KTLVTypeMask as u16));
    }

    fn get_data_ptr(&self) -> Result<* const u8, ChipError> {
        verify_or_return_error!(tlv_types::tlv_type_is_string(self.get_element_type()),
          Err(chip_error_wrong_tlv_type!()));

        if self.get_length() == 0 {
            return Ok(ptr::null());
        }

        unsafe {
            let remaining_len = self.m_buf_end.offset_from(self.m_read_point) as usize;
            verify_or_return_error!(remaining_len >= self.m_elem_len_or_val as usize, 
                Err(chip_error_tlv_underrun!()));
        }

        Ok(self.m_read_point)
    }

    fn ensure_data(&mut self, no_data_err: ChipError) -> ChipErrorResult {
        if self.m_read_point == self.m_buf_end {
            verify_or_return_error!((self.m_len_read != self.m_max_len) && (!self.m_backing_store.is_null()),
                Err(no_data_err));

            let mut buf_len: usize = 0;
            unsafe {
                (*self.m_backing_store).get_next_buffer(self as _, ptr::addr_of_mut!(self.m_read_point),
                    ptr::addr_of_mut!(buf_len))?;

                verify_or_return_error!(buf_len > 0, Err(no_data_err));

                buf_len = core::cmp::min(buf_len, self.m_max_len - self.m_len_read);
                self.m_buf_end = self.m_read_point.add(buf_len);
            }
        }

        chip_ok!()
    }

    fn read_data_raw(&mut self, mut buf: * mut u8, mut len: usize) -> ChipErrorResult {
        while len > 0 {
            self.ensure_data(chip_error_tlv_underrun!())?;
            unsafe {
                let remaining_len = self.m_buf_end.offset_from(self.m_read_point) as usize;
                let mut read_len = len;
                if read_len > remaining_len {
                    read_len = remaining_len;
                }
                if !buf.is_null() {
                    ptr::copy_nonoverlapping(self.m_read_point, buf, read_len);
                    buf = buf.add(read_len);
                }
                self.m_read_point = self.m_read_point.add(read_len);
                self.m_len_read += read_len;
                len -= read_len;
            }
        }

        chip_ok!()
    }

    fn read_data(&mut self, buf: &mut [u8]) -> ChipErrorResult {
        return self.read_data_raw(buf.as_mut_ptr(), buf.len());
        /*
        let mut start: usize = 0;
        while start < buf.len() {
            self.ensure_data(chip_error_tlv_underrun!())?;
            unsafe {
                let remaining_len = self.m_buf_end.offset_from_unsigned(self.m_read_point);
                let mut read_len = buf.len() - start;
                if read_len > remaining_len {
                    read_len = remaining_len;
                }
                buf[start..start + read_len].copy_from_slice(core::slice::from_raw_parts(self.m_read_point, read_len));
                start += read_len;
                let _ = self.m_read_point.add(read_len);
                self.m_len_read += read_len;
            }
        }

        chip_ok!()
        */
    }


    #[inline]
    fn is_container_open(&self) -> bool {
        self.m_container_open
    }

    fn skip_data(&mut self) -> ChipErrorResult {
        let elem_type = self.get_element_type();

        if tlv_types::tlv_type_has_length(elem_type) {
            return self.read_data_raw(ptr::null_mut(), self.m_elem_len_or_val as usize);
        }

        chip_ok!()
    }

    fn skip_to_end_of_container(&mut self) -> ChipErrorResult {
        let outer_container_type = self.m_container_type;
        let mut nest_level: u32 = 0;

        self.set_container_open(false);

        loop {
            let elem_type = self.get_element_type();
            if elem_type == TlvElementType::EndOfContainer {
                if nest_level == 0 {
                    return chip_ok!();
                }
                nest_level -= 1;
                self.m_container_type = if nest_level == 0 { outer_container_type } else { TlvType::KtlvTypeUnknownContainer }
            } else if tlv_types::tlv_elem_type_is_container(elem_type) {
                nest_level += 1;
                self.m_container_type = TlvType::from(elem_type);
            }

            self.skip_data()?;
            let _ = self.read_element()?;
        }
    }

    fn read_tag_raw(&mut self, tag_control: TLVTagControl, mut p: * const u8) -> Result<(Tag, usize), ChipError> {
        unsafe {
            match tag_control {
                TLVTagControl::ContextSpecific => {
                    return Ok((tlv_tags::context_tag(p.read()), 1));
                },
                TLVTagControl::CommonProfile2Bytes => {
                    return Ok((tlv_tags::common_tag(little_endian::read_u16_raw(&mut p).into()), 2));
                },
                TLVTagControl::CommonProfile4Bytes => {
                    return Ok((tlv_tags::common_tag(little_endian::read_u32_raw(&mut p)), 4));
                },
                TLVTagControl::ImplicitProfile2Bytes => {
                    if self.m_implicit_profile_id == (TlvCommonProfiles::KprofileIdNotSpecified as u32) {
                        return Ok((tlv_tags::unknown_implicit_tag(), 0));
                    } else {
                        //return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, u32::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"))), 2));
                        return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, little_endian::read_u16_raw(&mut p).into()), 2));
                    }
                },
                TLVTagControl::ImplicitProfile4Bytes => {
                    if self.m_implicit_profile_id == (TlvCommonProfiles::KprofileIdNotSpecified as u32) {
                        return Ok((tlv_tags::unknown_implicit_tag(), 0));
                    } else {
                        //return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, u32::from_le_bytes(buf[0..4].try_into().expect("read_tag: small buf"))), 4));
                        return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, little_endian::read_u32_raw(&mut p)), 4));
                    }
                },
                TLVTagControl::FullyQualified6Bytes => {
                    /*
                    let vendor_id = u16::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"));
                    let profile_num = u16::from_le_bytes(buf[2..4].try_into().expect("read_tag: small buf"));
                    let tag_num = u32::from_le_bytes(buf[4..6].try_into().expect("read_tag: small buf"));
                    return Ok((tlv_tags::profile_tag_vendor_id(vendor_id, profile_num, tag_num), 6));
                    */
                    let vendor_id = little_endian::read_u16_raw(&mut p);
                    let profile_num = little_endian::read_u16_raw(&mut p);
                    let tag_num: u32 = little_endian::read_u16_raw(&mut p).into();
                    return Ok((tlv_tags::profile_tag_vendor_id(vendor_id, profile_num, tag_num), 6));
                },
                TLVTagControl::FullyQualified8Bytes => {
                    /*
                    let vendor_id = u16::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"));
                    let profile_num = u16::from_le_bytes(buf[2..4].try_into().expect("read_tag: small buf"));
                    let tag_num = u32::from_le_bytes(buf[4..8].try_into().expect("read_tag: small buf"));
                    */
                    let vendor_id = little_endian::read_u16_raw(&mut p);
                    let profile_num = little_endian::read_u16_raw(&mut p);
                    let tag_num: u32 = little_endian::read_u16_raw(&mut p).into();
                    return Ok((tlv_tags::profile_tag_vendor_id(vendor_id, profile_num, tag_num), 8));
                },
                _ => {
                    Ok((tlv_tags::anonymous_tag(),0))
                }
            }
        }
    }


    fn read_tag(&mut self, tag_control: TLVTagControl, buf: &[u8]) -> Result<(Tag, usize), ChipError> {
        match tag_control {
            TLVTagControl::ContextSpecific => {
                return Ok((tlv_tags::context_tag(buf[0]), 1));
            },
            TLVTagControl::CommonProfile2Bytes => {
                return Ok((tlv_tags::common_tag(u32::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"))), 2));
            },
            TLVTagControl::CommonProfile4Bytes => {
                return Ok((tlv_tags::common_tag(u32::from_le_bytes(buf[0..4].try_into().expect("read_tag: small buf"))), 4));
            },
            TLVTagControl::ImplicitProfile2Bytes => {
                if self.m_implicit_profile_id == (TlvCommonProfiles::KprofileIdNotSpecified as u32) {
                    return Ok((tlv_tags::unknown_implicit_tag(), 0));
                } else {
                    return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, u32::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"))), 2));
                }
            },
            TLVTagControl::ImplicitProfile4Bytes => {
                if self.m_implicit_profile_id == (TlvCommonProfiles::KprofileIdNotSpecified as u32) {
                    return Ok((tlv_tags::unknown_implicit_tag(), 0));
                } else {
                    return Ok((tlv_tags::profile_tag(self.m_implicit_profile_id, u32::from_le_bytes(buf[0..4].try_into().expect("read_tag: small buf"))), 4));
                }
            },
            TLVTagControl::FullyQualified6Bytes => {
                let vendor_id = u16::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"));
                let profile_num = u16::from_le_bytes(buf[2..4].try_into().expect("read_tag: small buf"));
                let tag_num = u32::from_le_bytes(buf[4..6].try_into().expect("read_tag: small buf"));
                return Ok((tlv_tags::profile_tag_vendor_id(vendor_id, profile_num, tag_num), 6));
            },
            TLVTagControl::FullyQualified8Bytes => {
                let vendor_id = u16::from_le_bytes(buf[0..2].try_into().expect("read_tag: small buf"));
                let profile_num = u16::from_le_bytes(buf[2..4].try_into().expect("read_tag: small buf"));
                let tag_num = u32::from_le_bytes(buf[4..8].try_into().expect("read_tag: small buf"));
                return Ok((tlv_tags::profile_tag_vendor_id(vendor_id, profile_num, tag_num), 8));
            },
            _ => {
                Ok((tlv_tags::anonymous_tag(),0))
            }
        }
    }

    fn read_element(&mut self) -> ChipErrorResult {
        self.ensure_data(chip_error_end_of_tlv!())?;
        verify_or_return_error!(self.m_read_point.is_null() == false, Err(chip_error_invalid_tlv_element!()));

        unsafe {
            self.m_control_byte = self.m_read_point.read() as u16;
        }

        let elem_type = self.get_element_type();
        verify_or_return_error!(tlv_types::is_valid_tlv_type(elem_type), Err(chip_error_invalid_tlv_element!()));


        // we have check the range in is_valid_tlv_type.
        let tag_control = TLVTagControl::try_from((self.m_control_byte as u8) & (TLVTagControlMS::KTLVTagControlMask as u8) as u8).unwrap();

        let tag_bytes = Self::TAG_SIZES[(tag_control >> (TLVTagControlMS::KTLVTagControlShift as u32)) as usize];

        let len_or_val_field_size = tlv_types::get_tlv_field_size(elem_type);

        let val_or_len_bytes = tlv_types::tlv_field_size_to_bytes(len_or_val_field_size);

        let ele_head_bytes: u8 = 1 + tag_bytes + val_or_len_bytes;

        let mut staging_buf: [u8; 17] = [0; 17];

        self.read_data(&mut staging_buf[0..ele_head_bytes as usize])?;

        if let Ok((the_tag, tag_size)) = self.read_tag(tag_control, &staging_buf[1..]) {
            self.m_elem_tag = the_tag;
            match val_or_len_bytes {
                0 => {
                    self.m_elem_len_or_val = 0;
                }
                1 => {
                    self.m_elem_len_or_val = u8::from_le_bytes(staging_buf[(1+tag_size)..(1+tag_size + (val_or_len_bytes as usize))].try_into().expect("read_data: cannot get u8")) as u64;
                },
                2 => {
                    self.m_elem_len_or_val = u16::from_le_bytes(staging_buf[(1+tag_size)..(1+tag_size + (val_or_len_bytes as usize))].try_into().expect("read_data: cannot get u16")) as u64;
                },
                4 => {
                    self.m_elem_len_or_val = u32::from_le_bytes(staging_buf[(1+tag_size)..(1+tag_size + (val_or_len_bytes as usize))].try_into().expect("read_data: cannot get u32")) as u64;
                },
                8 => {
                    self.m_elem_len_or_val = u64::from_le_bytes(staging_buf[(1+tag_size)..(1+tag_size + (val_or_len_bytes as usize))].try_into().expect("read_data: cannot get u64"));
                },
                _ => {
                    return Err(chip_error_not_implemented!());
                }
            }
            verify_or_return_error!(!tlv_types::tlv_type_has_length(elem_type) || self.m_elem_len_or_val <= (u32::MAX as u64), Err(chip_error_not_implemented!()));
        } else {
            return Err(chip_error_not_implemented!());
        }

        return self.verify_element();
    }

    fn verify_element(&self) -> ChipErrorResult {
        if self.get_element_type() == TlvElementType::EndOfContainer {
            if self.m_container_type == TlvType::KtlvTypeNotSpecified {
                return Err(chip_error_invalid_tlv_element!());
            }
            if self.m_elem_tag != tlv_tags::anonymous_tag() {
                return Err(chip_error_invalid_tlv_tag!());
            }
        } else {
            if self.m_elem_tag == tlv_tags::unknown_implicit_tag() {
                return Err(chip_error_unknown_implicit_tlv_tag!());
            }

            match self.m_container_type {
                TlvType::KtlvTypeNotSpecified => {
                    if tlv_tags::is_context_tag(&self.m_elem_tag) {
                        return Err(chip_error_invalid_tlv_tag!());
                    }
                },
                TlvType::KtlvTypeStructure => {
                    if self.m_elem_tag == tlv_tags::anonymous_tag() {
                        return Err(chip_error_invalid_tlv_tag!());
                    }
                },
                TlvType::KtlvTypeArray => {
                    if self.m_elem_tag == tlv_tags::anonymous_tag() {
                        return Err(chip_error_invalid_tlv_tag!());
                    }
                },
                TlvType::KtlvTypeUnknownContainer | TlvType::KtlvTypeList => {
                    // do nothing
                },
                _ => {
                    return Err(chip_error_incorrect_state!());
                }
            }
        }

        if tlv_types::tlv_type_has_length(self.get_element_type()) {
            let overall_len_remaining: u32 = (self.m_max_len - self.m_len_read) as u32;
            if overall_len_remaining < (self.m_elem_len_or_val as u32) {
                return Err(chip_error_tlv_underrun!());
            }
        }

        return chip_ok!();
    }

    pub fn get_element_head_length(&self) -> Result<u8, ChipError> {
        let elem_type = self.get_element_type();
        verify_or_return_error!(tlv_types::is_valid_tlv_type(elem_type),
            Err(chip_error_invalid_tlv_element!()));

        let tag_control = TLVTagControl::try_from((self.m_control_byte as u8) & (TLVTagControlMS::KTLVTagControlMask as u8) as u8).unwrap();

        let tag_bytes = Self::TAG_SIZES[(tag_control >> (TLVTagControlMS::KTLVTagControlShift as u32)) as usize];

        let len_or_val_field_size = tlv_types::get_tlv_field_size(elem_type);

        let val_or_len_bytes = tlv_types::tlv_field_size_to_bytes(len_or_val_field_size);

        verify_or_return_error!((1 + tag_bytes + val_or_len_bytes) <= u8::MAX,
            Err(chip_error_internal!()));

        return Ok((1 + tag_bytes + val_or_len_bytes) as u8);
    }

    pub fn find_element_with_tag(&self, tag: &Tag) -> Result<Self, ChipError> {
        let mut reader = self.clone();

        while reader.next().is_ok() {
            verify_or_return_error!(TlvType::KtlvTypeNotSpecified != reader.get_type(),
                Err(chip_error_invalid_tlv_element!()));
            if *tag == reader.get_tag() {
                return Ok(reader.clone());
            }
        }

        return Err(chip_error_invalid_tlv_tag!());
    }

    pub fn count_remaining_in_container(&self) -> Result<isize, ChipError> {
        verify_or_return_error!(TlvType::KtlvTypeNotSpecified != self.m_container_type,
           Err(chip_error_incorrect_state!()));

        let mut reader = self.clone();
        let mut count: isize = 0;
        let mut return_err: ChipError = chip_no_error!();

        while reader.next().inspect_err(|e| return_err = *e).is_ok() {
            count += 1;
        }
        if return_err == chip_error_end_of_tlv!() {
            return Ok(count);
        }
        return Err(return_err);
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
        self.m_backing_store = backing_store;
        self.m_read_point = ptr::null_mut();
        let mut buf_len: usize = 0;

        unsafe {
            (*self.m_backing_store).on_init_reader(self as _, ptr::addr_of_mut!(self.m_read_point), ptr::addr_of_mut!(buf_len))?;
            self.m_buf_end = self.m_read_point.add(buf_len as usize);
        }

        self.m_len_read = 0;
        self.m_max_len = max_len as usize;
        self.clear_element_state();
        self.m_container_type = TlvType::KtlvTypeNotSpecified;
        self.set_container_open(false);
        self.m_implicit_profile_id = TlvCommonProfiles::KprofileIdNotSpecified as u32;

        self.m_app_data = ptr::null_mut();
        
        chip_ok!()
    }

    fn next(&mut self) -> ChipErrorResult {
        self.skip()?;
        let _ = self.read_element()?;

        let elem_type = self.get_element_type();

        verify_or_return_error!(elem_type != TlvElementType::EndOfContainer,
            Err(chip_error_end_of_tlv!()));

        if tlv_types::tlv_type_is_string(elem_type) && self.get_length() != 0 {
            self.ensure_data(chip_error_tlv_underrun!())?;
        }

        chip_ok!()
    }

    fn next_tag(&mut self, expected_tag: Tag) -> ChipErrorResult {
        self.next()?;
        self.expect(expected_tag)?;
        chip_ok!()
    }

    fn expect(&mut self, expected_tag: Tag) -> ChipErrorResult {
        verify_or_return_error!(self.get_type() != TlvType::KtlvTypeNotSpecified,
            Err(chip_error_wrong_tlv_type!()));
        verify_or_return_error!(self.get_tag() == expected_tag,
            Err(chip_error_unexpected_tlv_element!()));
        chip_ok!()
    }

    fn next_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult {
        self.next()?;
        self.expect_type_tag(expected_type, expected_tag)?;
        chip_ok!()
    }

    fn expect_type_tag(&mut self, expected_type: TlvType, expected_tag: Tag) -> ChipErrorResult {
        verify_or_return_error!(self.get_type() == expected_type,
            Err(chip_error_wrong_tlv_type!()));
        verify_or_return_error!(self.get_tag() == expected_tag,
            Err(chip_error_unexpected_tlv_element!()));
        chip_ok!()
    }

    fn get_type(&self) -> TlvType {
        let ele_type = self.get_element_type();
        match ele_type {
            TlvElementType::EndOfContainer => {
                TlvType::KtlvTypeNotSpecified
            },
            TlvElementType::FloatingPointNumber32 | TlvElementType::FloatingPointNumber64 => {
                TlvType::KtlvTypeFloatingPointNumber
            },
            TlvElementType::NotSpecified | TlvElementType::Null => {
                return TlvType::from(ele_type as i16);
            },
            _ => {
                return TlvType::from(((ele_type as u8) & !(TLVTypeMask::KTLVTypeSizeMask as u8)) as i16);
            }
        }
    }

    fn get_tag(&self) -> Tag {
        self.m_elem_tag
    }

    fn get_length(&self) -> usize {
        if tlv_types::tlv_type_has_length(self.get_element_type()) {
            return self.m_elem_len_or_val.try_into().unwrap();
        }
        0
    }

    fn get_control_byte(&self) -> u16 {
        tlv_common::KTLVCONTROL_BYTE_NOT_SPECIFIED
    }

    fn get_boolean(&self) -> Result<bool, ChipError> {
        let ele_type = self.get_element_type();
        match ele_type {
            TlvElementType::BooleanFalse => {
                Ok(false)
            },
            TlvElementType::BooleanTrue => {
                Ok(true)
            },
            _ => {
                Err(chip_error_wrong_tlv_type!())
            }
        }
    }

    fn get_i8(&self) -> Result<i8, ChipError> {
        let vi64 = self.get_i64()?;

        if let Ok(vi8) = i8::try_from(vi64) {
            return Ok(vi8);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_i16(&self) -> Result<i16, ChipError> {
        let vi64 = self.get_i64()?;

        if let Ok(vi16) = i16::try_from(vi64) {
            return Ok(vi16);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_i32(&self) -> Result<i32, ChipError> {
        let vi64 = self.get_i64()?;

        if let Ok(vi32) = i32::try_from(vi64) {
            return Ok(vi32);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_u8(&self) -> Result<u8, ChipError> {
        let vu64 = self.get_u64()?;

        if let Ok(vu8) = u8::try_from(vu64) {
            return Ok(vu8);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_u16(&self) -> Result<u16, ChipError> {
        let vu64 = self.get_u64()?;

        if let Ok(vu16) = u16::try_from(vu64) {
            return Ok(vu16);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_u32(&self) -> Result<u32, ChipError> {
        let vu64 = self.get_u64()?;

        if let Ok(vu32) = u32::try_from(vu64) {
            return Ok(vu32);
        }

        Err(chip_error_invalid_integer_value!())
    }

    fn get_i64(&self) -> Result<i64, ChipError> {
        match self.get_element_type() {
            TlvElementType::Int8 => {
                Ok((self.m_elem_len_or_val as i8) as i64)
            },
            TlvElementType::Int16 => {
                Ok((self.m_elem_len_or_val as i16) as i64)
            },
            TlvElementType::Int32 => {
                Ok((self.m_elem_len_or_val as i32) as i64)
            },
            TlvElementType::Int64 => {
                Ok(self.m_elem_len_or_val as i64)
            },
            _ => {
                Err(chip_error_wrong_tlv_type!())
            }
        }
    }

    fn get_u64(&self) -> Result<u64, ChipError> {
        match self.get_element_type() {
            TlvElementType::UInt8 | TlvElementType::UInt16 | TlvElementType::UInt32 | TlvElementType::UInt64 => {
                Ok(self.m_elem_len_or_val)
            },
            _ => {
                Err(chip_error_wrong_tlv_type!())
            }
        }
    }

    fn get_bytes(&mut self) -> Result<&[u8], ChipError> {
        let val = self.get_data_ptr()?;

        unsafe {
            return Ok(core::slice::from_raw_parts(val, self.get_length()));
         }
    }

    fn get_bytes_raw(&mut self, buf: * mut u8, buf_len: usize) -> ChipErrorResult {
        verify_or_return_error!(tlv_types::tlv_type_is_string(self.get_element_type()),
          Err(chip_error_wrong_tlv_type!()));

        if self.m_elem_len_or_val > buf_len as u64 {
            return Err(chip_error_buffer_too_small!());
        }

        unsafe {
            let mut buf_slice = core::slice::from_raw_parts_mut(buf, self.m_elem_len_or_val as usize);

            self.read_data(buf_slice)?;
        }

        self.m_elem_len_or_val = 0;

        chip_ok!()
    }

    fn get_string(&mut self) -> Result<Option<&str>, ChipError> {
        verify_or_return_error!(tlv_types::tlv_type_is_utf8_string(self.get_element_type()),
          Err(chip_error_wrong_tlv_type!()));

        let val = self.get_data_ptr()?;

        if val.is_null() {
            return Ok(None);
        }
        unsafe {
            let end = core::slice::from_raw_parts(val, self.get_length()).iter().position(|&b| b == 0x1F).
                unwrap_or(self.get_length());

            return Ok(core::str::from_utf8(core::slice::from_raw_parts(val, end)).ok());
        }
    }

    fn get_string_raw(&mut self, buf: * mut u8, buf_size: usize) -> ChipErrorResult {
        verify_or_return_error!(tlv_types::tlv_type_is_string(self.get_element_type()),
          Err(chip_error_wrong_tlv_type!()));

        if (self.m_elem_len_or_val + 1)> buf_size as u64 {
            return Err(chip_error_buffer_too_small!());
        }

        unsafe {
            *buf.add(self.m_elem_len_or_val as usize) = 0;
        }

        return self.get_bytes_raw(buf, buf_size - 1);
    }


    fn enter_container(&mut self) -> Result<TlvType, ChipError> {
        let elem_type = self.get_element_type();
        verify_or_return_error!(!tlv_types::tlv_elem_type_is_container(elem_type),
            Err(chip_error_incorrect_state!()));

        let outer_container_type = self.m_container_type;
        self.m_container_type = TlvType::from(elem_type);

        self.clear_element_state();
        self.set_container_open(false);

        return Ok(outer_container_type);
    }

    fn exit_container(&mut self, outer_container_type: TlvType) -> ChipErrorResult {
        self.skip_to_end_of_container()?;

        self.m_container_type = outer_container_type;
        self.clear_element_state();

        chip_ok!()
    }

    fn open_container(&mut self, reader: &mut Self) -> ChipErrorResult {
        let elem_type = self.get_element_type();
        if !tlv_types::tlv_elem_type_is_container(elem_type) {
            return Err(chip_error_incorrect_state!());
        }
        reader.m_backing_store = self.m_backing_store;
        reader.m_read_point = self.m_read_point;
        reader.m_buf_end = self.m_buf_end;
        reader.m_len_read = self.m_len_read;
        reader.m_max_len = self.m_max_len;
        reader.clear_element_state();
        reader.m_container_type = TlvType::from(elem_type);
        reader.set_container_open(false);
        reader.m_implicit_profile_id = self.m_implicit_profile_id;
        reader.m_app_data = self.m_app_data;

        self.set_container_open(true);

        chip_ok!()
    }

    fn close_container(&mut self, reader: &mut Self) -> ChipErrorResult {
        if !self.is_container_open() {
            return Err(chip_error_incorrect_state!());
        }

        if TlvElementType::from_container_type(reader.m_container_type) != self.get_element_type() {
            return Err(chip_error_incorrect_state!());
        }

        self.skip_to_end_of_container()?;

        self.m_backing_store = reader.m_backing_store;
        self.m_read_point = reader.m_read_point;
        self.m_buf_end = reader.m_buf_end;
        self.m_len_read = reader.m_len_read;
        self.m_max_len = reader.m_max_len;

        self.clear_element_state();

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
        let elem_type = self.get_element_type();
        verify_or_return_error!(elem_type != TlvElementType::EndOfContainer,
            Err(chip_error_end_of_tlv!()));

        if tlv_types::tlv_elem_type_is_container(elem_type) {
            let mut outer_container_type = self.enter_container()?;
            return self.exit_container(outer_container_type);
        }

        self.skip_data()?;
        self.clear_element_state();

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

        fn setup_with_values(buf: &[u8]) -> TheTlvReader {
            let mut reader = TheTlvReader::const_default();
            unsafe {
                //BUFFER.fill(0);
                reader.init(buf.as_ptr(), buf.len());
            }
            return reader;
        }

        #[test]
        fn init() {
            let reader = setup();
            assert_eq!(1,1);
        }

        #[test]
        fn get_boolean_false() {
            let mut reader = setup_with_values(&[0x08]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true,reader.get_boolean().is_ok_and(|v| v == false));
        }

        #[test]
        fn get_boolean_true() {
            let mut reader = setup_with_values(&[0x09]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true,reader.get_boolean().is_ok_and(|v| v == true));
        }

        #[test]
        fn get_i8_value_42() {
            let mut reader = setup_with_values(&[0x00, 0x2a]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true,reader.get_i8().is_ok_and(|v| v == 42));
        }

        #[test]
        fn get_i8_value_neg_17() {
            let mut reader = setup_with_values(&[0x00, 0xef]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_i8().inspect_err(|e| println!("get i8 err {}", e)).is_ok_and(|v| v == -17));
        }

        #[test]
        fn get_u8_value_neg_42() {
            let mut reader = setup_with_values(&[0x04, 0x2a]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_u8().inspect_err(|e| println!("get u8 err {}", e)).is_ok_and(|v| v == 42));
        }

        #[test]
        fn get_i16_value_42() {
            let mut reader = setup_with_values(&[0x01, 0x2a, 0x00]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_i16().inspect_err(|e| println!("get i16 err {}", e)).is_ok_and(|v| v == 42));
        }

        #[test]
        fn get_i32_value_neg_170000() {
            let mut reader = setup_with_values(&[0x02, 0xf0, 0x67, 0xfd, 0xff]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_i32().inspect_err(|e| println!("get i32 err {}", e)).is_ok_and(|v| v == -170000));
        }

        #[test]
        fn get_i64_value_40000000000() {
            let mut reader = setup_with_values(&[0x03 ,0x00 ,0x90 ,0x2f ,0x50 ,0x09 ,0x00 ,0x00 ,0x00]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_i64().inspect_err(|e| println!("get i64 err {}", e)).is_ok_and(|v| v == 40000000000));
        }

        #[test]
        fn get_UTF8_string_1_byte_length_hello() {
            let mut reader = setup_with_values(&[0x0c ,0x06 ,0x48 ,0x65 ,0x6c ,0x6c ,0x6f ,0x21]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_string().inspect_err(|e| println!("get string err {}", e)).is_ok_and(|s| s.is_some_and(|ss| ss == "Hello!")));
        }

        #[test]
        fn get_octet_string_1_byte_length_0_4() {
            let mut reader = setup_with_values(&[0x10 ,0x05 ,0x00 ,0x01 ,0x02 ,0x03 ,0x04]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(true, reader.get_bytes().inspect_err(|e| println!("get string err {}", e)).is_ok_and(|s| s.len() == 5 && s[0] == 0x00 && 
                    s[1] == 0x01 && s[2] == 0x02 && s[3] == 0x03 && s[4] == 0x04 ));
        }

        #[test]
        fn get_null() {
            let mut reader = setup_with_values(&[0x14]);
            assert_eq!(true, reader.next().inspect_err(|e| println!("next err {}", e)).is_ok());
            assert_eq!(TlvType::KtlvTypeNull, reader.get_type());
        }
    }
}
