use super::tlv_backing_store::TlvBackingStore;
use super::tlv_types::{TlvType,TlvElementType};
use super::tlv_types;
use super::tlv_tags::{Tag,TlvCommonProfiles,TLVTagControl};
use super::tlv_tags;

use crate::chip::chip_lib::support::buffer_writer::little_endian::BufferWriter as LittleEndianBufferWriter;
use crate::chip::chip_lib::support::buffer_writer::BufferWriter;

use crate::ChipErrorResult;
use crate::chip_ok;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_internal;
use crate::chip_error_incorrect_state;
use crate::chip_error_tlv_container_open;
use crate::chip_error_no_memory;
use crate::chip_error_invalid_tlv_tag;
use crate::chip_error_buffer_too_small;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::verify_or_die;

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
            (*self.m_backing_store).on_init_writer(self as * mut Self, ptr::addr_of_mut!(self.m_buf_start), ptr::addr_of_mut!(self.m_remaining_len))?;
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

    fn write_element_head(&mut self, e_type: TlvElementType, tag: Tag, len_or_val: u64) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(!self.is_container_open(), Err(chip_error_tlv_container_open!()));

        let mut staging_buf: [u8; 17] = [0; 17];
        let tag_num: u32 = tlv_tags::tag_num_from_tag(&tag);

        let mut writer: LittleEndianBufferWriter = LittleEndianBufferWriter::default_with_buf(&mut staging_buf[..]);

        if tlv_tags::is_special_tag(&tag) {
            if tag_num <= tlv_tags::SpecialTagNumber::KContextTagMaxNum as u32 {
                if (self.m_container_type != TlvType::KtlvTypeStructure) &&
                    (self.m_container_type != TlvType::KtlvTypeList) {
                    return Err(chip_error_invalid_tlv_tag!());
                }

                writer.put_u8(TLVTagControl::ContextSpecific as u8 | e_type as u8);
                writer.put_u8(tag_num as u8);
            } else {
                if (e_type != TlvElementType::EndOfContainer) &&
                    (self.m_container_type != TlvType::KtlvTypeNotSpecified) && 
                    (self.m_container_type != TlvType::KtlvTypeArray) && 
                    (self.m_container_type != TlvType::KtlvTypeList) {
                    return Err(chip_error_invalid_tlv_tag!());
                }
                writer.put_u8(TLVTagControl::Anonymous as u8 | e_type as u8);
            }
        } else {
            let profile_id: u32 = tlv_tags::profile_id_from_tag(&tag);

            if (self.m_container_type != TlvType::KtlvTypeNotSpecified) &&
                (self.m_container_type != TlvType::KtlvTypeStructure) && 
                    (self.m_container_type != TlvType::KtlvTypeList) {
                    return Err(chip_error_invalid_tlv_tag!());
            }

            if profile_id == TlvCommonProfiles::KcommonProfileId as u32{
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

    fn write_data(&mut self, buf: &[u8], mut len: usize) -> ChipErrorResult {
        verify_or_return_error!(self.is_initialized(), Err(chip_error_incorrect_state!()));
        verify_or_return_error!((self.m_len_written + len) <= self.m_max_len, Err(chip_error_buffer_too_small!()));
        let mut p_buf: * const u8 = buf.as_ptr();

        while len > 0 {
            if self.m_remaining_len == 0 {
                verify_or_return_error!(self.m_backing_store.is_null() == false, Err(chip_error_no_memory!()));
                unsafe {
                    verify_or_return_error!(self.m_write_point.offset_from(self.m_buf_start) > 0, Err(chip_error_incorrect_state!()));
                    verify_or_return_error!((self.m_write_point.offset_from(self.m_buf_start) as u64) < (u32::MAX as u64), Err(chip_error_incorrect_state!()));

                    (*self.m_backing_store).finalize_buffer(
                        self as * mut Self, self.m_buf_start, self.m_write_point.offset_from(self.m_buf_start) as usize)?;
                    (*self.m_backing_store).get_new_buffer(self as * mut Self, &mut self.m_buf_start, &mut self.m_remaining_len)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use std::*;
    use crate::chip::chip_lib::core::tlv_backing_store::TlvBackingStore;

    mod no_backing {
        use super::*;
        use super::super::*;
        use std::*;

        struct DummyBackStore;
        impl TlvBackingStore for DummyBackStore {
            fn on_init_writer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, _buf: * mut * mut u8, _buf_len: * mut usize) -> ChipErrorResult {
                chip_ok!()
            }

            fn finalize_buffer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, _buf: * mut u8, _buf_len: usize) -> ChipErrorResult {
                chip_ok!()
            }

            fn get_new_buffer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, _buf: * mut * mut u8, _buf_len: &mut usize) -> ChipErrorResult {
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
        fn write_element_head() {
            let mut writer = setup();
            assert_eq!(true, writer.is_initialized());
        }
    }

    /*
    const TMP_BUF_LEN: usize = 64;

    struct VecBackingStore {
        m_back: Vec<Vec<u8>>,
        m_current: [u8; TMP_BUF_LEN],
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
        fn on_init_writer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, mut buf: * mut * mut u8, buf_len: * mut usize) -> ChipErrorResult {
            self.reset();

            unsafe {
                *buf = self.m_current.as_mut_ptr();
                *buf_len = TMP_BUF_LEN;
            }

            chip_ok!()
        }

        fn finalize_buffer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, buf: * mut u8, buf_len: usize) -> ChipErrorResult {
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

        fn get_new_buffer<TlvWriterType: TlvWriter>(&mut self, _writer: * mut TlvWriterType, buf: * mut * mut u8, buf_len: &mut usize) -> ChipErrorResult {
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

    fn setup() -> VecBackingStore {
        let back = VecBackingStore::default();
    }

    #[test]
    fn init() {
        assert_eq!(1, 1);
    }
    */
}
