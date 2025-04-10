use super::tlv_backing_store::TlvBackingStore;
use super::tlv_types::TlvType;
use super::tlv_tags::TlvCommonProfiles;

use core::ptr;

pub struct TlvWriterBasic<'a, BackingStoreType> 
where
    BackingStoreType: TlvBackingStore,
{
    pub m_app_data: * mut u8,
    pub m_implicit_profile_id: u32,
    m_backing_store: * mut BackingStoreType,
    m_buf: Option<&'a mut [u8]>,
    m_write_point: usize,
    m_remaining_len: usize,
    m_len_written: usize,
    m_max_len: usize,
    m_reserved_size: usize,
    m_container_type: TlvType,
    m_initiialization_cookie: u16,
    m_container_open: bool,
    m_close_container_recerved: bool,
}

impl<'a, BackingStoreType> TlvWriterBasic<'a, BackingStoreType> 
where
    BackingStoreType: TlvBackingStore,
{
    pub const KEXPECTED_INITIALIZATION_COOKIE: u16 = 0x52b1;

    pub const fn const_default() -> Self {
        Self {
            m_app_data: ptr::null_mut(),
            m_implicit_profile_id: TlvCommonProfiles::KprofileIdNotSpecified.into(),
            m_backing_store: ptr::null_mut(),
            m_buf: None,
            m_write_point: 0,
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

    pub fn init(&mut self, buf: Option<&'a mut [u8]>) {
        self.m_buf = buf;
        self.m_initiialization_cookie = 0;
        self.m_backing_store = ptr::null_mut();
        self.m_write_point = 0;
        self.m_remaining_len = buf.len();;
        self.m_len_written = 0;
        self.m_max_len = buf.len(),;
        self.m_container_type = TlvType::KtlvTypeNotSpecified;
        self.m_reserved_size = 0;
        self.m_implicit_profile_id = TlvCommonProfiles::KprofileIdNotSpecified.into();

        self.set_container_open(false);
        self.set_close_container_reserved(true);

        self.m_initiialization_cookie = Self::KEXPECTED_INITIALIZATION_COOKIE;
    }

    pub fn init_backing_store(&mut self, backing_store: * mut BackingStoreType, max_len: u32) {
        let actual_max_len: usize = if max_len > u32::MAX { u32::Max as usize } else { max_len as usize }
        self.init(None);
        self.m_max_len = actual_max_len;
        self.m_initiialization_cookie = 0;
        self.m_backing_store = backing_store;
        self.m_remaining_len = 0;
    }

    fn set_container_open(&mut self, container_open: bool) {
        self.m_container_open = container_open;
    }

    fn set_close_container_reserved(&mut self, close_container_reserved: bool) {
        self.m_close_container_recerved = close_container_reserved;
    }
}
