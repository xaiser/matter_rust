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
    m_buf: Option<&'a [u8]>,
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
    pub const fn const_default() -> Self {
        Self {
            m_app_data: ptr::null_mut(),
            m_implicit_profile_id: TlvCommonProfiles::KprofileIdNotSpecified as u32,
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
}
