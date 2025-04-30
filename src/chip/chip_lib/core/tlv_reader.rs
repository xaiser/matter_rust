use super::tlv_tags::Tag;
use super::tlv_types::TlvType;
use super::tlv_backing_store::TlvBackingStore;
use crate::ChipErrorResult;
use crate::ChipError;

pub trait TlvReader<'a> {
    type BackingStoreType;

    fn init(&mut self, data: &'a [u8]);

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

    fn open_container(&mut self) -> Result<Self, ChipError>;

    fn close_container(&mut self, reader: Self) -> ChipErrorResult;

    fn get_container_type(&self) -> TlvType;

    fn verify_end_of_container(&mut self) -> ChipErrorResult;

    fn get_backing_store(&mut self) -> * mut BackingStoreType;

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
    m_backing_store: * mut TlvBackingStore,
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
}

/*
impl<BackingStoreType> TlvReader for TlvReaderBasic<BackingStoreType> {
    type BackingStoreType = BackingStoreType;
}
*/
