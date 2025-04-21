use super::tlv_tags::Tag;
use super::tlv_types::TlvType;
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

    fn get_u8(&self) -> Result<u8, ChipError>;
}
