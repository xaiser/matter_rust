use crate::{
    chip::asn1::{Tag, Class},
    ChipErrorResult,
    chip_ok,
};

pub trait ASN1Writer {
    fn get_length_written(&self) -> usize;
    fn put_value(class: Class, tag: Tag, is_constructed: bool, value: &[u8]) -> ChipErrorResult;
}

#[derive(Default)]
pub struct NullASN1Writer;

impl ASN1Writer for NullASN1Writer {
    fn get_length_written(&self) -> usize { 0 }
    fn put_value(_class: Class, _tag: Tag, _is_constructed: bool, _value: &[u8]) -> ChipErrorResult {
        chip_ok!()
    }
}
