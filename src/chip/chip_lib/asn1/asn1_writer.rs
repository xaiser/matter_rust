use crate::{
    chip_sdk_error,
    chip_asn1_error,
    asn1_error_unsupported_encoding,
    asn1_error_overflow,
    verify_or_return_error,
    verify_or_return_value,
    chip::asn1::{Tag, Class},
    ChipErrorResult,
    chip_ok,
};

mod FieldLength {
    pub const K_UNKNOWN_LENGTH: i32 = -1;
    pub const K_LENGTH_FIELD_RESERVE_SIZE: u8 = 1;
    pub const K_UNKNOWN_LENGTH_MARKER: u8 = 0xFF;
}

pub trait ASN1Writer {
    fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult;
    fn get_length_written(&self) -> usize;
    fn put_value(&mut self, class: Class, tag: Tag, is_constructed: bool, value: &[u8]) -> ChipErrorResult;
}

#[derive(Default)]
pub struct NullASN1Writer;

impl ASN1Writer for NullASN1Writer {
    fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult {
        chip_ok!()
    }
    fn get_length_written(&self) -> usize { 0 }
    fn put_value(&mut self, _class: Class, _tag: Tag, _is_constructed: bool, _value: &[u8]) -> ChipErrorResult {
        chip_ok!()
    }
}

pub struct TestASN1Writer<'a> {
    m_buf: Option<&'a mut [u8]>,
    m_write_point: usize,
}

impl<'a> Default for TestASN1Writer<'_> {
    fn default() -> Self {
        TestASN1Writer::new()
    }
}

impl<'a> TestASN1Writer<'a> {
    pub const fn new() -> Self {
        Self {
            m_buf: None,
            m_write_point: 0,
        }
    }

    pub fn init(&mut self, buf: &'a mut [u8]) {
        self.m_buf = Some(buf);
        self.m_write_point = 0;
    }

    fn bytes_for_length(len: i32) -> u8 {
        match len {
            v if v == FieldLength::K_UNKNOWN_LENGTH => {
                FieldLength::K_LENGTH_FIELD_RESERVE_SIZE
            },
            v if v < 128 => {
                1
            },
            v if v < 65536 => {
                2
            },
            v if v < (1 << 24) => {
                4
            },
            _ => {
                5
            }
        }
    }

    fn encode_length(buf: &'a mut [u8], mut bytes_for_len: u8, mut len_to_encode: i32) {
        if bytes_for_len == 1 {
            buf[0] = len_to_encode as u8;
        } else {
            bytes_for_len -= 1;
            buf[0] = 0x80u8 | bytes_for_len;
            while bytes_for_len > 0 {
                buf[bytes_for_len as usize] = len_to_encode as u8;
                len_to_encode = len_to_encode >> 8;
                bytes_for_len -= 1;
            }
        }
    }
}

impl<'a> ASN1Writer for TestASN1Writer<'a> {
    fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult {
        verify_or_return_error!(tag < 0x1Fu8, Err(asn1_error_unsupported_encoding!()));

        verify_or_return_error!(len >= 0 || len == FieldLength::K_UNKNOWN_LENGTH, Err(asn1_error_unsupported_encoding!()));

        let bytes_for_len = TestASN1Writer::bytes_for_length(len);

        // Make sure there's enough space to encode the entire value.
        // Note that the calculated total length doesn't overflow because `len` is a signed value (int32_t).
        // Note that if `len` is not kUnknownLength then it is non-negative (`len` >= 0).
        let total_len: u32 = 1u32 + (bytes_for_len as u32) + { if len != FieldLength::K_UNKNOWN_LENGTH { len as u32 } else { 0u32 } };

        if let Some(m_buf) = self.m_buf.as_mut() {
            verify_or_return_error!(self.m_write_point + (total_len as usize) <= m_buf.len(), Err(asn1_error_overflow!()));

            m_buf[self.m_write_point] = cls | { if is_constructed { 0x20u8 } else { 0u8} } | tag;
            self.m_write_point += 1;
            if len != FieldLength::K_UNKNOWN_LENGTH {
                TestASN1Writer::encode_length(&mut m_buf[self.m_write_point..], bytes_for_len, len);
            }
        }



        chip_ok!()
    }
    fn get_length_written(&self) -> usize { 0 }
    fn put_value(&mut self, _class: Class, _tag: Tag, _is_constructed: bool, _value: &[u8]) -> ChipErrorResult {
        chip_ok!()
    }
}
