use crate::{
    chip::asn1::{Tag, Class, Oid},
    ChipErrorResult,
};

mod FieldLength {
    pub const K_UNKNOWN_LENGTH: i32 = -1;
    pub const K_LENGTH_FIELD_RESERVE_SIZE: u8 = 1;
    pub const K_UNKNOWN_LENGTH_MARKER: u8 = 0xFF;
}

pub trait Asn1Writer {
    fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult;
    fn get_length_written(&self) -> usize;
    fn put_value(&mut self, class: Class, tag: Tag, is_constructed: bool, value: &[u8]) -> ChipErrorResult;
    fn put_string(&mut self, tag: Tag, value: &str) -> ChipErrorResult;

    fn put_object_id(&mut self, oid: Oid) -> ChipErrorResult {
        let bytes = oid.to_be_bytes();
        return self.put_object_id_raw(&bytes);
    }

    fn put_object_id_raw(&mut self, value: &[u8]) -> ChipErrorResult;
}

mod asn1_writer {
    use crate::{
        chip_sdk_error,
        chip_asn1_error,
        asn1_error_unsupported_encoding,
        asn1_error_overflow,
        asn1_error_invalid_state,
        verify_or_return_error,
        verify_or_return_value,
        chip::asn1::{Oid, Tag, Class, Asn1TagClasses, Asn1UniversalTag},
        ChipErrorResult,
        chip_ok,
    };

    use super::*;

    #[derive(Default)]
    pub struct NullAsn1Writer;

    impl Asn1Writer for NullAsn1Writer {
        fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult {
            chip_ok!()
        }
        fn get_length_written(&self) -> usize { 0 }
        fn put_value(&mut self, _class: Class, _tag: Tag, _is_constructed: bool, _value: &[u8]) -> ChipErrorResult {
            chip_ok!()
        }

        fn put_string(&mut self, tag: Tag, value: &str) -> ChipErrorResult {
            chip_ok!()
        }

        fn put_object_id_raw(&mut self, _value: &[u8]) -> ChipErrorResult {
            chip_ok!()
        }
    }

    pub struct TestAsn1Writer<'a> {
        m_buf: Option<&'a mut [u8]>,
        m_write_point: usize,
    }

    impl<'a> Default for TestAsn1Writer<'_> {
        fn default() -> Self {
            TestAsn1Writer::new()
        }
    }

    impl<'a> TestAsn1Writer<'a> {
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

        fn write_data(&mut self, data: &[u8]) -> ChipErrorResult {
            if let Some(m_buf) = self.m_buf.as_mut() {
                verify_or_return_error!(self.m_write_point + data.len() <= m_buf.len(), Err(asn1_error_overflow!()));
                m_buf[self.m_write_point..self.m_write_point + data.len()].copy_from_slice(data);
                self.m_write_point += data.len();
            }

            chip_ok!()
        }
    }

    impl<'a> Asn1Writer for TestAsn1Writer<'a> {
        fn encode_head(&mut self, cls: Class, tag: Tag, is_constructed: bool, len: i32) -> ChipErrorResult {
            verify_or_return_error!(tag < 0x1Fu8, Err(asn1_error_unsupported_encoding!()));

            verify_or_return_error!(len >= 0 || len == FieldLength::K_UNKNOWN_LENGTH, Err(asn1_error_unsupported_encoding!()));

            let bytes_for_len = TestAsn1Writer::bytes_for_length(len);

            // Make sure there's enough space to encode the entire value.
            // Note that the calculated total length doesn't overflow because `len` is a signed value (int32_t).
            // Note that if `len` is not kUnknownLength then it is non-negative (`len` >= 0).
            let total_len: u32 = 1u32 + (bytes_for_len as u32) + { if len != FieldLength::K_UNKNOWN_LENGTH { len as u32 } else { 0u32 } };

            if let Some(m_buf) = self.m_buf.as_mut() {
                verify_or_return_error!(self.m_write_point + (total_len as usize) <= m_buf.len(), Err(asn1_error_overflow!()));

                m_buf[self.m_write_point] = cls | { if is_constructed { 0x20u8 } else { 0u8} } | tag;
                self.m_write_point += 1;
                if len != FieldLength::K_UNKNOWN_LENGTH {
                    TestAsn1Writer::encode_length(&mut m_buf[self.m_write_point..], bytes_for_len, len);
                } else {
                    // TODO: we do not support unknow lenght yet.
                    return Err(asn1_error_invalid_state!());
                }

                self.m_write_point += bytes_for_len as usize;
            } else {
                // if no buffer, just return success in case we use null pointer as NullWriter
            }

            chip_ok!()
        }

        fn get_length_written(&self) -> usize { self.m_write_point }

        fn put_value(&mut self, class: Class, tag: Tag, is_constructed: bool, value: &[u8]) -> ChipErrorResult {
            self.encode_head(class, tag, is_constructed, value.len() as i32)?;
            return self.write_data(value);
        }

        fn put_string(&mut self, tag: Tag, value: &str) -> ChipErrorResult {
            return self.put_value(Asn1TagClasses::Kasn1TagClassUniversal as u8, tag, false, value.as_bytes());
        }

        fn put_object_id_raw(&mut self, value: &[u8]) -> ChipErrorResult {
            return self.put_value(Asn1TagClasses::Kasn1TagClassUniversal as u8, Asn1UniversalTag::Kasn1UniversalTagObjectId as Tag, false, value);
        }
    }

    #[cfg(test)]
    pub(super) mod tests {
        use super::*;

        #[test]
        fn encode_header_correctly() {
            let mut writer = TestAsn1Writer::default();
            let mut buf = [0xFFu8; 32];
            writer.init(&mut buf);

            assert!(writer.encode_head(0x20, 0x01, false, 1).is_ok());
            assert_eq!(0x21, buf[0]);
            assert_eq!(1, buf[1]);
        }

        #[test]
        fn encode_header_correctlly_with_len_bigger_than_128() {
            let mut writer = TestAsn1Writer::default();
            let mut buf = [0xFFu8; 256];
            writer.init(&mut buf);

            assert!(writer.encode_head(0x20, 0x01, false, 129).is_ok());
            assert_eq!(0x21, buf[0]);
            assert_eq!(0x81, buf[1]);
            assert_eq!(0x81, buf[2]);
        }

        #[test]
        fn put_string_successfully() {
            let mut writer = TestAsn1Writer::default();
            let mut buf = [0xFFu8; 256];
            writer.init(&mut buf);

            writer.put_string(0, "12");
            assert_eq!(4, writer.get_length_written());
            assert_eq!(0x0, buf[0]);
            assert_eq!(0x2, buf[1]);
            assert_eq!(b'1', buf[2]);
            assert_eq!(b'2', buf[3]);
        }
    }
} // end of asn1_writer

pub use asn1_writer::*;
