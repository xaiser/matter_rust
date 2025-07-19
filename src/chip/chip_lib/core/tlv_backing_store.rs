use super::tlv_writer::TlvWriter;
use super::tlv_reader::TlvReader;
use crate::ChipErrorResult;
use crate::chip_ok;

pub trait TlvBackingStore {
    fn on_init_writer<TlvWriterType: TlvWriter>(&mut self, writer: * mut TlvWriterType, buf: * mut * mut u8, buf_len: * mut usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn on_init_reader<TlvReaderType: TlvReader>(&mut self, reader: * mut TlvReaderType, buf: * mut * const u8, buf_len: * mut usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn finalize_buffer<TlvWriterType: TlvWriter>(&mut self, writer: * mut TlvWriterType, buf: * mut u8, buf_len: usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_next_buffer<TlvReaderType: TlvReader>(&mut self, reader: * mut TlvReaderType, buf: * mut * const u8, buf_len: * mut usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_new_buffer<TlvWriterType: TlvWriter>(&mut self, writer: * mut TlvWriterType, buf: * mut * mut u8, buf_len: &mut usize) -> ChipErrorResult {
        chip_ok!()
    }

    fn get_new_buffer_will_always_fail(&self) -> bool;
}
