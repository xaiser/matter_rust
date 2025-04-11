use super::tlv_writer::TlvWriter;
use crate::ChipErrorResult;

pub trait TlvBackingStore {
    fn on_init_writer<TlvWriterType: TlvWriter>(&mut self, writer: * mut TlvWriterType, buf: * const * mut u8, buf_len: * mut usize) -> ChipErrorResult;

    fn finalize_buffer<TlvWriterType: TlvWriter>(&mut self, writer: * mut TlvWriterType, buf: * mut u8, buf_len: usize) -> ChipErrorResult;

    fn get_new_buffer_will_always_fail(&self) -> bool;
}
