use crate::ChipError;
use crate::chip_no_error;


pub trait BufferReader<'a> {
    fn init(&mut self, buffer: &'a [u8]);

    fn octets_read(&self) -> usize;

    fn remaining(&self) -> usize;

    fn has_at_least(&self, octets: usize) -> bool {
        octets < self.remaining()
    }

    fn status_code(&self) -> ChipError;

    fn is_sueccess(&self) -> bool {
        self.status_code() == chip_no_error!()
    }

    /**
     * Read a byte string from the BufferReader
     *
     * @param [out] dest Where the bytes read
     * @param [in] size How many bytes to read
     *
     * @note The read can put the reader in a failed-status state if there are
     *       not enough octets available.  Callers must either continue to do
     *       more reads on the return value or check its status to see whether
     *       the sequence of reads that has been performed succeeded.
     */
    fn read_bytes(self, dest: &mut [u8]) -> Self;

    /**
     * Access bytes of size length, useful for in-place processing of strings
     *
     * data_ptr MUST NOT be null and will contain the data pointer with `len` bytes available
     * if this call is successful
     *
     * If len is greater than the number of available bytes, the object enters in a failed status.
     */
    fn zero_copy_process_bytes(self, data: &mut [u8]) -> Self;

    /**
     * Advance the Reader forward by the specified number of octets.
     *
     * @param len The number of octets to skip.
     *
     * @note If the len argument is greater than the number of available octets
     *       remaining, the Reader will advance to the end of the buffer
     *       without entering a failed-status state.
     */
    fn skip(self, len: usize) -> Self;

    fn ensure_available(&mut self, size: usize) -> bool;
}

pub mod little_endian {
    use crate::ChipError;
    use crate::chip_no_error;
    use crate::chip_core_error;
    use crate::chip_sdk_error;

    use core::ptr;

    pub struct Reader<'a> {
        m_buf: &'a [u8],
        m_read_ptr: usize,
        m_available: usize,
        m_status: ChipError,
    }

    impl Reader<'_> {
        pub const fn const_default() -> Self {
            Reader {
                m_buf: &[],
                m_read_ptr: 0,
                m_available: 0,
                m_status: chip_no_error!(),
            }
        }
    }

    impl<'a> super::BufferReader<'a> for Reader<'a> {
        fn init(&mut self, buffer: &'a [u8]) {
            self.m_buf = buffer;
            self.m_available = buffer.len();
            self.m_read_ptr = 0;
        }

        fn octets_read(&self) -> usize {
            self.m_read_ptr
        }

        fn remaining(&self) -> usize {
            self.m_available
        }

        fn status_code(&self) -> ChipError {
            self.m_status.clone()
        }

        fn read_bytes(mut self, dest: &mut [u8]) -> Self {
            let size: usize = dest.len();
            if self.ensure_available(size) {
                unsafe {
                    ptr::copy_nonoverlapping(self.m_buf.as_ptr().wrapping_add(self.m_read_ptr), dest.as_mut_ptr(), size);
                }
                self.m_read_ptr += size;
                self.m_available -= size;
            }
            self
        }

        fn zero_copy_process_bytes(mut self, data: &mut [u8]) -> Self {
            self
        }

        fn skip(mut self, len: usize) -> Self {
            self
        }

        fn ensure_available(&mut self, size: usize) -> bool {
            false
        }
    }
}

