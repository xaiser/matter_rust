use crate::ChipError;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;


pub trait BufferReader<'a> {
    fn default(buffer: &'a [u8]) -> Self;

    fn default_with_raw(buffer: * const u8, length: usize) -> Self;

    fn octets_read(&self) -> usize;

    fn remaining(&self) -> usize;

    fn has_at_least(&self, octets: usize) -> bool {
        octets < self.remaining()
    }

    fn status_code(&self) -> ChipError;

    fn is_success(&self) -> bool {
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
    fn read_bytes(&mut self, dest: &mut [u8]) -> &mut Self;
    fn read_bytes_with_raw(&mut self, dest: * mut u8, size: usize) -> &mut Self;

    /**
     * Access bytes of size length, useful for in-place processing of strings
     *
     * data_ptr MUST NOT be null and will contain the data pointer with `len` bytes available
     * if this call is successful
     *
     * If len is greater than the number of available bytes, the object enters in a failed status.
     */
    fn zero_copy_process_bytes(&mut self, len: usize, data: &mut &'a [u8]) -> &mut Self;

    /**
     * Advance the Reader forward by the specified number of octets.
     *
     * @param len The number of octets to skip.
     *
     * @note If the len argument is greater than the number of available octets
     *       remaining, the Reader will advance to the end of the buffer
     *       without entering a failed-status state.
     */
    fn skip(&mut self, len: usize) -> &mut Self;

    fn ensure_available(&mut self, size: usize) -> bool;
}

pub mod little_endian {
    use crate::ChipError;
    use crate::chip_no_error;
    use crate::chip_core_error;
    use crate::chip_sdk_error;
    use crate::chip_error_buffer_too_small;
    use crate::chip_static_assert;
    use crate::verify_or_return;
    use super::BufferReader;

    use core::ptr;
    use core::slice::from_raw_parts;
    use core::cmp::min;
    use core::mem::size_of;

    #[derive(Copy,Clone)]
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
        fn default(buffer: &'a [u8]) -> Self {
            Reader {
                m_buf: buffer,
                m_available: buffer.len(),
                m_read_ptr: 0,
                m_status: chip_no_error!(),
            }
        }

        fn default_with_raw(buffer: * const u8, length: usize) -> Self {
            unsafe {
                Reader {
                    m_buf: from_raw_parts(buffer, length),
                    m_available: length,
                    m_read_ptr: 0,
                    m_status: chip_no_error!(),
                }
            }
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

        fn read_bytes(&mut self, dest: &mut [u8]) -> &mut Self {
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

        fn read_bytes_with_raw(&mut self, dest: * mut u8, size: usize) -> &mut Self {
            if self.ensure_available(size) {
                unsafe {
                    ptr::copy_nonoverlapping(self.m_buf.as_ptr().wrapping_add(self.m_read_ptr), dest, size);
                }
                self.m_read_ptr += size;
                self.m_available -= size;
            }
            self
        }


        fn zero_copy_process_bytes(&mut self, len: usize, data: &mut &'a [u8]) -> &mut Self {
            // in case the windoes method panic
            if 0 == len {
                return self;
            }

            if let Some(window) = self.m_buf.windows(len).next() {
                if len > self.m_available {
                    *data = &[];
                    self.m_status = chip_error_buffer_too_small!();
                    self.m_available = 0;
                } else {
                    *data = window;
                    self.m_read_ptr += len;
                    self.m_available -= len;
                }
            } else {
                *data = &[];
                self.m_status = chip_error_buffer_too_small!();
                self.m_available = 0;
            }
            self
        }

        fn skip(&mut self, mut len: usize) -> &mut Self {
            len = min(len, self.m_available);
            self.m_read_ptr += len;
            self.m_available = (self.m_available - len) as usize;
            self
        }

        fn ensure_available(&mut self, size: usize) -> bool {
            if self.m_available < size {
                self.m_status = chip_error_buffer_too_small!();
                self.m_available = 0;
                return false;
            }
            return true;
        }
    }

    impl<'a> Reader<'a> {
        fn read_helper<T>(p: * const u8, dest: &mut T) {
            let result: T;
        }

        fn raw_read_low_level_be_careful<T: Default>(&mut self, ret_val: &mut T) {
            chip_static_assert!((-1 & 3) == 3, "LittleEndian::BufferReader only works with 2's complement architectures.");
            verify_or_return!(self.is_success());
            /*

            let data_size: usize = size_of::<T>();
            let mut result: [u8; 64] = [0; 64];
            let _ = self.read_bytes(&mut result[0..data_size]);
            *ret_val = T::from_le_byte(&result[0..data_size]);
            */
            let mut result: T = T::default();
            let _ = self.read_bytes_with_raw(ptr::addr_of_mut!(result) as * mut u8, size_of::<T>());

            let _a: u16 = u16::from_le_bytes([0x01, 0x01]);
        }

        pub fn read_bool(&mut self, dest: &mut bool) -> &mut Self {
            chip_static_assert!(size_of::<bool>() == 1, "Expect single-byte bool");
            return self;
        }
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  mod little_endian_reader {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::ChipError;
      use crate::chip_no_error;
      use crate::chip_core_error;
      use crate::chip_sdk_error;
      use crate::chip_error_buffer_too_small;

     static mut LITTLE_READER: super::super::little_endian::Reader = little_endian::Reader::const_default(); 
     static THE_DATA: [u8; 7] = [1,2,3,4,5,6,7];

     fn set_up() {
         unsafe {
             LITTLE_READER = little_endian::Reader::default(&THE_DATA[0..3]); 
         }
     }

      
      #[test]
      fn init() {
          set_up();
          unsafe {
              assert_eq!(3, LITTLE_READER.remaining());
          }
      }
      
      #[test]
      fn read_bytes() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              let mut dest: [u8; 2] = [0; 2];
              let _ = LITTLE_READER.read_bytes(&mut dest[0..2]);
              assert_eq!(chip_no_error!(), LITTLE_READER.status_code());
              assert_eq!(1, dest[0]);
              assert_eq!(2, dest[1]);
          }
      }
      
      #[test]
      fn read_bytes_too_much() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              let mut dest: [u8; 4] = [0; 4];
              let _ = LITTLE_READER.read_bytes(&mut dest[0..4]);
              assert_eq!(chip_error_buffer_too_small!(), LITTLE_READER.status_code());
          }
      }
      
      #[test]
      fn zero_copy() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              //let dest: [u8; 2] = [0; 2];
              let mut r_dest: &[u8] = &[];
              let _ = LITTLE_READER.zero_copy_process_bytes(2, &mut r_dest);
              assert_eq!(1, r_dest[0]);
              assert_eq!(2, r_dest[1]);
              assert_eq!(chip_no_error!(), LITTLE_READER.status_code());
          }
      }
      
      #[test]
      fn zero_copy_size_0() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              let mut r_dest: &[u8] = &[];
              let _ = LITTLE_READER.zero_copy_process_bytes(0, &mut r_dest);
              assert_eq!(chip_no_error!(), LITTLE_READER.status_code());
              assert_eq!(3, LITTLE_READER.remaining());
          }
      }
      
      #[test]
      fn zero_copy_too_much() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              let mut r_dest: &[u8] = &[];
              let _ = LITTLE_READER.zero_copy_process_bytes(4, &mut r_dest);
              assert_eq!(chip_error_buffer_too_small!(), LITTLE_READER.status_code());
              assert_eq!(0, LITTLE_READER.remaining());
          }
      }
      
      #[test]
      fn zero_copy_too_much_on_second_read() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              let mut r_dest: &[u8] = &[];
              let _ = LITTLE_READER.zero_copy_process_bytes(1, &mut r_dest);
              assert_eq!(1, r_dest[0]);
              assert_eq!(chip_no_error!(), LITTLE_READER.status_code());
              let _ = LITTLE_READER.zero_copy_process_bytes(3, &mut r_dest);
              assert_eq!(chip_error_buffer_too_small!(), LITTLE_READER.status_code());
              assert_eq!(0, LITTLE_READER.remaining());
          }
      }
      
      #[test]
      fn skip() {
          set_up();
          unsafe {
              //LITTLE_READER.init(&THE_DATA[0..3]);
              assert_eq!(3, LITTLE_READER.remaining());
              let _ = LITTLE_READER.skip(2);
              assert_eq!(1, LITTLE_READER.remaining());
          }
      }
  }
}

