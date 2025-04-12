use core::cmp::min;
pub trait EndianPut {
    fn endian_sign_put(&self, x: i64, len: usize, buf: &mut [u8]) -> usize;
    fn endian_unsign_put(&self, x: u64, len: usize, buf: &mut [u8]) -> usize;
}

pub trait BufferWriter<'a> {
    fn default_with_buf(buf: &'a mut [u8]) -> Self;

    fn skip(&mut self, len: usize) -> &mut Self;

    fn put(&mut self, buf: &[u8]) -> &mut Self;

    fn put_u8(&mut self, c: u8) -> &mut Self;

    fn needed(&self) -> usize;

    fn write_pos(&self) -> usize {
        self.needed()
    }

    fn available(&self) -> usize;

    fn is_fit(&self) -> bool {
        return self.fit().is_ok();
    }

    fn fit(&self) -> Result<usize, usize>;

    fn size(&self) -> usize;

    fn buffer(&mut self) -> &mut [u8];

    fn const_buffer(&self) -> &[u8];
}

pub struct EndianBufferWriter<'a, EndianPutter>
where
    EndianPutter: EndianPut,
{
    m_buf: &'a mut[u8],
    m_needed: usize,
    m_endian_putter: EndianPutter,
}

impl<'a, EndianPutter> BufferWriter<'a> for EndianBufferWriter<'a, EndianPutter>
    where
        EndianPutter: EndianPut + Default,
{
    fn default_with_buf(buf: &'a mut [u8]) -> Self {
        Self {
            m_buf: buf,
            m_needed: 0,
            m_endian_putter: EndianPutter::default(),
        }
    }

    fn skip(&mut self, len: usize) -> &mut Self {
        self.m_needed += len;
        self
    }

    fn put(&mut self, buf: &[u8]) -> &mut Self {
        let available = self.available();
        if available > 0 {
            let copy_len: usize = min(available as usize, buf.len());
            self.m_buf[self.m_needed..self.m_needed + copy_len].copy_from_slice(&buf[..copy_len]);
        }
        self.m_needed += buf.len();
        self
    }

    fn put_u8(&mut self, x: u8) -> &mut Self {
        if self.m_needed < self.m_buf.len() {
            self.m_buf[self.m_needed] = x;
        }
        self.m_needed += 1;
        self
    }

    fn needed(&self) -> usize {
        return self.m_needed;
    }

    fn write_pos(&self) -> usize {
        self.needed()
    }

    fn available(&self) -> usize {
        if self.m_buf.len() < self.m_needed {
            return 0;
        } else {
            return self.m_buf.len() - self.m_needed;
        }
    }

    fn is_fit(&self) -> bool {
        return self.fit().is_ok();
    }

    fn fit(&self) -> Result<usize, usize> {
        let actually_written = if self.m_buf.len() >= self.m_needed { self.m_needed } else { self.m_buf.len() };

        if self.m_buf.len() >= self.m_needed {
            return Ok(actually_written);
        } else {
            return Err(actually_written);
        }
    }

    fn size(&self) -> usize {
        return self.m_buf.len();
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.m_buf
    }

    fn const_buffer(&self) -> &[u8] {
        return self.m_buf as &[u8];
    }
}

impl<'a, EndianPutter> EndianBufferWriter<'a, EndianPutter>
where
    EndianPutter: EndianPut + Default 
{
    #[allow(dead_code)]
    pub fn put_u16(&mut self, x: u16) -> &mut Self {
        let len = core::mem::size_of::<u16>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_unsign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }

    #[allow(dead_code)]
    pub fn put_i16(&mut self, x: i16) -> &mut Self {
        let len = core::mem::size_of::<i16>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_sign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }

    #[allow(dead_code)]
    pub fn put_u32(&mut self, x: u32) -> &mut Self {
        let len = core::mem::size_of::<u32>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_unsign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }

    #[allow(dead_code)]
    pub fn put_i32(&mut self, x: i32) -> &mut Self {
        let len = core::mem::size_of::<i32>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_sign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }

    #[allow(dead_code)]
    pub fn put_u64(&mut self, x: u64) -> &mut Self {
        let len = core::mem::size_of::<u64>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_unsign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }

    #[allow(dead_code)]
    pub fn put_i64(&mut self, x: i64) -> &mut Self {
        let len = core::mem::size_of::<i64>();
        if self.available() > 0 {
            let _ = self.m_endian_putter.endian_sign_put(x.into(), len, &mut self.m_buf[self.m_needed..]);
        }
        self.m_needed += len;
        self
    }
}

pub mod little_endian {
    use core::cmp::min;
    use super::{EndianBufferWriter, EndianPut};

    #[derive(Default)]
    pub struct LittleEndianPutter;

    impl EndianPut for LittleEndianPutter {
        fn endian_sign_put(&self, x: i64, len: usize, buf: &mut [u8]) -> usize {
            return self.endian_unsign_put(x as u64, len, buf);
        }

        fn endian_unsign_put(&self, mut x: u64, len: usize, buf: &mut [u8]) -> usize {
            let copy_len = min(len, buf.len());

            for i in 0..copy_len {
                buf[i] = (x & 0xFF) as u8;
                x = x >> 8;
            }

            return copy_len;
        }
    }

    pub type BufferWriter<'a> = EndianBufferWriter<'a, LittleEndianPutter>;
}

pub mod big_endian {
    use core::cmp::min;
    use super::{EndianBufferWriter, EndianPut};

    #[derive(Default)]
    pub struct BigEndianPutter;

    impl EndianPut for BigEndianPutter {
        fn endian_sign_put(&self, x: i64, len: usize, buf: &mut [u8]) -> usize {
            return self.endian_unsign_put(x as u64, len, buf);
        }

        fn endian_unsign_put(&self, x: u64, len: usize, buf: &mut [u8]) -> usize {
            let copy_len = min(len, buf.len());

            for i in 0..copy_len {
                buf[i] = ((x >> (copy_len - i - 1) * 8) & 0xFF) as u8;
            }

            return copy_len;
        }
    }

    pub type BufferWriter<'a> = EndianBufferWriter<'a, BigEndianPutter>;
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  mod common_apis {
      use super::super::*;

      #[test]
      fn init() {
          let mut buf: [u8; 1] = [0];
          let wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          assert_eq!(1, wb.size());
      }

      #[test]
      fn skip() {
          let mut buf: [u8; 1] = [0];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          assert_eq!(0, wb.needed());
          let _ = wb.skip(10);
          assert_eq!(10, wb.needed());
      }

      #[test]
      fn put() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: [u8; 2] = [1; 2];
          wb.put(&src[..]);
          assert_eq!(buf, src);
      }

      #[test]
      fn put_u8() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u8 = 1;
          wb.put_u8(src);
          assert_eq!([1, 0], buf);
      }

      #[test]
      fn write_pos() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u8 = 1;
          wb.put_u8(src);
          assert_eq!(1, wb.write_pos());
      }

      #[test]
      fn is_fit() {
          let mut buf: [u8; 2] = [0; 2];
          let wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          assert_eq!(true, wb.is_fit());
      }
  }
  
  mod little_endian_writer {
      use super::super::*;

      #[test]
      fn put_u16() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u16 = 0x1234;
          wb.put_u16(src);
          assert_eq!([0x34, 0x12], buf);
      }

      #[test]
      fn put_i16() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i16 = 0x1234;
          wb.put_i16(src);
          assert_eq!([0x34, 0x12], buf);
      }

      #[test]
      fn put_u32() {
          let mut buf: [u8; 4] = [0; 4];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u32 = 0x12345678;
          wb.put_u32(src);
          assert_eq!([0x78, 0x56, 0x34, 0x12], buf);
      }

      #[test]
      fn put_i32() {
          let mut buf: [u8; 4] = [0; 4];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i32 = 0x12345678;
          wb.put_i32(src);
          assert_eq!([0x78, 0x56, 0x34, 0x12], buf);
      }

      #[test]
      fn put_u64() {
          let mut buf: [u8; 8] = [0; 8];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u64 = 0x12345678aabbccdd;
          wb.put_u64(src);
          assert_eq!([0xdd, 0xcc, 0xbb, 0xaa, 0x78, 0x56, 0x34, 0x12], buf);
      }

      #[test]
      fn put_i64() {
          let mut buf: [u8; 8] = [0; 8];
          let mut wb: little_endian::BufferWriter = little_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i64 = 0x12345678aabbccdd;
          wb.put_i64(src);
          assert_eq!([0xdd, 0xcc, 0xbb, 0xaa, 0x78, 0x56, 0x34, 0x12], buf);
      }
  }
  
  mod big_endian_writer {
      use super::super::*;

      #[test]
      fn put_u16() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u16 = 0x1234;
          wb.put_u16(src);
          assert_eq!([0x12, 0x34], buf);
      }

      #[test]
      fn put_i16() {
          let mut buf: [u8; 2] = [0; 2];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i16 = 0x1234;
          wb.put_i16(src);
          assert_eq!([0x12, 0x34], buf);
      }

      #[test]
      fn put_u32() {
          let mut buf: [u8; 4] = [0; 4];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u32 = 0x12345678;
          wb.put_u32(src);
          assert_eq!([0x12, 0x34, 0x56, 0x78], buf);
      }

      #[test]
      fn put_i32() {
          let mut buf: [u8; 4] = [0; 4];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i32 = 0x12345678;
          wb.put_i32(src);
          assert_eq!([0x12, 0x34, 0x56, 0x78], buf);
      }

      #[test]
      fn put_u64() {
          let mut buf: [u8; 8] = [0; 8];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: u64 = 0x12345678aabbccdd;
          wb.put_u64(src);
          assert_eq!([0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd], buf);
      }

      #[test]
      fn put_i64() {
          let mut buf: [u8; 8] = [0; 8];
          let mut wb: big_endian::BufferWriter = big_endian::BufferWriter::default_with_buf(&mut buf[..]);
          let src: i64 = 0x12345678aabbccdd;
          wb.put_i64(src);
          assert_eq!([0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd], buf);
      }
  }
}
