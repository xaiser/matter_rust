// A simple string

use core::fmt::{self, Write};
use core::str;

#[derive(Copy,Clone, Debug)]
pub struct DefaultString<const N: usize> { m_buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for DefaultString<N> {
    fn default() -> Self {
        DefaultString::<N>::const_default()
    }
}

impl<const N: usize> DefaultString<N> {
    pub const fn const_default() -> Self {
        Self {
            m_buf: [0; N],
            len: 0
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn raw_bytes(&mut self) -> &mut [u8] {
        &mut self.m_buf[..]
    }

    pub fn const_raw_bytes(&self) -> &[u8] {
        &self.m_buf[..]
    }

    pub fn bytes(&mut self) -> &mut [u8] {
        &mut self.m_buf[..self.len]
    }

    pub fn const_bytes(&self) -> &[u8] {
        &self.m_buf[..self.len]
    }

    pub fn str(&self) -> &str {
        str::from_utf8(self.const_bytes()).unwrap_or(&"")
    }

    pub fn clear(&mut self) {
        self.m_buf.fill(0);
        self.len = 0;
    }
}

impl<const N: usize> From<&[u8]> for DefaultString<N> {
    fn from(value: &[u8]) -> Self {
        let mut string = DefaultString::<N>::default();

        if value.len() == 0 {
            return string;
        }

        let size = core::cmp::min(N, value.len());
        string.m_buf[0..size].copy_from_slice(&value[0..size]);
        string.len = size;
        return string;
    }
}

impl<const N: usize> From<&str> for DefaultString<N> {
    fn from(value: &str) -> Self {
        let mut string = DefaultString::<N>::default();

        if value.len() == 0 {
            return string;
        }

        let size = core::cmp::min(N, value.len());
        string.m_buf[0..size].copy_from_slice(&value.as_bytes()[0..size]);
        string.len = size;
        return string;
    }
}

impl<const N: usize> Write for DefaultString<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let current_len = self.len();
        let bytes = s.as_bytes();
        let to_copy = bytes.len().min(N - current_len);
        self.m_buf[current_len..current_len + to_copy]
            .copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

impl<const N: usize> PartialEq for DefaultString<N> {
    fn eq(&self, other: &Self) -> bool {
        self.const_bytes() == other.const_bytes()
    }
}

impl<const N: usize> Eq for DefaultString<N> {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn init() {
        let s = DefaultString::<10>::const_default();
        assert_eq!(0, s.len());
        assert_eq!(10, s.capacity());
    }

    #[test]
    fn write() {
        let mut s = DefaultString::<10>::const_default();
        write!(&mut s, "123");
        assert_eq!("123", s.str());
    }

    #[test]
    fn write_over_size() {
        let mut s = DefaultString::<1>::const_default();
        write!(&mut s, "123");
        assert_eq!("1", s.str());
    }

    #[test]
    fn from_u8() {
        let a = [1u8, 2u8, 3u8];
        let s = DefaultString::<3>::from(&a[..]);
        assert_eq!(&a[..], s.const_raw_bytes());
    }

    #[test]
    fn from_str() {
        let a = "123";
        let s = DefaultString::<3>::from(a);
        assert_eq!(a, s.str());
    }
}
