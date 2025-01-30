#[cfg(test)]
use core::{mem, ptr};
#[cfg(not(test))]
extern crate std;
#[cfg(not(test))]
use std::*;

use super::system_config::*;
use crate::chip_system_align_size;

const ZEROED_PACKETBUFFER: BufferPoolElement = BufferPoolElement { block: [0; PacketBuffer::KBLOCK_SIZE as usize] };

static mut S_BUFFER_POLL: [BufferPoolElement; CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize] = [ZEROED_PACKETBUFFER; CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize];
static mut S_FREE_LIST: * mut PacketBuffer = ptr::null_mut();
static mut S_IS_POOL_INIT: bool = false;

pub struct PacketBuffer
{
    next: * mut PacketBuffer,
    payload: * mut u8,
    tot_len: u32,
    len: u32,
    ref_count: u16,
}

union BufferPoolElement
{
    header: mem::ManuallyDrop<PacketBuffer>,
    block: [u8; PacketBuffer::KBLOCK_SIZE as usize],
}

impl PacketBuffer
{
    pub const KSTRUCTURESIZE: u16 = chip_system_align_size!(mem::size_of::<PacketBuffer>(), 4) as u16;
    pub const KMAX_SIZE_WITHOUT_RESERVE: u32 = CHIP_SYSTEM_CONFIG_PACKETBUFFER_CAPACITY_MAX;
    pub const KBLOCK_SIZE: u16 = PacketBuffer::KSTRUCTURESIZE + PacketBuffer::KMAX_SIZE_WITHOUT_RESERVE as u16;
    pub const KDEFAULT_HEADER_RESERVE: u16 = CHIP_SYSTEM_CONFIG_HEADER_RESERVE_SIZE as u16;
    pub const KMAX_ALLOC_SIZE: u32 = PacketBuffer::KMAX_SIZE_WITHOUT_RESERVE;

    pub fn chained_buffer(&self) -> * mut PacketBuffer {
        return self.next;
    }

    pub fn build_free_list() -> * mut PacketBuffer {
        let mut l_head: * mut PacketBuffer = ptr::null_mut();

        unsafe {
            for i in 0..CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize {
                let l_cursor: * mut PacketBuffer = &mut (*S_BUFFER_POLL[i].header);
                (*l_cursor).next = l_head;
                l_head = l_cursor;
            }
        }

        return l_head;
    }

    pub fn free(mut packet: * mut Self) {
        unsafe {
            while false == packet.is_null() {
                let next_packet: * mut Self = (*packet).chained_buffer();
                (*packet).ref_count -= 1;
                if (*packet).ref_count == 0 {
                    (*packet).clear();
                    (*packet).next = S_FREE_LIST;
                    S_FREE_LIST = packet;
                    packet = next_packet;
                }
                else {
                    packet = ptr::null_mut();
                }
            }
        }
    }

    pub fn reserve_start_const(&self) -> * const u8 {
        let start = self as * const Self as * const u8;
        return unsafe {start.add(PacketBuffer::KSTRUCTURESIZE as usize).cast::<u8>()}
    }

    pub fn reserve_start(&mut self) -> * mut u8 {
        let start = self as * mut Self as * mut u8;
        return unsafe {start.add(PacketBuffer::KSTRUCTURESIZE as usize).cast::<u8>()}
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.tot_len = 0;
    }

    pub fn add_ref(&mut self) {
        // TODO: check if ref overflow.
        self.ref_count += 1;
    }

    pub fn free_head(packet: * mut Self) -> * mut Self{
        let next: * mut Self;
        unsafe {
            next = (*packet).chained_buffer();
            (*packet).next = ptr::null_mut();
            PacketBuffer::free(packet);
        }
        return next;
    }

    pub fn has_chained_buffer(&self) -> bool {
        return self.chained_buffer().is_null() != true;
    }

    pub fn add_to_end(&mut self, mut other_handle: PacketBufferHandle) {
        let packet = other_handle.unsafe_release();
        let mut l_cursor: * mut PacketBuffer = self;
        while false == l_cursor.is_null() {
            unsafe {
                (*l_cursor).tot_len = (*l_cursor).tot_len + (*packet).tot_len;
                if false == (*l_cursor).has_chained_buffer() {
                    (*l_cursor).next = packet;
                    break;
                }
                l_cursor = (*l_cursor).chained_buffer();
            }
        }
    }

    pub fn consume(&mut self, mut consume_length: u32) {
        if consume_length > self.len {
            consume_length = self.len;
        }
        unsafe {
            self.payload = self.payload.add(consume_length as usize);
        }
        self.len = self.len - consume_length;
        self.tot_len = self.tot_len - consume_length;
    }
}

pub struct PacketBufferHandle
{
    m_buffer: * mut PacketBuffer,
}

impl PacketBufferHandle
{
    pub fn new(a_available_size: u32, a_reserved_size: u16) -> Option<Self> {
        let sum_of_sizes: u64 = a_available_size as u64 + a_reserved_size as u64 + PacketBuffer::KSTRUCTURESIZE as u64;
        let sum_of_available_and_reserved: u64 = a_available_size as u64 + a_reserved_size as u64;

        if sum_of_sizes > u32::MAX as u64 {
            return None;
        }
        // sumOfAvailAndReserved is no larger than sumOfSizes, which we checked can be cast to
        // size_t.
        let alloc_size = sum_of_available_and_reserved as u32;
        if alloc_size > PacketBuffer::KMAX_ALLOC_SIZE {
            return None;
        }

        let returned_handle: Option<Self>;

        unsafe {
            if false == S_IS_POOL_INIT {
                S_FREE_LIST = PacketBuffer::build_free_list();
                S_IS_POOL_INIT = true;
            }

            let lpacket = S_FREE_LIST;
            if lpacket.is_null() {
                return None;
            }
            else {
                S_FREE_LIST = (*lpacket).chained_buffer();
            }

            (*lpacket).payload = (*lpacket).reserve_start().add(a_reserved_size as usize);
            (*lpacket).len = 0;
            (*lpacket).tot_len = 0;
            (*lpacket).next = ptr::null_mut();
            (*lpacket).ref_count = 1;

            returned_handle = Some(PacketBufferHandle{m_buffer: lpacket});
        }

        //return Some(PacketBufferHandle{m_buffer: lpacket});
        return returned_handle;
    }

    pub fn new_with_default_header(a_available_size: u32) -> Option<Self> {
        PacketBufferHandle::new(a_available_size, PacketBuffer::KDEFAULT_HEADER_RESERVE)
    }

    pub fn new_with_data(data: &[u8], additional_size: u32, reserved_size: u16) -> Option<Self> {
        let buffer = PacketBufferHandle::new(data.len() as u32 + additional_size, reserved_size);
        return buffer.map(|b| {
            if b.is_null() == false {
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr(), (*b.get_raw()).payload, data.len());
                    (*b.get_raw()).tot_len = data.len() as u32;
                    (*b.get_raw()).len = data.len() as u32;
                }
            }
            return b;
        });
    }

    pub fn is_null(&self) -> bool {
        return self.m_buffer.is_null();
    }

    pub fn retain(&mut self) -> Option<Self> {
        unsafe {
            (*self.m_buffer).add_ref();
        }
        return Some(PacketBufferHandle {m_buffer: self.m_buffer});
    }

    pub fn get_raw(&self) -> * mut PacketBuffer {
        return self.m_buffer;
    }

    pub fn pop_head(&mut self) -> Option<Self> {
        let head = self.m_buffer;
        unsafe {
            self.m_buffer = (*self.m_buffer).chained_buffer();

            (*head).next = ptr::null_mut();
            (*head).tot_len = (*head).len;
        }

        return Some(PacketBufferHandle{m_buffer: head});
    }

    pub fn free_head(&mut self) {
        self.m_buffer = PacketBuffer::free_head(self.m_buffer);
    }

    pub fn add_to_end(&mut self, mut other: Self) {
        unsafe {
            if self.is_null() {
                self.m_buffer = other.m_buffer;
                other.m_buffer = ptr::null_mut();
            } else {
                (*self.m_buffer).add_to_end(other);
            }
        }
    }

    pub fn unsafe_release(&mut self) -> * mut PacketBuffer {
        let buffer: * mut PacketBuffer;
        buffer = self.m_buffer;
        self.m_buffer = ptr::null_mut();
        return buffer;
    }

    pub fn consume(&mut self, consume_length: u32) {
        unsafe {
            (*self.m_buffer).consume(consume_length);
        }
    }

    pub fn advance(&mut self) {
        unsafe {
            *self = PacketBufferHandle::hold((*self.m_buffer).chained_buffer());
        }
    }

    fn hold(buffer: * mut PacketBuffer) -> Self {
        if false == buffer.is_null() {
            unsafe {
                (*buffer).add_ref();
            }
        }
        return PacketBufferHandle{ m_buffer: buffer };
    }
}

impl Drop for PacketBufferHandle {
    fn drop(&mut self) {
        if false == self.m_buffer.is_null() {
            PacketBuffer::free(self.m_buffer);
        }
        self.m_buffer = ptr::null_mut();
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod new {
      use super::super::*;
      use std::*;

      fn set_up() {
          unsafe {
              // reset static memory block
              S_BUFFER_POLL = [ZEROED_PACKETBUFFER; CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize];
              S_IS_POOL_INIT = false;
          }
      }

      #[test]
      fn new_packet_buffer() {
          set_up();
          let buffer = PacketBufferHandle::new(1,1);
          assert_eq!(buffer.is_none(), false);
      }

      #[test]
      fn new_packet_buffer_with_oversize_u32_max_available_space() {
          set_up();
          let buffer = PacketBufferHandle::new_with_default_header(u32::MAX);
          assert_eq!(buffer.is_none(), true);
      }

      #[test]
      fn new_packet_buffer_with_oversize_alloc_max_available_space() {
          set_up();
          let mut extra : u32 = 1;
          if PacketBuffer::KMAX_ALLOC_SIZE % 2 != 0 {
              extra += 1;
          }
          let buffer = PacketBufferHandle::new(PacketBuffer::KMAX_ALLOC_SIZE/2 + extra, (PacketBuffer::KMAX_ALLOC_SIZE/2) as u16);
          assert_eq!(buffer.is_none(), true);
      }

      #[test]
      fn new_packet_buffer_but_out_of_sapce() {
          set_up();
          unsafe {
              S_IS_POOL_INIT = true;
              S_FREE_LIST = ptr::null_mut();
          }
          let buffer = PacketBufferHandle::new(1,1);
          assert_eq!(buffer.is_none(), true);
      }

      #[test]
      fn new_packet_buffer_with_data() {
          set_up();
          let data: [u8; 4] = [1,2,3,4];
          let buffer = PacketBufferHandle::new_with_data(&data[0..4], 0, 8);
          assert_eq!(buffer.is_none(), false);
          unsafe {
              let buffer_ptr = (*(buffer.unwrap().get_raw())).payload;
              let data_ptr = data.as_ptr();
              for i in 0..data.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
          }
      }

      #[test]
      fn drop() {
          set_up();
          let before_alloc: u64;
          let after_drop: u64;
          unsafe {
              before_alloc = ptr::addr_of!(S_FREE_LIST) as u64;
          }
          let buffer = PacketBufferHandle::new(1,1);
          mem::drop(buffer);
          unsafe {
              after_drop = ptr::addr_of!(S_FREE_LIST) as u64;
          }
          assert_eq!(before_alloc, after_drop);
      }
  }

  mod push_and_pop {
      use super::super::*;
      use std::*;

      fn set_up() {
          unsafe {
              // reset static memory block
              S_BUFFER_POLL = [ZEROED_PACKETBUFFER; CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize];
              S_IS_POOL_INIT = false;
          }
      }

      #[test]
      fn push_one() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let data2: [u8; 4] = [21, 22, 23, 24];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          let b2 = PacketBufferHandle::new_with_data(&data2[0..4],0,8).unwrap();
          b1.add_to_end(b2);
          unsafe {
              let buffer_ptr = (*(b1.get_raw())).payload;
              let data_ptr = data1.as_ptr();
              for i in 0..data1.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
              let len = (*(b1.get_raw())).tot_len;
              assert_eq!(data1.len() + data2.len(), len as usize);
          }
      }

      #[test]
      fn push_and_pop_one() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let data2: [u8; 4] = [21, 22, 23, 24];
          let mut b1_2 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          let b2 = PacketBufferHandle::new_with_data(&data2[0..4],0,8).unwrap();
          b1_2.add_to_end(b2);
          let b1_poped = b1_2.pop_head();
          assert_eq!(false, b1_poped.is_none());
          let b1_poped = b1_poped.unwrap();


          unsafe {
              // verify data1
              let buffer_ptr = (*(b1_poped.get_raw())).payload;
              let data_ptr = data1.as_ptr();
              for i in 0..data1.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
              let len = (*(b1_poped.get_raw())).tot_len;
              assert_eq!(data1.len(), len as usize);

              // verify data2
              let buffer_ptr = (*(b1_2.get_raw())).payload;
              let data_ptr = data2.as_ptr();
              for i in 0..data2.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
              let len = (*(b1_2.get_raw())).tot_len;
              assert_eq!(data2.len(), len as usize);
          }
      }

      #[test]
      fn pop_self() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          let _ = b1.pop_head();
          assert_eq!(true, b1.is_null());
      }

      #[test]
      fn push_from_empty() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let data2: [u8; 4] = [21, 22, 23, 24];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          let _ = b1.pop_head();
          let b2 = PacketBufferHandle::new_with_data(&data2[0..4],0,8).unwrap();
          b1.add_to_end(b2);
          assert_eq!(false, b1.is_null());

          unsafe {
              // verify data2 in b1
              let buffer_ptr = (*(b1.get_raw())).payload;
              let data_ptr = data2.as_ptr();
              for i in 0..data2.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
              let len = (*(b1.get_raw())).tot_len;
              assert_eq!(data2.len(), len as usize);
          }
      }

      #[test]
      fn free_head() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          b1.free_head();
          assert_eq!(true, b1.is_null());
      }
  }

  mod advance_and_consume {
      use super::super::*;
      use std::*;

      fn set_up() {
          unsafe {
              // reset static memory block
              S_BUFFER_POLL = [ZEROED_PACKETBUFFER; CHIP_SYSTEM_CONFIG_PACKETBUFFER_POOL_SIZE as usize];
              S_IS_POOL_INIT = false;
          }
      }

      #[test]
      fn advance_one() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let data2: [u8; 5] = [21, 22, 23, 24, 25];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          let b2 = PacketBufferHandle::new_with_data(&data2[0..5],0,8).unwrap();
          b1.add_to_end(b2);
          unsafe {
              assert_eq!(1, (*(b1.get_raw())).ref_count);
          }
          b1.advance();
          unsafe {
              let buffer_ptr = (*(b1.get_raw())).payload;
              let data_ptr = data2.as_ptr();
              for i in 0..data2.len() {
                  assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(data_ptr.add(i)));
              }
              let len = (*(b1.get_raw())).tot_len;
              assert_eq!(data2.len(), len as usize);
              assert_eq!(1, (*(b1.get_raw())).ref_count);
          }
      }

      #[test]
      fn advance_to_empty() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          b1.advance();
          assert_eq!(true, b1.is_null());
      }

      #[test]
      fn consume_one() {
          set_up();
          let data1: [u8; 4] = [11, 12, 13, 14];
          let mut b1 = PacketBufferHandle::new_with_data(&data1[0..4],0,8).unwrap();
          unsafe {
              assert_eq!(11, *((*b1.get_raw()).payload));
              b1.consume(1);
              assert_eq!(12, *((*b1.get_raw()).payload));
          }
      }
  }
}
