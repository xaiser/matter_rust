use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::system::LayerImpl;
use crate::chip::transport::raw::message_header::PacketHeader;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::str::FromStr;

#[repr(u8)]
pub enum TransportPayloadCapability {
    KMrpPayload,
    KLargePayload,
    KMrpOrTcpCompatiablePayload,
}

#[derive(Clone)]
pub struct EncryptedPacketBufferHandle {
    m_packet_buffer_handle: PacketBufferHandle,
}

impl Default for EncryptedPacketBufferHandle {
    fn default() -> Self {
        EncryptedPacketBufferHandle::const_default()
    }
}

impl EncryptedPacketBufferHandle {
    pub const fn const_default() -> Self {
        Self {
            m_packet_buffer_handle: PacketBufferHandle::const_default(),
        }
    }

    pub fn get_raw(&mut self) -> &mut PacketBufferHandle {
        return &mut self.m_packet_buffer_handle;
    }

    pub fn has_chained_buffer(&self) -> bool {
        return self.m_packet_buffer_handle.has_chained_buffer();
    }

    pub fn get_message_counter(&self) -> u32 {
        let mut header: PacketHeader = PacketHeader::default();
        let mut header_size: u16 = 0;
        unsafe {
            let err = header.decode_with_raw(
                (*self.m_packet_buffer_handle.get_raw()).start(),
                (*self.m_packet_buffer_handle.get_raw()).data_len() as usize,
                &mut header_size,
            );

            if err.is_ok() {
                return header.get_message_counter();
            }

            chip_log_error!(
                Inet,
                "fail to decode EncryptedPacketBufferHandle header {}",
                err.err().unwrap()
            );
        }

        0
    }

    pub fn mark_encrypted(buffer: PacketBufferHandle) -> Self {
        Self {
            m_packet_buffer_handle: buffer,
        }
    }

    pub fn cast_to_writable(&mut self) -> PacketBufferHandle {
        return self.m_packet_buffer_handle.retain().unwrap();
    }
}

pub struct SessionManager {
    m_system_layer: *mut LayerImpl,
}
