use super::peer_address::PeerAddress;
use crate::ChipError;
use crate::system::system_packet_buffer::PacketBufferHandle;

pub struct MessageTransportContext;

pub trait RawTransportDelegate
{
    pub fn handle_message_received(&self, peer_address: &PeerAddress, msg: & mut PacketBufferHandle,
        ctxt: * const MessageTransportContext);
}

pub trait Base<'a>
{
    pub fn set_deletgate<T: RawTransportDelegate>(&mut self, delegate: &'a T) {
        self.m_delegate = delegate;
    }

    pub fn send_message(&mut self, peer_address: &PeerAddress, msg_buf: &PacketBufferHandle) -> ChipError;

    pub fn can_send_to_peer(&mut self, peer_address: &PeerAddress) -> bool;

    pub fn close(&mut self) { }

    fn handle_message_received(&mut self, peer_address: &PeerAddress, buffer: &PacketBufferHandle, ctxt: * const MessageTransportContext);
}
