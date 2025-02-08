use super::peer_address::PeerAddress;
use crate::ChipError;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;

pub struct MessageTransportContext;

pub trait RawTransportDelegate {
    fn handle_message_received(&self, peer_address: &PeerAddress, msg: & mut PacketBufferHandle,
        ctxt: * const MessageTransportContext);
}

pub trait Base<T: RawTransportDelegate> {
    fn set_deletgate(&mut self, delegate: * mut T);

    fn send_message(&mut self, peer_address: &PeerAddress, msg_buf: PacketBufferHandle) -> ChipError;

    fn can_send_to_peer(&mut self, peer_address: &PeerAddress) -> bool;

    fn close(&mut self) { }

    fn handle_message_received(&mut self, peer_address: &PeerAddress, buffer: PacketBufferHandle, ctxt: * const MessageTransportContext);
}
