use crate::ChipErrorResult;
use super::raw::base::Base;
use crate::chip::transport::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;

pub trait TransportMgrBase<'a> {
    //type RawDelegateType: RawTransportDelegate;
    type TransportType: Base;
    type TransportMgrDelegateType;

    fn init(&mut self, transport: * mut Self::TransportType) -> ChipErrorResult;

    fn send_message(&mut self, address: PeerAddress, msg_buf: PacketBufferHandle) -> ChipErrorResult;

    fn set_session_manager(&mut self, session_manager: * mut Self::TransportMgrDelegateType);

    fn get_session_manager(&mut self) -> * mut Self::TransportMgrDelegateType;

    fn close(&mut self);
}
