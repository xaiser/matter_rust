use crate::ChipErrorResult;
use super::raw::base::{Base, RawTransportDelegate};
use crate::chip::transport::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;

pub trait TransportMgrBase<'a> {
    //type RawDelegateType: RawTransportDelegate;
    type TransportType: Base;
    type TransportMgrDelegateType;

    fn init(&mut self, transport: &'a Self::TransportType) -> ChipErrorResult;

    fn send_message(&mut self, address: &PeerAddress, msg_buf: PacketBufferHandle) -> ChipErrorResult;

    fn set_session_manager(&mut self, session_manager: &'a Self::TransportMgrDelegateType);

    fn get_session_manager(&mut self) -> &'a Self::TransportMgrDelegateType;
}
