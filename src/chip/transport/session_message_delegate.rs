use crate::{
    chip::{
        transport::{
            raw::{
                message_header::{PacketHeader, PayloadHeader},
            },
            session::SessionHandle,
        },
        system::system_packet_buffer::PacketBufferHandle,
    },
};

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum DuplicateMessage {
    Yes,
    No
}

pub trait SessionMessageDelegate {
    fn on_message_received(packet_header: &PacketHeader, payload_header: &PayloadHeader,
        session: &SessionHandle, is_duplicate: DuplicateMessage, msg_buf: &mut PacketBufferHandle);
}
