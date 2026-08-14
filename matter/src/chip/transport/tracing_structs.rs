use crate::{
    verify_or_die,
    chip::{
        transport::{
            raw::{
                message_header::{PayloadHeader, PacketHeader},
                peer_address::PeerAddress,
            },
            session::SessionHandle,
        },
    },
};


// Concrete definitions of the message tracing info that session managers
// report
#[derive(Debug, Clone, Copy)]
pub enum OutgoingMessageType {
    KgroupMessage,
    KsecureSession,
    Kunauthenticated,
}

// A message is about to be sent
#[derive(Clone, Copy)]
pub struct MessageSendInfo<'a> {
    pub message_type: OutgoingMessageType,
    pub payload_header: &'a PayloadHeader,
    pub packet_header: &'a PacketHeader,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum IncomingMessageType {
    KgroupMessage,
    KsecureUnicast,
    Kunauthenticated,
}

// A message has been received
#[derive(Clone, Copy)]
pub struct MessageReceivedInfo<'a> {
    pub messageType: IncomingMessageType,
    pub payload_header: &'a PayloadHeader,
    pub packet_header: &'a PacketHeader,
    pub session: &'a SessionHandle,
    pub peer_address: &'a PeerAddress,
    pub payload: &'a [u8],
}
