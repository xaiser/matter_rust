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
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
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

impl<'a> MessageSendInfo<'a> {
    pub const fn new(message_type: OutgoingMessageType, payload_header: &'a PayloadHeader, packet_header: &'a PacketHeader,
        payload: &'a [u8]) -> Self {
        Self {
            message_type,
            payload_header,
            packet_header,
            payload,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum IncomingMessageType {
    KgroupMessage,
    KsecureUnicast,
    Kunauthenticated,
}

// A message has been received
#[derive(Clone, Copy)]
pub struct MessageReceivedInfo<'a> {
    pub message_type: IncomingMessageType,
    pub payload_header: &'a PayloadHeader,
    pub packet_header: &'a PacketHeader,
    pub session: &'a SessionHandle,
    pub peer_address: &'a PeerAddress,
    pub payload: &'a [u8],
}

impl<'a> MessageReceivedInfo<'a> {
    pub const fn new(message_type: IncomingMessageType, payload_header: &'a PayloadHeader, packet_header: &'a PacketHeader, session: &'a SessionHandle,
        peer_address: &'a PeerAddress, payload: &'a [u8]) -> Self {
        Self {
            message_type,
            payload_header,
            packet_header,
            session,
            peer_address,
            payload,
        }
    }
}
