use crate::chip::system::system_config::CHIP_SYSTEM_CONFIG_HEADER_RESERVE_SIZE;
use crate::chip::NodeId;

use bitflags::{bitflags, Flags};

// Figure out the max size of a packet we can allocate, including all headers.
const KMAX_IP_PACKET_SIZE_BYTES: usize = 1280;
const KMAX_UDP_AND_IP_HEADER_SIZE_BYTES: usize = 48;

// Max space we have for our Application Payload and MIC, per spec.
const KMAX_PER_SPEC_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES: usize = 
KMAX_IP_PACKET_SIZE_BYTES - KMAX_UDP_AND_IP_HEADER_SIZE_BYTES + CHIP_SYSTEM_CONFIG_HEADER_RESERVE_SIZE as usize;

// Max space we have for our Application Payload and MIC in our actual packet
// buffers.  This is the size _excluding_ the header reserve.
const KMAX_PACKETBUFFER_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES: usize = crate::chip::system::system_packet_buffer::PacketBuffer::KMAX_SIZE as usize;

const KMAX_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES: usize = 
if KMAX_PER_SPEC_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES < KMAX_PACKETBUFFER_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES {KMAX_PER_SPEC_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES} else {KMAX_PACKETBUFFER_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES};

const KMAX_TAG_LEN: usize = 16;

// This is somewhat of an under-estimate, because in practice any time we have a
// tag we will not have source/destination node IDs, but above we are including
// those in the header sizes.
const KMAX_APP_MESSAGE_LEN: usize = KMAX_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES - KMAX_TAG_LEN;

const KMSG_UNICAST_SESSION_ID_UNSECURED: u16 = 0x0000;

const KMAX_TCP_AND_IP_HEADER_SIZE_BYTES: usize = 60;

// Max space for the Application Payload and MIC for large packet buffers
// This is the size _excluding_ the header reserve.
const KMAX_LARGE_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES: usize = 
crate::chip::system::system_packet_buffer::PacketBuffer::KLARGE_BUF_MAX_SIZE as usize - KMAX_TCP_AND_IP_HEADER_SIZE_BYTES;

const KMAX_LARGE_APP_MESSAGE_LEN: usize = KMAX_LARGE_APPLICATION_PAYLOAD_AND_MIC_SIZE_BYTES - KMAX_TAG_LEN;

pub type PacketHeaderFlags = i32;

pub mod header {
    use bitflags::bitflags;

    #[repr(u8)]
    #[derive(Clone, Copy)]
    pub enum SessionType {
        KUnicastSession = 0,
        KGroupSession,
    }

    impl From<u8> for SessionType {
        fn from(value: u8) -> Self {
            match value {
                0 => SessionType::KUnicastSession,
                _ => SessionType::KGroupSession,
            }
        }
    }

    bitflags! {
        pub struct ExFlagValues: u8 {
            /// Set when current message is sent by the initiator of an exchange.
            const KExchangeFlagInitiator = 0x01;

            /// Set when current message is an acknowledgment for a previously received message.
            const KExchangeFlagAckMsg = 0x02;

            /// Set when current message is requesting an acknowledgment from the recipient.
            const KExchangeFlagNeedsAck = 0x04;

            /// Secured Extension block is present.
            const KExchangeFlagSecuredExtension = 0x08;

            /// Set when a vendor id is prepended to the Message Protocol Id field.
            const KExchangeFlagVendorIdPresent = 0x10;
        }
    }

    bitflags! {
        pub struct MsgFlagValues: u8 {
            /// Header flag specifying that a source node id is included in the header.
            const KSourceNodeIdPresent       = 0b00000100;
            const KDestinationNodeIdPresent  = 0b00000001;
            const KDestinationGroupIdPresent = 0b00000010;
            const KDSIZReserved              = 0b00000011;
        }
    }

    bitflags! {
        pub struct SecFlagValues: u8 {
            const KPrivacyFlag      = 0b10000000;
            const KControlMsgFlag   = 0b01000000;
            const KMsgExtensionFlag = 0b00100000;
        }
    }

    #[repr(u8)]
    pub enum SecFlagMask {
        KSessionTypeMask = 0b00000011, // Mask to extract sessionType
    }

    pub type MsgFlags = MsgFlagValues;
    pub type SecFlags = SecFlagValues;
    pub type ExFlags = ExFlagValues;
} // header mod

pub struct PacketHeader {
    m_message_counter: u32,
    m_source_node_id: Option<NodeId>,
    m_destination_node_id: Option<NodeId>,
    m_sessino_id: u16,
    m_session_type: header::SessionType,
    m_msg_flags: header::MsgFlags,
    m_sec_flags: header::SecFlags,
}

impl PacketHeader {
    pub fn get_message_counter(&self) -> u32 {
        self.m_message_counter
    }

    pub fn get_source_node_id(&self) -> &Option<NodeId> {
        &self.m_source_node_id
    }

    pub fn get_destination_node_id(&self) -> &Option<NodeId> {
        &self.m_destination_node_id
    }

    pub fn get_session_id(&self) -> u16 {
        self.m_sessino_id
    }

    pub fn get_session_type(&self) -> header::SessionType {
        self.m_session_type.clone()
    }

    pub fn get_message_flags(&self) -> <header::MsgFlags as Flags>::Bits {
        self.m_msg_flags.bits()
    }

    pub fn get_security_flags(&self) -> <header::SecFlags as Flags>::Bits {
        self.m_sec_flags.bits()
    }

    pub fn has_privacy_flag(&self) -> bool {
        self.m_sec_flags.contains(header::SecFlagValues::KPrivacyFlag)
    }

    pub fn has_source_node_id(&self) -> bool {
        self.m_msg_flags.contains(header::MsgFlagValues::KSourceNodeIdPresent)
    }

    pub fn has_destination_node_id(&self) -> bool {
        self.m_msg_flags.contains(header::MsgFlagValues::KDestinationNodeIdPresent)
    }

    pub fn set_message_flags(&mut self, flags: header::MsgFlags) {
        self.m_msg_flags = flags;
    }

    pub fn set_security_flags(&mut self, flags: header::SecFlags) {
        self.m_sec_flags = flags;
    }

    pub fn set_message_flags_raw(&mut self, bits: <header::MsgFlags as Flags>::Bits) {
        self.m_msg_flags = header::MsgFlags::from_bits_retain(bits);
    }

    pub fn set_security_flags_raw(&mut self, bits: <header::SecFlags as Flags>::Bits) {
        self.m_sec_flags = header::SecFlags::from_bits_retain(bits);
        self.m_session_type = (self.m_sec_flags & header::SecFlagMask::KSessionTypeMask).bits() as header::SessionType;
    }

}
