// allow for never used before we implement all features
#![allow(dead_code)]
use crate::chip::system::system_config::CHIP_SYSTEM_CONFIG_HEADER_RESERVE_SIZE;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::crypto::crypto_pal::CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES;
use crate::chip::{NodeId,GroupId};

use crate::ChipError;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;

use core::mem::size_of;
use core::slice;

use bitflags::{Flags};

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
    #[derive(Clone, Copy, PartialEq)]
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

    pub const KSESSION_TYPE_MASK: u8 = 0b00000011;

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
    pub const KPRIVACY_HEADER_OFFSET: usize = 4;
    pub const KPRIVACY_HEADER_MIN_LENGTH: usize = 4;
    pub const KHEADER_MIN_LENGTH: usize = 8;

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
        self.m_session_type = header::SessionType::from(self.m_sec_flags.bits() & header::KSESSION_TYPE_MASK);
    }

    pub fn is_group_session(&self) -> bool {
        false
    }

    pub fn is_unicast_session(&self) -> bool {
        self.m_session_type == header::SessionType::KUnicastSession
    }

    pub fn is_session_type_valid(&self) -> bool {
        match self.m_session_type {
            header::SessionType::KGroupSession => true,
            header::SessionType::KUnicastSession => true,
        }
    }

    pub fn is_valid_group_msg(&self) -> bool {
        return self.is_group_session() && self.has_source_node_id() && self.has_destination_node_id() && !self.is_secure_session_control_msg();
    }

    pub fn is_valid_mcsp_msg(&self) -> bool {
        return self.is_group_session() && self.has_source_node_id() && self.has_destination_node_id() && self.is_secure_session_control_msg();
    }

    pub fn is_encrypted(&self) -> bool {
        return !((self.m_sessino_id == KMSG_UNICAST_SESSION_ID_UNSECURED) && self.is_unicast_session());
    }

    pub fn mic_tag_length(&self) -> u16 {
        if self.is_encrypted() {
            return CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES as u16;
        } else {
            return 0;
        }
    }

    pub fn is_secure_session_control_msg(&self) -> bool {
        return self.m_sec_flags.contains(header::SecFlagValues::KControlMsgFlag);
    }

    pub fn set_secure_session_control_msg(mut self, value: bool) -> Self {
        self.m_sec_flags.set(header::SecFlagValues::KControlMsgFlag, value);
        self
    }

    pub fn set_source_node_id(mut self, id: NodeId) -> Self {
        self.m_source_node_id = Some(id);
        self.m_msg_flags.insert(header::MsgFlagValues::KSourceNodeIdPresent);
        self
    }

    pub fn set_source_node_id_option(mut self, id: Option<NodeId>) -> Self {
        self.m_source_node_id = id;
        self.m_msg_flags.set(header::MsgFlagValues::KSourceNodeIdPresent, id.is_some());
        self
    }

    pub fn clear_source_node_id(mut self) -> Self {
        self.m_source_node_id = None;
        self.m_msg_flags.remove(header::MsgFlagValues::KSourceNodeIdPresent);
        self
    }

    pub fn set_destination_node_id(mut self, id: NodeId) -> Self {
        self.m_destination_node_id = Some(id);
        self.m_msg_flags.insert(header::MsgFlagValues::KDestinationNodeIdPresent);
        self
    }

    pub fn set_destination_node_id_option(mut self, id: Option<NodeId>) -> Self {
        self.m_destination_node_id = id;
        self.m_msg_flags.set(header::MsgFlagValues::KDestinationNodeIdPresent, id.is_some());
        self
    }

    pub fn clear_destination_node_id(mut self) -> Self {
        self.m_destination_node_id = None;
        self.m_msg_flags.remove(header::MsgFlagValues::KDestinationNodeIdPresent);
        self
    }

    pub fn set_session_type(mut self, the_type: header::SessionType) -> Self {
        self.m_session_type = the_type;
        let type_mask: u8 = header::KSESSION_TYPE_MASK as u8;
        self.m_sec_flags = header::SecFlags::from_bits_retain((self.m_sec_flags.bits() & !type_mask) | (the_type as u8 & type_mask));
        self
    }

    pub fn set_session_id(mut self, id: u16) -> Self {
        self.m_sessino_id = id;
        self
    }

    pub fn set_message_counter(mut self, counter: u32) -> Self {
        self.m_message_counter = counter;
        self
    }

    pub fn set_unsecured(mut self) -> Self {
        self.m_sessino_id = KMSG_UNICAST_SESSION_ID_UNSECURED;
        self.m_session_type = header::SessionType::KUnicastSession;
        self
    }

    pub fn privacy_header(msg_buf: * mut u8) -> * mut u8 {
        msg_buf.wrapping_add(Self::KPRIVACY_HEADER_OFFSET)
    }

    pub fn privacy_header_length(&self) -> usize {
        let mut len: usize = Self::KPRIVACY_HEADER_MIN_LENGTH;
        if self.m_msg_flags.contains(header::MsgFlagValues::KSourceNodeIdPresent) {
            len += size_of::<NodeId>();
        }
        if self.m_msg_flags.contains(header::MsgFlagValues::KDestinationNodeIdPresent) {
            len += size_of::<NodeId>();
        }
        if self.m_msg_flags.contains(header::MsgFlagValues::KDestinationGroupIdPresent) {
            len += size_of::<GroupId>();
        }

        return len;
    }

    pub fn payload_offset(&self) -> usize {
        let mut offset: usize = Self::KPRIVACY_HEADER_MIN_LENGTH;
        offset += self.privacy_header_length();
        return offset;
    }

    /**
     * A call to `Encode` will require at least this many bytes on the current
     * object to be successful.
     *
     * @return the number of bytes needed in a buffer to be able to Encode.
     */
    pub fn encode_size_bytes(&self) -> u16 {
        0
    }

    /**
     * Decodes the fixed portion of the header fields from the given buffer.
     * The fixed header includes: message flags, session id, and security flags.
     *
     * @return CHIP_NO_ERROR on success.
     *
     * Possible failures:
     *    CHIP_ERROR_INVALID_ARGUMENT on insufficient buffer size
     *    CHIP_ERROR_VERSION_MISMATCH if header version is not supported.
     */
    pub fn decode_fixed(&mut self, buf: &PacketBufferHandle) -> ChipError {
        chip_no_error!()
    }

    /**
     * Decodes a header from the given buffer.
     *
     * @param data - the buffer to read from
     * @param size - bytes available in the buffer
     * @param decode_size - number of bytes read from the buffer to decode the
     *                      object
     *
     * @return CHIP_NO_ERROR on success.
     *
     * Possible failures:
     *    CHIP_ERROR_INVALID_ARGUMENT on insufficient buffer size
     *    CHIP_ERROR_VERSION_MISMATCH if header version is not supported.
     */
    pub fn decode(&mut self, data: &[u8], decode_size: &mut u16) -> ChipError {
        chip_no_error!()
    }

    /**
     * A version of Decode that decodes from the start of a PacketBuffer and
     * consumes the bytes we decoded from.
     */
    pub fn decode_and_consume(&mut self, buf: &PacketBufferHandle) -> ChipError {
        chip_no_error!()
    }

    /**
     * Encodes a header into the given buffer.
     *
     * @param data - the buffer to write to
     * @param size - space available in the buffer (in bytes)
     * @param encode_size - number of bytes written to the buffer.
     *
     * @return CHIP_NO_ERROR on success.
     *
     * Possible failures:
     *    CHIP_ERROR_INVALID_ARGUMENT on insufficient buffer size
     */
    pub fn encode(&self, data: &[u8], encode_size: &mut u16) -> ChipError {
        chip_no_error!()
    }

    pub fn encode_before_data(&self, buf: &PacketBufferHandle) -> ChipError {
        chip_no_error!()
    }

    pub fn encode_at_start(&self, buf: &PacketBufferHandle, encode_size: &mut u16) -> ChipError {
        unsafe {
            return self.encode(slice::from_raw_parts((*(buf.get_raw())).start(), (*(buf.get_raw())).data_len() as usize), encode_size);
        }
    }

}
