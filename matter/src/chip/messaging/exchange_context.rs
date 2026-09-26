use crate::{
    chip::{
        protocols::{
            self, protocols::MessageTypeTrait,
        },
        system::{
            system_packet_buffer::PacketBufferHandle,
        },
        messaging::{
            flags::SendMessageFlags as SendFlags,
        },
    },
    ChipErrorResult, chip_ok,
    chip_error_invalid_argument,
    chip_core_error, chip_sdk_error,
};

pub struct ExchangeContext;

impl ExchangeContext {
    pub fn get_exchange_id(&self) -> u16 {
        0
    }

    pub fn is_initiator(&self) -> bool {
        false
    }

    pub fn send_message_id_type(&mut self, _protocol_id: protocols::Id, _msg_type: u8, _msg_payload: PacketBufferHandle,
        _send_flags: &SendFlags) -> ChipErrorResult {

        chip_ok!()
    }

    pub fn send_message<MsgType: MessageTypeTrait>(&mut self, msg_type: MsgType, msg_payload: PacketBufferHandle,
        send_flags: &SendFlags) -> ChipErrorResult {
        /*
        self.send_message_id_type(<MsgType as MessageTypeTrait>::PROTOCOL_ID, msg_type.try_into().map_err(|_|
                Err(chip_error_invalid_argument!()))?, msg_payload, send_flags)
        */
    }
}
