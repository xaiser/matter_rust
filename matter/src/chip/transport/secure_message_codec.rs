use crate::{
    chip::{
        transport::{
            raw::{
                message_header::{PayloadHeader, PacketHeader},
            },
            crypto_context::{
                CryptoContext,
                NONCE_LENGTH,
            },
        },
        system::system_packet_buffer::PacketBufferHandle,
    },
    //verify_or_return_error, verify_or_return_value,
    ChipError, ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    //chip_error_incorrect_state, chip_error_internal, chip_error_no_memory, chip_error_invalid_argument, chip_error_invalid_use_of_session_key,
};

pub fn encrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &PayloadHeader, packet_header: &PacketHeader, msg_buf: &mut PacketBufferHandle) -> ChipErrorResult {
    chip_ok!()
}

pub fn decrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &PayloadHeader, packet_header: &PacketHeader, msg_buf: &mut PacketBufferHandle) -> ChipErrorResult {
    chip_ok!()
}
