use crate::{
    chip::{
        transport::{
            raw::{
                message_header::{PayloadHeader, PacketHeader, MessageAuthenticationCode},
            },
            crypto_context::{
                CryptoContext,
                NONCE_LENGTH,
            },
        },
        system::system_packet_buffer::PacketBufferHandle,
    },
    verify_or_return_error, verify_or_return_value,
    ChipError, ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    chip_error_invalid_argument, chip_error_invalid_message_length,
};

pub fn encrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &PayloadHeader, packet_header: &PacketHeader, 
    msg_buf: &mut PacketBufferHandle) -> ChipErrorResult
{
    verify_or_return_error!(!msg_buf.is_null(), Err(chip_error_invalid_argument!()));
    verify_or_return_error!(!msg_buf.has_chained_buffer(), Err(chip_error_invalid_message_length!()));

    payload_header.encode_before_data(msg_buf)?;

    let data = msg_buf.start();
    let total_len = msg_buf.total_length();

    let mut mac = MessageAuthenticationCode::default();

    //context.encrypt(data.as_ref_unchecked(), data.as_mut_unchecked(), nonce, packet_header, &mut mac)?;

    chip_ok!()
}

pub fn decrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &PayloadHeader, packet_header: &PacketHeader, msg_buf: &mut PacketBufferHandle) -> ChipErrorResult {
    chip_ok!()
}
