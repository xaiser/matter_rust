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
        crypto::Text,
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
    let total_length = msg_buf.total_length();

    let data = unsafe {
        core::slice::from_raw_parts_mut(msg_buf.start(), total_length)
    };

    let mut mac = MessageAuthenticationCode::default();

    context.encrypt(Text::new_in_place(data), nonce, packet_header, &mut mac)?;

    let data = unsafe {
        core::slice::from_raw_parts_mut(msg_buf.start().add(total_length), msg_buf.available_data_length())
    };
    let mut tag_len: u16 = 0;
    mac.encode(packet_header, data, &mut tag_len)?;

    msg_buf.set_data_length(total_length + tag_len as usize);

    chip_ok!()
}

pub fn decrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &PayloadHeader, packet_header: &PacketHeader, msg_buf: &mut PacketBufferHandle) -> ChipErrorResult {
    chip_ok!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            system::system_packet_buffer::{
                reset_pool,
                PacketBufferHandle,
            },
        },
    };

    fn setup() {
        reset_pool();
    }

    #[test]
    fn encrypt_successfull() {
        let msg = PacketBufferHandle::new(0,0);
        assert!(false);
    }
} // end of tests
