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
    chip_error_invalid_argument, chip_error_invalid_message_length, chip_error_internal,
};

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::str::FromStr;

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

pub fn decrypt(context: &CryptoContext, nonce: &[u8; NONCE_LENGTH], payload_header: &mut PayloadHeader, packet_header: &PacketHeader, msg_buf: &mut PacketBufferHandle) -> ChipErrorResult {
    verify_or_return_error!(!msg_buf.is_null(), Err(chip_error_invalid_argument!()));

    let total_length = msg_buf.total_length();
    let data = unsafe {
        core::slice::from_raw_parts_mut(msg_buf.start(), total_length)
    };

    let footer_len = packet_header.mic_tag_length() as usize;
    verify_or_return_error!(footer_len <= total_length, Err(chip_error_invalid_message_length!()));

    let mut tag_len = 0u16;
    let mut mac = MessageAuthenticationCode::default();
    if let Some(mac_data) = data.get((total_length - footer_len)..) {
        mac.decode(packet_header, mac_data, &mut tag_len)?;
    } else {
        return Err(chip_error_invalid_message_length!());
    }

    verify_or_return_error!(usize::from(tag_len) == footer_len, Err(chip_error_internal!()));

    let len = total_length - tag_len as usize;

    msg_buf.set_data_length(len);
    let data = unsafe {
        core::slice::from_raw_parts_mut(msg_buf.start(), len)
    };
    context.decrypt(Text::new_in_place(data), nonce, packet_header, &mac)?;

    payload_header.decode_and_consume(msg_buf)?;

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
            crypto::{
                aes::key_128::{self, SymmetricKeyContext, mode_ccm},
                raw_session_keystore::RawKeySessionKeystore,
                P256EcdhDeriveSecret,
            },
            transport::{
                crypto_context::{
                    SessionInfoType,
                    SessionRole,
                },
            },
            protocols::protocols, VendorId,
        },
    };
    use core::ptr;


    fn setup() {
        reset_pool();
    }

    #[test]
    fn encrypt_successfull() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        let packet_header = PacketHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        let mut keystore = RawKeySessionKeystore::new();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];

        let mut context = CryptoContext::new();

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        assert!(encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn encrypt_null_buffer() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        let mut keystore = RawKeySessionKeystore::new();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];

        let mut context = CryptoContext::new();

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let _ = msg.pop_head();

        assert!(!encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn encrypt_chained_buffer() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let mut msg_1 = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        let mut keystore = RawKeySessionKeystore::new();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];

        let mut context = CryptoContext::new();

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        msg.add_to_end(msg_1);

        assert!(!encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn encrypt_invalid_packet_head() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        let packet_header = PacketHeader::default();

        let mut keystore = RawKeySessionKeystore::new();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];

        let mut context = CryptoContext::new();

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        assert!(!encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn encrypt_invalid_context() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        let context = CryptoContext::new();

        assert!(!encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn decrypt_successfull() {
        // to encrypt first
        let data = [1u8; 16];
        let mut msg = PacketBufferHandle::new_with_data(&data[..], 0, 0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default().set_exchange_id(0xBBAA);
        let packet_header = PacketHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        let mut keystore = RawKeySessionKeystore::new();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];
        let mut context = CryptoContext::new();
        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        assert!(encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());

        let mut payload_header_output = PayloadHeader::default();

        assert!(decrypt(&context, &nonce, &mut payload_header_output, &packet_header, &mut msg).is_ok());
    }
} // end of tests
