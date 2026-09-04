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
    ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    chip_error_invalid_argument, chip_error_invalid_message_length, chip_error_internal,
};

/*
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::str::FromStr;
*/

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

#[allow(dead_code)]
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
                session_keystore::{SessionKeystore, SessionKeys},
                raw_session_keystore::RawKeySessionKeystore,
                P256EcdhDeriveSecret, Symmetric128BitsKeyByteArray,  Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle,
                Symmetric128BitsKeyHandle,
            },
            transport::{
                crypto_context::{
                    SessionInfoType,
                    SessionRole,
                },
            },
            protocols::protocols, VendorId,
        },
        ChipError,
    };
    use core::ptr;

    // a key store to create keypair where encrypt key = decrypti key
    #[derive(Default)]
    pub struct TestKeySessionKeystore {
        pub m_aes128_session_keys: SessionKeys,
        pub m_hkdf_session_keys: SessionKeys,
    }

    impl SessionKeystore for TestKeySessionKeystore {
        fn create_key_aes128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Aes128KeyHandle, ChipError> {
            let mut key = Aes128KeyHandle::default();
            key.as_mut::<Symmetric128BitsKeyByteArray>().copy_from_slice(key_material);

            Ok(key)
        }

        fn create_key_hmac128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Hmac128KeyHandle, ChipError> {
            let mut key = Hmac128KeyHandle::default();
            key.as_mut::<Symmetric128BitsKeyByteArray>().copy_from_slice(key_material);

            Ok(key)
        }

        fn create_key_hkdf(&mut self, _key_material: &[u8]) -> Result<HkdfKeyHandle, ChipError> {
            let key = HkdfKeyHandle::default();

            Ok(key)
        }

        fn destroy_key_128bits(&mut self, _key: &mut Symmetric128BitsKeyHandle) {
        }

        fn destroy_key_hkdf(&mut self, _key: &mut HkdfKeyHandle) {
        }

        fn drive_key(&mut self, _secret: &P256EcdhDeriveSecret, _salt: &[u8], _info: &[u8]) -> Result<Aes128KeyHandle, ChipError> {
            Ok(Aes128KeyHandle::default())
        }

        fn derive_session_keys_aes128(&mut self, _secret: &[u8], _salt: &[u8], _info: &[u8]) -> Result<SessionKeys, ChipError> {
            let mut session_keys = SessionKeys::default();

            // i2r
            let src = self.m_aes128_session_keys.i2r_key.as_ref::<Symmetric128BitsKeyByteArray>();
            let dest = session_keys.i2r_key.as_mut::<Symmetric128BitsKeyByteArray>();
            dest.copy_from_slice(src);

            // r2i
            let src = self.m_aes128_session_keys.r2i_key.as_ref::<Symmetric128BitsKeyByteArray>();
            let dest = session_keys.r2i_key.as_mut::<Symmetric128BitsKeyByteArray>();
            dest.copy_from_slice(src);

            // challenge
            let src = self.m_aes128_session_keys.attestation_challenge.const_bytes();
            let dest = session_keys.attestation_challenge.bytes();
            dest.copy_from_slice(src);

            Ok(session_keys)
        }

        fn derive_session_keys_hkdf(&mut self, _secret: &HkdfKeyHandle, _salt: &[u8], _info: &[u8]) -> Result<SessionKeys, ChipError> {
            let mut session_keys = SessionKeys::default();

            // i2r
            let src = self.m_hkdf_session_keys.i2r_key.as_ref::<Symmetric128BitsKeyByteArray>();
            let dest = session_keys.i2r_key.as_mut::<Symmetric128BitsKeyByteArray>();
            dest.copy_from_slice(src);

            // r2i
            let src = self.m_hkdf_session_keys.r2i_key.as_ref::<Symmetric128BitsKeyByteArray>();
            let dest = session_keys.r2i_key.as_mut::<Symmetric128BitsKeyByteArray>();
            dest.copy_from_slice(src);

            // challenge
            let src = self.m_hkdf_session_keys.attestation_challenge.const_bytes();
            let dest = session_keys.attestation_challenge.bytes();
            dest.copy_from_slice(src);

            Ok(session_keys)
        }

        fn persist_icd_key(&mut self) -> Result<Symmetric128BitsKeyHandle, ChipError> {
            Ok(Symmetric128BitsKeyHandle::default())
        }
    }

    #[test]
    fn encrypt_successfull() {
        let mut msg = PacketBufferHandle::new(0,0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default();
        //let packet_header = PacketHeader::default();
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
        let msg_1 = PacketBufferHandle::new(0,0).unwrap();
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
        //let packet_header = PacketHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        // to ensure the encrypt key = decrypt key
        let mut keystore = TestKeySessionKeystore::default();
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
        assert_eq!(payload_header.get_exchange_id(), payload_header_output.get_exchange_id());
    }

    #[test]
    fn decrypt_null_msg() {
        // to encrypt first
        let data = [1u8; 16];
        let mut msg = PacketBufferHandle::new_with_data(&data[..], 0, 0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default().set_exchange_id(0xBBAA);
        //let packet_header = PacketHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        // to ensure the encrypt key = decrypt key
        let mut keystore = TestKeySessionKeystore::default();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];
        let mut context = CryptoContext::new();
        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        assert!(encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());

        let mut payload_header_output = PayloadHeader::default();

        let _ = msg.pop_head();
        assert!(!decrypt(&context, &nonce, &mut payload_header_output, &packet_header, &mut msg).is_ok());
    }

    #[test]
    fn decrypt_invalid_packet_header() {
        // to encrypt first
        let data = [1u8; 16];
        let mut msg = PacketBufferHandle::new_with_data(&data[..], 0, 0).unwrap();
        let nonce = [1u8; NONCE_LENGTH];
        let payload_header = PayloadHeader::default().set_exchange_id(0xBBAA);
        //let packet_header = PacketHeader::default();
        let mut packet_header = PacketHeader::default()
            .set_session_id(0x3412)
            .set_message_counter(0x00123456)
            .set_source_node_id(0x1122334455667788)
            .set_destination_node_id(0x2233445566778899);
        packet_header.set_message_flags_raw(0x05);
        packet_header.set_security_flags_raw(0x00);

        // to ensure the encrypt key = decrypt key
        let mut keystore = TestKeySessionKeystore::default();
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);
        let salt = [1u8; 2];
        let mut context = CryptoContext::new();
        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        assert!(encrypt(&context, &nonce, &payload_header, &packet_header, &mut msg).is_ok());

        let mut payload_header_output = PayloadHeader::default();
        let packet_header = PacketHeader::default();

        assert!(!decrypt(&context, &nonce, &mut payload_header_output, &packet_header, &mut msg).is_ok());
    }
} // end of tests
