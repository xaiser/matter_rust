#![allow(dead_code)]
use crate::{
    chip::{
        chip_lib::support::buffer_writer::{self, BufferWriter},
        crypto::{
            aes::key_128::{mode_ccm},
            crypto_pal::{
                Aes128KeyHandle, AttestationChallenge, SymmetricKeyContext, P256Keypair, P256PublicKey, HkdfKeyHandle,
                P256EcdhDeriveSecret, ECPKeypair, SymmetricEncryptResult, SymmetricDecryptResult,
            },
            session_keystore::SessionKeystore,
        },
        transport::raw::message_header::{MessageAuthenticationCode, PacketHeader, KMAX_TAG_LEN},
        NodeId,
    },
    verify_or_return_error, verify_or_return_value,
    ChipError, ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    chip_error_incorrect_state, chip_error_internal, chip_error_no_memory, chip_error_invalid_argument, chip_error_invalid_use_of_session_key,
};

/*
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;
*/

use core::ptr::NonNull;

#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum SessionRole {
    KInitiator,
    KResponder,
}

#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum SessionInfoType {
    KSessionEstablishment, /* A new secure session is established. */
    KSessionResumption,    /* An old session is being resumed. */
}

pub struct CryptoContext {
    m_session_role: SessionRole,
    m_key_available: bool,
    m_encryption_key: Aes128KeyHandle,
    m_decryption_key: Aes128KeyHandle,
    m_attestation_challenge: AttestationChallenge,
    // Since we have to removed the type in the session holder, so we cannot use template here.
    // TODO: find a way to not use *mut dyn
    m_key_store: Option<NonNull<dyn SessionKeystore>>,
    m_key_context: Option<NonNull<dyn SymmetricKeyContext>>,
}

type NonceStorage = [u8; CryptoContext::KAESCCM_NONCE_LEN];
// Somehow rustc melt down on this define

impl Drop for CryptoContext {
    fn drop(&mut self) {
        if let Some(store) = self.m_key_store.as_mut() {
            unsafe {
                store.as_mut().destroy_key_128bits(&mut self.m_encryption_key);
                store.as_mut().destroy_key_128bits(&mut self.m_decryption_key);
            }
        }

        self.m_key_store = None;
        self.m_key_context = None;
    }
}

impl CryptoContext {
    pub const KPRIVACY_NONCE_MIC_FRAGMENT_OFFSET: usize = 5;
    pub const KPRIVACY_NONCE_MIC_FRAGMENT_LENGTH: usize = 11;
    pub const KAESCCM_NONCE_LEN: usize = 13;

    const KMAX_AAD_LEN: usize = 128;

    /* Session Establish Key Info */
    const SE_KEYS_INFO: [u8; 11] = [ 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73 ];

    /* Session Resumption Key Info */
    const RSE_KEYS_INFO: [u8; 21] = [ 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x75,
                                        0x6d, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73 ];

    pub const fn new() -> Self {
        Self {
            m_session_role: SessionRole::KInitiator,
            m_key_available: false,
            m_encryption_key: Aes128KeyHandle::new(),
            m_decryption_key: Aes128KeyHandle::new(),
            m_attestation_challenge: AttestationChallenge::const_default(),
            m_key_store: None,
            m_key_context: None,
        }
    }

    pub const fn new_with_key_context(key_context: NonNull<dyn SymmetricKeyContext>) -> Self {
        Self {
            m_session_role: SessionRole::KInitiator,
            m_key_available: false,
            m_encryption_key: Aes128KeyHandle::new(),
            m_decryption_key: Aes128KeyHandle::new(),
            m_attestation_challenge: AttestationChallenge::const_default(),
            m_key_store: None,
            m_key_context: Some(key_context),
        }
    }

    pub fn init_from_key_pair(&mut self, keystore: *mut dyn SessionKeystore, local_keypair: &P256Keypair, remote_public_key: &P256PublicKey,
        salt: &[u8], info_type: SessionInfoType, role: SessionRole) -> ChipErrorResult
    {
        verify_or_return_error!(self.m_key_available == false, Err(chip_error_incorrect_state!()));
        let mut secret = P256EcdhDeriveSecret::default();

        local_keypair.ecdh_derive_secret(remote_public_key, &mut secret)?;

        return self.init_from_secret(keystore, secret.const_bytes(), salt, info_type, role);
    }

    pub fn init_from_secret(&mut self, keystore: *mut dyn SessionKeystore, secret: &[u8],
        salt: &[u8], info_type: SessionInfoType, role: SessionRole) -> ChipErrorResult
    {
        verify_or_return_error!(self.m_key_available == false, Err(chip_error_incorrect_state!()));
        let info = if info_type == SessionInfoType::KSessionResumption {
            &Self::RSE_KEYS_INFO[..]
        } else {
            &Self::SE_KEYS_INFO[..]
        };
        unsafe {
            if let Some(store) = keystore.as_mut() {
                let keys = store.derive_session_keys_aes128(secret, salt, info)?;
                if role == SessionRole::KInitiator {
                    self.m_encryption_key = keys.i2r_key;
                    self.m_decryption_key = keys.r2i_key;
                } else {
                    self.m_encryption_key = keys.r2i_key;
                    self.m_decryption_key = keys.i2r_key;
                }

                self.m_attestation_challenge = keys.attestation_challenge;
            } else {
                return Err(chip_error_internal!());
            }
        }

        self.m_key_available = true;
        self.m_session_role = role;

        unsafe {
            self.m_key_store = Some(NonNull::new_unchecked(keystore));
        }

        chip_ok!()
    }

    pub fn init_from_secret_hkdf_key(&mut self, keystore: *mut dyn SessionKeystore, hkdf_key: &HkdfKeyHandle,
        salt: &[u8], info_type: SessionInfoType, role: SessionRole) -> ChipErrorResult
    {
        verify_or_return_error!(self.m_key_available == false, Err(chip_error_incorrect_state!()));
        let info = if info_type == SessionInfoType::KSessionResumption {
            &Self::RSE_KEYS_INFO[..]
        } else {
            &Self::SE_KEYS_INFO[..]
        };
        unsafe {
            if let Some(store) = keystore.as_mut() {
                let keys = store.derive_session_keys_hkdf(hkdf_key, salt, info)?;
                if role == SessionRole::KInitiator {
                    self.m_encryption_key = keys.i2r_key;
                    self.m_decryption_key = keys.r2i_key;
                } else {
                    self.m_encryption_key = keys.r2i_key;
                    self.m_decryption_key = keys.i2r_key;
                }

                self.m_attestation_challenge = keys.attestation_challenge;
            } else {
                return Err(chip_error_internal!());
            }
        }

        self.m_key_available = true;
        self.m_session_role = role;

        unsafe {
            self.m_key_store = Some(NonNull::new_unchecked(keystore));
        }

        chip_ok!()
    }

    pub fn build_nonce(nonce: &mut [u8; Self::KAESCCM_NONCE_LEN], security_flags: u8, message_counter: u32, node_id: NodeId) -> ChipErrorResult {
        let mut bbuf = buffer_writer::little_endian::BufferWriter::default_with_buf(&mut nonce[..]);
        bbuf.put_u8(security_flags);
        bbuf.put_u32(message_counter);
        bbuf.put_u64(node_id);

        if bbuf.is_fit() {
            return chip_ok!()
        } else {
            return Err(chip_error_no_memory!());
        }
    }

    pub fn build_privacy_nonce(nonce: &mut [u8; Self::KAESCCM_NONCE_LEN], session_id: u16, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        let mut bbuf = buffer_writer::little_endian::BufferWriter::default_with_buf(&mut nonce[..]);
        let mic_fragment = &mac.get_tag()[Self::KPRIVACY_NONCE_MIC_FRAGMENT_OFFSET..(Self::KPRIVACY_NONCE_MIC_FRAGMENT_OFFSET + Self::KPRIVACY_NONCE_MIC_FRAGMENT_LENGTH)];
        bbuf.put_u16(session_id);
        bbuf.put(mic_fragment);

        if bbuf.is_fit() {
            return chip_ok!()
        } else {
            return Err(chip_error_no_memory!());
        }
    }

    pub fn encrypt(&self, input: &[u8], output: &mut [u8], nonce: &[u8; Self::KAESCCM_NONCE_LEN], header: &PacketHeader, mac: &mut MessageAuthenticationCode) -> Result<SymmetricEncryptResult, ChipError> {
        let tag_len = header.mic_tag_length();

        verify_or_return_error!(input.len() > 0 && input.len() <= output.len(), Err(chip_error_invalid_argument!()));

        let mut aad = [0u8; Self::KMAX_AAD_LEN];
        let mut tag = [0u8; KMAX_TAG_LEN];

        let aad_len = Self::get_additional_auth_data(header, &mut aad)?;
        verify_or_return_error!(aad_len <= Self::KMAX_AAD_LEN, Err(chip_error_invalid_argument!()));
        verify_or_return_error!(usize::from(tag_len) <= KMAX_TAG_LEN, Err(chip_error_invalid_argument!()));

        let result_sizes;

        if let Some(context_ptr) = self.m_key_context.as_ref() 
        {
            unsafe {
                result_sizes = context_ptr.as_ref().message_encrypt(input, &aad[..aad_len], &nonce[..], &mut tag[..tag_len as usize], &mut output[..input.len()])?;
            }
        } else {
            verify_or_return_error!(self.m_key_available, Err(chip_error_invalid_use_of_session_key!()));
            result_sizes = mode_ccm::encrypt_autosize(input, &aad[..aad_len], &self.m_encryption_key, &nonce[..], &mut tag[..tag_len as usize], &mut output[..input.len()])?;
        }

        if !mac.set_tag_ref(&tag[..tag_len as usize]) {
            return Err(chip_error_invalid_argument!());
        }

        Ok(result_sizes)
    }

    pub fn decrypt(&self, input: &[u8], output: &mut [u8], nonce: &[u8; Self::KAESCCM_NONCE_LEN], header: &PacketHeader, mac: &MessageAuthenticationCode) -> Result<SymmetricDecryptResult, ChipError> {
        let tag_len = header.mic_tag_length();
        let tag = mac.get_tag();
        verify_or_return_error!(usize::from(tag_len) <= tag.len(), Err(chip_error_invalid_argument!()));

        verify_or_return_error!(input.len() > 0 && input.len() <= output.len(), Err(chip_error_invalid_argument!()));

        let mut aad = [0u8; Self::KMAX_AAD_LEN];

        let aad_len = Self::get_additional_auth_data(header, &mut aad)?;
        verify_or_return_error!(aad_len <= Self::KMAX_AAD_LEN, Err(chip_error_invalid_argument!()));

        let result_sizes;

        if let Some(context_ptr) = self.m_key_context.as_ref() 
        {
            unsafe {
                result_sizes = context_ptr.as_ref().message_decrypt(input, &aad[..aad_len], &nonce[..], &tag[..tag_len as usize], &mut output[..input.len()])?;
            }
        } else {
            verify_or_return_error!(self.m_key_available, Err(chip_error_invalid_use_of_session_key!()));
            result_sizes = mode_ccm::decrypt_autosize(input, &aad[..aad_len], &tag[..tag_len as usize], &self.m_decryption_key, &nonce[..], &mut output[..input.len()])?;
        }

        Ok(result_sizes)
    }

    pub fn privacy_encrypt(&self, input: &[u8], output: &mut [u8], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        verify_or_return_error!(input.len() > 0 && input.len() <= output.len(), Err(chip_error_invalid_argument!()));

        if let Some(context_ptr) = self.m_key_context.as_ref() 
        {
            let mut privacy_nonce: [u8; Self::KAESCCM_NONCE_LEN] = [0; Self::KAESCCM_NONCE_LEN];
            Self::build_privacy_nonce(&mut privacy_nonce, header.get_session_id(), mac)?;
            unsafe {
                return context_ptr.as_ref().privacy_encrypt(input, &privacy_nonce[..], &mut output[..input.len()]);
            }
        } else {
            return Err(chip_error_invalid_use_of_session_key!());
        }
    }

    pub fn privacy_decrypt(&self, input: &[u8], output: &mut [u8], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        verify_or_return_error!(input.len() > 0 && input.len() <= output.len(), Err(chip_error_invalid_argument!()));

        if let Some(context_ptr) = self.m_key_context.as_ref() 
        {
            let mut privacy_nonce: [u8; Self::KAESCCM_NONCE_LEN] = [0; Self::KAESCCM_NONCE_LEN];
            Self::build_privacy_nonce(&mut privacy_nonce, header.get_session_id(), mac)?;
            unsafe {
                return context_ptr.as_ref().privacy_decrypt(input, &privacy_nonce[..], &mut output[..input.len()]);
            }
        } else {
            return Err(chip_error_invalid_use_of_session_key!());
        }
    }

    pub fn get_attestation_challenge(&self) -> &[u8] {
        self.m_attestation_challenge.const_bytes()
    }

    pub fn is_initiator(&self) -> bool {
        self.m_key_available && (self.m_session_role == SessionRole::KInitiator)
    }

    pub fn is_responder(&self) -> bool {
        self.m_key_available && (self.m_session_role == SessionRole::KResponder)
    }

    fn get_additional_auth_data(header: &PacketHeader, aad: &mut [u8]) -> Result<usize, ChipError> {
        verify_or_return_error!(aad.len() >= header.encode_size_bytes().into(), Err(chip_error_invalid_argument!()));

        let mut actual_encoded_header_size: u16 = 0;

        header.encode(aad, &mut actual_encoded_header_size)?;

        verify_or_return_error!(aad.len() >= actual_encoded_header_size.into(), Err(chip_error_invalid_argument!()));

        Ok(actual_encoded_header_size as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            crypto::{
                aes::key_128::{self, SymmetricKeyContext, mode_ccm},
                raw_session_keystore::RawKeySessionKeystore,
                session_keystore::{SessionKeystore, SessionKeys},
                Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
                P256EcdhDeriveSecret, AttestationChallenge, FromOpaqueContext, OpaqueContext, HKDFSha, clear_secret_data,
                ECPKeyTarget, P256KeypairBase,
            },
        },
    };
    use core::ptr;

    // tag = 16 bytes, nonce = 13 byte
    type TestKeyContext = key_128::RawSymmetricKeyContext<mode_ccm::U16, mode_ccm::U13>;

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
    fn init_by_secret_successfully() {
        let mut context = CryptoContext::new();
        let mut keystore = RawKeySessionKeystore::new();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());
    }

    #[test]
    fn init_by_hkdf_secret_successfully() {
        let mut context = CryptoContext::new();
        let mut keystore = RawKeySessionKeystore::new();

        const DATA_SIZE: usize = 2;
        let key_material = [1u8; DATA_SIZE];
        let hkdf_key = keystore.create_key_hkdf(&key_material);
        assert!(hkdf_key.is_ok());
        let hkdf_key = hkdf_key.unwrap();

        let salt = [1u8; 2];

        assert!(context.init_from_secret_hkdf_key(ptr::addr_of_mut!(keystore), &hkdf_key, &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());
    }

    #[test]
    fn init_by_keypair_successfully() {
        let mut context = CryptoContext::new();
        let mut keystore = RawKeySessionKeystore::new();

        let mut keypair = P256Keypair::default();
        let _ = keypair.initialize(ECPKeyTarget::Ecdh);

        let mut remote_keypair = P256Keypair::default();
        let _ = remote_keypair.initialize(ECPKeyTarget::Ecdh);
        let remote_public_key = remote_keypair.public_key();

        let salt = [1u8; 2];

        assert!(context.init_from_key_pair(ptr::addr_of_mut!(keystore), &keypair, &remote_public_key, &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());
    }

    #[test]
    fn encrypt_decrypt_correctly() {
        let mut context = CryptoContext::new();
        // ensure the encrypt & decrypt use the same key(default)
        let mut keystore = TestKeySessionKeystore::default();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        let nonce = [1u8; CryptoContext::KAESCCM_NONCE_LEN];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(context.encrypt(&input, &mut output, &nonce, &header, &mut mac).is_ok());

        let mut output_2 = [0u8; 16];

        assert!(context.decrypt(&output, &mut output_2, &nonce, &header, &mac).inspect_err(|e| println!("err is {:?}", e)).is_ok());
    }

    #[test]
    fn encrypt_empty_input() {
        let mut context = CryptoContext::new();
        // ensure the encrypt & decrypt use the same key(default)
        let mut keystore = TestKeySessionKeystore::default();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [];
        let mut output = [0u8; 16];
        let nonce = [1u8; CryptoContext::KAESCCM_NONCE_LEN];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(!context.encrypt(&input, &mut output, &nonce, &header, &mut mac).is_ok());
    }

    #[test]
    fn encrypt_empty_header() {
        let mut context = CryptoContext::new();
        // ensure the encrypt & decrypt use the same key(default)
        let mut keystore = TestKeySessionKeystore::default();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        let nonce = [1u8; CryptoContext::KAESCCM_NONCE_LEN];
        // create a encrypted header
        let header = PacketHeader::default();
        let mut mac = MessageAuthenticationCode::default();

        assert!(!context.encrypt(&input, &mut output, &nonce, &header, &mut mac).is_ok());
    }

    #[test]
    fn decrypt_empty_input() {
        let mut context = CryptoContext::new();
        // ensure the encrypt & decrypt use the same key(default)
        let mut keystore = TestKeySessionKeystore::default();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        let nonce = [1u8; CryptoContext::KAESCCM_NONCE_LEN];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(context.encrypt(&input, &mut output, &nonce, &header, &mut mac).is_ok());

        let mut output_2 = [];

        assert!(!context.decrypt(&output, &mut output_2, &nonce, &header, &mac).inspect_err(|e| println!("err is {:?}", e)).is_ok());
    }

    #[test]
    fn decrypt_empty_header() {
        let mut context = CryptoContext::new();
        // ensure the encrypt & decrypt use the same key(default)
        let mut keystore = TestKeySessionKeystore::default();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        let nonce = [1u8; CryptoContext::KAESCCM_NONCE_LEN];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(context.encrypt(&input, &mut output, &nonce, &header, &mut mac).is_ok());

        let mut output_2 = [0u8; 16];
        let header = PacketHeader::default();

        assert!(!context.decrypt(&output, &mut output_2, &nonce, &header, &mac).inspect_err(|e| println!("err is {:?}", e)).is_ok());
    }

    #[test]
    fn privacy_encrypt_decrypt_correctly() {
        let mut encrypt_key = Symmetric128BitsKeyByteArray::default();
        let mut privacy_key = Symmetric128BitsKeyByteArray::default();
        encrypt_key.fill(1);
        privacy_key.fill(2);
        let mut keystore = TestKeySessionKeystore::default();
        let mut key_context = TestKeyContext::new();

        assert!(key_context.init(&encrypt_key, &privacy_key, 0, ptr::addr_of_mut!(keystore)).is_ok());

        let mut context = CryptoContext::new_with_key_context(NonNull::from_mut(&mut key_context));

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(context.privacy_encrypt(&input, &mut output, &header, &mut mac).is_ok());

        let mut output_2 = [0u8; 16];

        assert!(context.privacy_decrypt(&output, &mut output_2, &header, &mac).inspect_err(|e| println!("err is {:?}", e)).is_ok());
    }

    #[test]
    fn privacy_encrypt_empyt_input() {
        let mut encrypt_key = Symmetric128BitsKeyByteArray::default();
        let mut privacy_key = Symmetric128BitsKeyByteArray::default();
        encrypt_key.fill(1);
        privacy_key.fill(2);
        let mut keystore = TestKeySessionKeystore::default();
        let mut key_context = TestKeyContext::new();

        assert!(key_context.init(&encrypt_key, &privacy_key, 0, ptr::addr_of_mut!(keystore)).is_ok());

        let mut context = CryptoContext::new_with_key_context(NonNull::from_mut(&mut key_context));

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [];
        let mut output = [0u8; 16];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(!context.privacy_encrypt(&input, &mut output, &header, &mut mac).is_ok());
    }

    #[test]
    fn privacy_encrypt_no_key_context() {
        let mut keystore = TestKeySessionKeystore::default();

        let mut context = CryptoContext::new();

        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let salt = [1u8; 2];

        assert!(context.init_from_secret(ptr::addr_of_mut!(keystore), secret.const_bytes(), &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());

        let input = [1u8; 16];
        let mut output = [0u8; 16];
        // create a encrypted header
        let header = PacketHeader::default().set_session_id(0x1);
        let mut mac = MessageAuthenticationCode::default();

        assert!(!context.privacy_encrypt(&input, &mut output, &header, &mut mac).is_ok());
    }
} // end of tests
