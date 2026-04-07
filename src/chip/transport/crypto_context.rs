#![allow(dead_code)]
use crate::{
    chip::{
        chip_lib::support::buffer_writer::{self, EndianBufferWriter, BufferWriter},
        crypto::{
            crypto_pal::{
                Aes128KeyHandle, AttestationChallenge, SymmetricKeyContext, P256Keypair, P256PublicKey, HkdfKeyHandle,
                P256EcdhDeriveSecret, ECPKeypair,
            },
            session_keystore::SessionKeystore,
        },
        transport::raw::message_header::{MessageAuthenticationCode, PacketHeader},
        NodeId,
    },
    verify_or_return_error, verify_or_return_value,
    ChipError, ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    chip_error_incorrect_state, chip_error_internal, chip_error_no_memory, chip_error_invalid_argument,
};

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
/*
type NonceView<'a> = &'a mut [u8; CryptoContext::KAESCCM_NONCE_LEN];
type ConstNonceView<'a> = &'a [u8; CryptoContext::KAESCCM_NONCE_LEN];
*/

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

    pub fn encrypt(&self, input: &[u8], output: &mut [u8], nonce: &[u8; Self::KAESCCM_NONCE_LEN], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn decrypt(&self, input: &[u8], output: &mut [u8], nonce: &[u8; Self::KAESCCM_NONCE_LEN], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn privacy_encrypt(&self, input: &[u8], output: &mut [u8], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        chip_ok!()
    }
    pub fn privacy_decrypt(&self, input: &[u8], output: &mut [u8], header: &PacketHeader, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn get_attestation_challenge(&self) -> &[u8] {
        &[]
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
                raw_session_keystore::RawKeySessionKeystore,
                session_keystore::SessionKeystore,
                Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
                P256EcdhDeriveSecret, AttestationChallenge, FromOpaqueContext, OpaqueContext, HKDFSha, clear_secret_data,
                ECPKeyTarget, P256KeypairBase,
            },
        },
    };
    use core::ptr;

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
        keypair.initialize(ECPKeyTarget::Ecdh);

        let mut remote_keypair = P256Keypair::default();
        remote_keypair.initialize(ECPKeyTarget::Ecdh);
        let remote_public_key = remote_keypair.public_key();

        let salt = [1u8; 2];

        assert!(context.init_from_key_pair(ptr::addr_of_mut!(keystore), &keypair, &remote_public_key, &salt[..], SessionInfoType::KSessionEstablishment, 
                SessionRole::KInitiator).is_ok());
    }
} // end of tests
