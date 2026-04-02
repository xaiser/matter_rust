#![allow(dead_code)]
use crate::{
    ChipError, ChipErrorResult, chip_ok, chip_core_error, chip_sdk_error,
    chip::{
        crypto::{
            crypto_pal::{
                Aes128KeyHandle, AttestationChallenge, SymmetricKeyContext, P256Keypair, P256PublicKey, HkdfKeyHandle,
            },
            session_keystore::SessionKeystore,
        },
        transport::raw::message_header::{MessageAuthenticationCode, PacketHeader},
        NodeId,
    },
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
        chip_ok!()
    }

    pub fn init_from_secret(&mut self, keystore: *mut dyn SessionKeystore, secret: &[u8],
        salt: &[u8], info_type: SessionInfoType, role: SessionRole) -> ChipErrorResult
    {
        chip_ok!()
    }

    pub fn init_from_secret_hkdf_key(&mut self, keystore: *mut dyn SessionKeystore, hkdf_key: &HkdfKeyHandle,
        salt: &[u8], info_type: SessionInfoType, role: SessionRole) -> ChipErrorResult
    {
        chip_ok!()
    }

    pub fn build_nonce(nonce: &[u8; Self::KAESCCM_NONCE_LEN], security_flags: u8, message_counter: u32, node_id: NodeId) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn build_privacy_nonce(nonce: &[u8; Self::KAESCCM_NONCE_LEN], session_id: u16, mac: &MessageAuthenticationCode) -> ChipErrorResult {
        chip_ok!()
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

    fn get_additional_auth_data(header: &PacketHeader, aad: &mut [u8]) {}
}
