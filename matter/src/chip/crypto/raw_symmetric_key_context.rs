// A simple implementation of SymmetricKeyContext
use crate::{
    chip::{
        crypto::{
            crypto_pal::{
                Aes128KeyHandle,
                Symmetric128BitsKeyByteArray,
                SymmetricKeyContext,
            },
            session_keystore::SessionKeystore,
        },
    },
    ChipErrorResult, chip_ok, ChipError, 
    chip_core_error,
    chip_no_error,
    chip_sdk_error,
    chip_error_internal,
    chip_error_invalid_argument,
    verify_or_return_error,
    verify_or_return_value,
};
use aes::Aes128;
use ccm::{
    consts::{U8, U13},
    Ccm,
};

use core::ptr::NonNull;

type Aes128Ccm = Ccm<Aes128, U8, U13>;

pub struct RawSymmetricKeyContext {
    m_hash: u16,
    m_encryption_key: Aes128KeyHandle,
    m_privacy_key: Aes128KeyHandle,
    m_keystore: Option<NonNull<dyn SessionKeystore>>,
}

impl RawSymmetricKeyContext {
    pub const fn new() -> Self {
        Self {
            m_hash: 0,
            m_encryption_key: Aes128KeyHandle::new(),
            m_privacy_key: Aes128KeyHandle::new(),
            m_keystore: None,
        }
    }

    pub fn init(&mut self, encryption_key: &Symmetric128BitsKeyByteArray, privacy_key: &Symmetric128BitsKeyByteArray, hash: u16, keystore: *mut dyn SessionKeystore) -> ChipErrorResult {
        verify_or_return_error!(!keystore.is_null(), Err(chip_error_invalid_argument!()));

        self.release_keys();

        self.m_hash = hash;

        unsafe {
            self.m_keystore = Some(NonNull::new_unchecked(keystore));
            if let Some(store) = keystore.as_mut() {
                self.m_encryption_key = store.create_key_aes128(encryption_key)?;
                self.m_privacy_key = store.create_key_aes128(privacy_key)?;
            } else {
                return Err(chip_error_internal!());
            }
        }

        chip_ok!()
    }

    pub fn release_keys(&mut self) {
        self.m_encryption_key = Aes128KeyHandle::new();
        self.m_privacy_key = Aes128KeyHandle::new();
    }
}

impl SymmetricKeyContext for RawSymmetricKeyContext {
    fn get_key_hash(&mut self) -> u16 {
        self.m_hash
    }

    fn message_encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8], mic: &mut [u8], ciphertext: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn message_decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], mic: &[u8], plaintext: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn privacy_encrypt(&self, input: &[u8], nonce: &[u8], output: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn privacy_decrypt(&self, input: &[u8], nonce: &[u8], output: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn release(&mut self) {
        self.release_keys();
    }
}
