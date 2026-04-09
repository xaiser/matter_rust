//type Aes128Ccm = Ccm<Aes128, U8, U13>;

mod aes128_ccm {
    use crate::{
        chip::{
            crypto::{
                crypto_pal::{self, Symmetric128BitsKeyByteArray, Aes128KeyHandle},
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
        KeyInit,
        Ccm,
    };

    use core::ptr::NonNull;

    pub fn create_aes128_ccm<Ccm: KeyInit>(key: &Aes128KeyHandle) -> Result<Ccm, ()> {
            Ccm::new_from_slice(key.as_ref::<Symmetric128BitsKeyByteArray>()).map_err(|_| ())
    }

    pub struct SymmetricKeyContext {
        m_hash: u16,
        m_encryption_key: Aes128KeyHandle,
        m_privacy_key: Aes128KeyHandle,
        m_keystore: Option<NonNull<dyn SessionKeystore>>,
    }

    impl SymmetricKeyContext {
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

    impl crypto_pal::SymmetricKeyContext for SymmetricKeyContext {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::crypto::{
        simple_rand::SimpleRng,
    };
    use ccm::{
        consts::{U8, U10, U13},
        Ccm,
        Nonce,
        Tag,
        AeadInPlace,
        KeyInit,
    };

    #[test]
    fn encrypt() {
        let mut rng = SimpleRng::default_with_seed(12345);
        let key = [1u8; 16];
        let ccm = Aes128Ccm::new_from_slice(&key);
        assert!(ccm.is_ok());
        let ccm = ccm.unwrap();
        let nonce = Nonce::<U13>::from_slice(&[1u8; 13]);
        let aad = [1u8; 1];

        let input = [1u8; 16];
        let mut output = [1u8; 16];

        assert!(ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output).is_ok());
        let mut output = [1u8; 16];
        let r1 = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);
        let mut output = [1u8; 16];
        let r2 = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);

        assert_eq!(r1, r2);
    }

    #[test]
    fn decrypt() {
        let mut rng = SimpleRng::default_with_seed(12345);
        let key = [1u8; 16];
        let ccm = Aes128Ccm::new_from_slice(&key);
        assert!(ccm.is_ok());
        let ccm = ccm.unwrap();
        let nonce = Nonce::<U13>::from_slice(&[1u8; 13]);
        let aad = [1u8; 1];

        let input = [1u8; 16];
        let mut output = [1u8; 16];

        let tag = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);
        assert!(tag.is_ok());
        let tag = tag.unwrap();

        assert!(ccm.decrypt_in_place_detached(&nonce, &aad[..], &mut output, &tag).is_ok());

        assert_eq!(output, [1u8; 16]);
    }
} // end of tests
