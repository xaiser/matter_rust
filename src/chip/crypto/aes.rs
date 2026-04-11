//type Aes128Ccm = Ccm<Aes128, U8, U13>;

mod key_128 {
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
    use typenum::Unsigned;
    use aes::Aes128;

    use aead::{
        KeyInit,
        AeadInPlace,
        AeadCore,
    };

    use core::ptr::NonNull;
    use core::marker::PhantomData;

    pub mod mode_ccm {
        use super::*;
        use ccm::{
            Nonce,
            Tag,
            KeyInit,
            Ccm,
            AeadInPlace,
            AeadCore,
        };

        pub fn create_aes128_ccm<Ccm: KeyInit>(key: &Aes128KeyHandle) -> Result<Ccm, ()> {
                Ccm::new_from_slice(key.as_ref::<Symmetric128BitsKeyByteArray>()).map_err(|_| ())
        }

        pub fn encrypt<C: KeyInit + AeadInPlace + AeadCore>(plaintext: &[u8], aad: &[u8], key: &Aes128KeyHandle, nonce: &[u8], mic: &mut [u8], ciphertext: &mut [u8]) -> ChipErrorResult {
            verify_or_return_error!(<C as AeadCore>::NonceSize::to_usize() == nonce.len(), Err(chip_error_invalid_argument!()));

            let ccm = create_aes128_ccm::<C>(key).map_err(|_| chip_error_invalid_argument!())?;
            let input_size = plaintext.len();
            let tag;
            
            if let Some(text) = ciphertext.get_mut(..input_size) {
                text.copy_from_slice(plaintext);
                tag = ccm.encrypt_in_place_detached(&Nonce::<<C as AeadCore>::NonceSize>::from_slice(nonce), aad, text).map_err(|_| {
                    text.fill(0);
                    chip_error_internal!()
                })?;
            } else {
                return Err(chip_error_invalid_argument!());
            }

            let tag_size = tag.len();

            if let Some(in_mic) = mic.get_mut(..tag_size) {
                in_mic.copy_from_slice(tag.as_slice());
            } else {
                return Err(chip_error_internal!());
            }

            chip_ok!()
        }
        
        pub fn decrypt<C: KeyInit + AeadInPlace + AeadCore>(ciphertext: &[u8], aad: &[u8], tag: &[u8], key: &Aes128KeyHandle, nonce: &[u8], plaintext: &mut [u8]) -> ChipErrorResult {
            verify_or_return_error!(<C as AeadCore>::NonceSize::to_usize() == nonce.len(), Err(chip_error_invalid_argument!()));
            verify_or_return_error!(<C as AeadCore>::TagSize::to_usize() == tag.len(), Err(chip_error_invalid_argument!()));

            let ccm = create_aes128_ccm::<C>(key).map_err(|_| chip_error_invalid_argument!())?;
            let cipher_text_size = ciphertext.len();

            if let Some(text) = plaintext.get_mut(..cipher_text_size) {
                text.copy_from_slice(ciphertext);
                ccm.decrypt_in_place_detached(&Nonce::<<C as AeadCore>::NonceSize>::from_slice(nonce), aad, text, &Tag::<<C as AeadCore>::TagSize>::from_slice(tag)).map_err(|_| {
                    text.fill(0);
                    chip_error_internal!()
                })?;
            } else {
                return Err(chip_error_invalid_argument!());
            }

            chip_ok!()
        }
    } // end of mod ccm

    pub mod mode_ctr {
        use super::*;
        use aes::{
            cipher::{KeyIvInit, StreamCipher, IvSizeUser},
            Aes128,
        };
        use ctr;

        pub fn create_aes128<C: KeyIvInit>(key: &Aes128KeyHandle, iv: &[u8]) -> Result<C, ()> {
            C::new_from_slices(key.as_ref::<Symmetric128BitsKeyByteArray>(), iv).map_err(|_| ())
        }

        pub fn encrypt<Ctr: KeyIvInit + StreamCipher>(input: &[u8], key: &Aes128KeyHandle, nonce: &[u8], output: &mut [u8]) -> ChipErrorResult {
            let mut ctr = create_aes128::<Ctr>(key, nonce).map_err(|_| chip_error_invalid_argument!())?;
            let input_size = input.len();

            ctr.apply_keystream_b2b(input, output).map_err(|_| chip_error_internal!())?;

            chip_ok!()
        }
    } // end of mod ctr

    pub struct SymmetricKeyContext<C: KeyInit + AeadInPlace + AeadCore> {
        m_hash: u16,
        m_encryption_key: Aes128KeyHandle,
        m_privacy_key: Aes128KeyHandle,
        m_keystore: Option<NonNull<dyn SessionKeystore>>,
        m_phantom: PhantomData<C>,
    }

    impl<C: KeyInit + AeadInPlace + AeadCore> SymmetricKeyContext<C> {
        pub const fn new() -> Self {
            Self {
                m_hash: 0,
                m_encryption_key: Aes128KeyHandle::new(),
                m_privacy_key: Aes128KeyHandle::new(),
                m_keystore: None,
                m_phantom: PhantomData,
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

    impl<C: KeyInit + AeadInPlace + AeadCore> crypto_pal::SymmetricKeyContext for SymmetricKeyContext<C> {
        fn get_key_hash(&mut self) -> u16 {
            self.m_hash
        }

        fn message_encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8], mic: &mut [u8], ciphertext: &mut [u8]) -> ChipErrorResult {
            return mode_ccm::encrypt::<C>(plaintext, aad, &self.m_encryption_key, aad, mic, ciphertext);
        }

        fn message_decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], mic: &[u8], plaintext: &mut [u8]) -> ChipErrorResult {
            return mode_ccm::decrypt::<C>(ciphertext, aad, mic, &self.m_encryption_key, nonce, plaintext);
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
        //simple_rand::SimpleRng,
    };
    use aes::Aes128;
    use ccm::{
        consts::{U8, U10, U13},
        Ccm,
        Nonce,
        Tag,
        AeadInPlace,
        KeyInit,
    };
    mod test_ccm {
        use super::*;
        use super::super::*;

        type Aes128Ccm = Ccm<Aes128, U8, U13>;

        #[test]
        fn encrypt() {
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
    } // end of test_ccm

    mod test_ctr {
        use super::*;
        use super::super::*;
        use crate::chip::crypto::crypto_pal::Aes128KeyHandle;

        type Aes128Ctr = ctr::Ctr32LE<Aes128>;

        #[test]
        fn encrypt() {
            let key = Aes128KeyHandle::new();
            let iv = [1u8; 16];
            let input = [1u8; 16];
            let mut output = [0u8; 16];

            assert!(key_128::mode_ctr::encrypt::<Aes128Ctr>(&input[..], &key, &iv[..], &mut output).is_ok());
        }

        #[test]
        fn decrypt() {
            let key = Aes128KeyHandle::new();
            let iv = [1u8; 16];
            let input = [1u8; 16];
            let mut output = [0u8; 16];
            let mut output_2 = [0u8; 16];

            assert!(key_128::mode_ctr::encrypt::<Aes128Ctr>(&input[..], &key, &iv[..], &mut output).is_ok());

            assert!(key_128::mode_ctr::encrypt::<Aes128Ctr>(&output, &key, &iv[..], &mut output_2).is_ok());

            assert_eq!(input, output_2);
        }
    } // end of test_ctr
} // end of tests
