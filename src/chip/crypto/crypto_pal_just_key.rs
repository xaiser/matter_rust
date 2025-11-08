use crate::chip_core_error;
use crate::chip_error_internal;
use crate::chip_error_invalid_argument;
use crate::chip_error_well_uninitialized;
use crate::chip_error_buffer_too_small;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use crate::chip::crypto::*;


pub struct P256KeypairJust {
    m_key_context: P256KeypairContext,
    m_public_key: P256PublicKey,
}

impl P256KeypairJust {
    pub fn const_default() -> Self {
        Self {
            m_key_context: P256KeypairContext::const_default(),
            m_public_key: P256PublicKey::const_default()
        }
    }
    pub fn clear(&mut self) {
        self.m_key_context.m_bytes.fill(0);
    }
}

impl Default for P256KeypairJust {
    fn default() -> Self {
        P256KeypairJust::const_default()
    }
}

impl ECPKeypair<P256PublicKey, P256EcdhDeriveSecret, P256EcdsaSignature> for P256KeypairJust {
    fn new_certificate_signing_request(&self, csr: &mut [u8]) -> Result<usize, ChipError> {
        Err(chip_error_internal!())
    }

    fn ecdsa_sign_msg(
        &self,
        msg: &[u8],
        out_signature: &mut P256EcdsaSignature,
    ) -> ChipErrorResult {
        let mut hasher = Sha256::new();
        hasher.update(&msg[..]);
        let hash_result = hasher.finalize();

        let secret_key = SecretKey::from_slice(&self.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH]).map_err(|_| {
            chip_error_internal!()
        })?;

        let sign_key = SigningKey::from(&secret_key);

        let sig: Signature = sign_key.sign(hash_result.as_slice());
        out_signature
            .bytes()
            .copy_from_slice(sig.to_bytes().as_slice());
        out_signature.set_length(sig.to_bytes().as_slice().len())?;
        chip_ok!()
    }

    fn ecdh_derive_secret(
        &self,
        remote_public_key: &P256PublicKey,
        out_secret: &mut P256EcdhDeriveSecret,
    ) -> ChipErrorResult {
        Err(chip_error_internal!())
    }

    fn ecdsa_pubkey(&self) -> &P256PublicKey {
        &self.m_public_key
    }

    fn ecdh_pubkey(&self) -> &P256PublicKey {
        &self.m_public_key
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;
    use crate::chip::CryptoRng;

    static mut TEST: u32 = 0;

    #[test]
    fn sign_message() {
        /*
        let mut kp = P256Keypair::default();
        let _ = kp.initialize(ECPKeyTarget::Ecdh);

        let mut sig: P256EcdsaSignature = P256EcdsaSignature::default();
        let message = b"plain text";
        assert_eq!(true, kp.ecdsa_sign_msg(&message[..], &mut sig).is_ok());
        */
        let seed: u32 = 1;
        let mut rand = CryptoRng::default_with_seed(seed);
        let secret_key = SecretKey::random(&mut rand);
        let public_key = secret_key.public_key();
        let mut keypair = P256KeypairJust::default();
        &keypair.m_key_context.m_bytes[0..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(public_key.to_encoded_point(false).as_bytes());
        &keypair.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH].copy_from_slice(secret_key.to_bytes().as_slice());

        let mut sig: P256EcdsaSignature = P256EcdsaSignature::default();
        let message = b"plain text";
        assert_eq!(true, keypair.ecdsa_sign_msg(&message[..], &mut sig).inspect_err(|e| println!("err {}", e)).is_ok());
        let veryify_key = VerifyingKey::from(&public_key);

        // generate hash for message
        let mut hasher = Sha256::new();
        hasher.update(&message[..]);
        let hash_result = hasher.finalize();

        // convert sig to correct type in P256
        let sig = Signature::from_slice(sig.const_bytes());
        assert_eq!(true, sig.is_ok());
        let sig = sig.unwrap();

        // verify
        assert_eq!(true, veryify_key.verify(hash_result.as_slice(), &sig).is_ok());
    }
} // end of mod test
