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
use p256::{PublicKey, SecretKey, elliptic_curve};
use sha2::{Digest, Sha256};
use crate::chip::crypto::*;
use crate::chip::CryptoRng;

use crate::verify_or_return_error;
use crate::verify_or_return_value;


pub struct P256KeypairJust {
    m_key_context: P256KeypairContext,
    m_public_key: P256PublicKey,
    m_initialized: bool,
}

impl P256KeypairJust {
    pub fn const_default() -> Self {
        Self {
            m_key_context: P256KeypairContext::const_default(),
            m_public_key: P256PublicKey::const_default(),
            m_initialized: false,
        }
    }
    pub fn clear(&mut self) {
        self.m_key_context.m_bytes.fill(0);
        self.m_public_key = P256PublicKey::const_default();
        self.m_initialized = false;
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
        let pk = PublicKey::from_sec1_bytes(remote_public_key.const_bytes()).map_err(|_| {
            chip_error_internal!()
        })?;

        let secret_key = SecretKey::from_slice(&self.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH]).map_err(|_| {
            chip_error_internal!()
        })?;

        let shared_secret = elliptic_curve::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), pk.as_affine());

        out_secret
            .bytes()
            .copy_from_slice(shared_secret.raw_secret_bytes());
        out_secret.set_length(shared_secret.raw_secret_bytes().len())?;

        chip_ok!()
    }

    fn ecdsa_pubkey(&self) -> &P256PublicKey {
        &self.m_public_key
    }

    fn ecdh_pubkey(&self) -> &P256PublicKey {
        &self.m_public_key
    }
}

impl P256KeypairBase for P256KeypairJust {
    fn initialize(&mut self, _key_target: ECPKeyTarget) -> ChipErrorResult {
        self.clear();
        static mut TEST: u32 = 0;
        unsafe {
            TEST += 1;
            //let mut rand = CryptoRng::default();
            let mut rand = CryptoRng::default_with_seed(TEST);
            self.m_initialized = true;
            let secret_key = SecretKey::random(&mut rand);
            let public_key = secret_key.public_key();
            self.m_key_context.m_bytes[0..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(public_key.to_encoded_point(false).as_bytes());
            self.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH].copy_from_slice(secret_key.to_bytes().as_slice());
            self.m_public_key = P256PublicKey::default_with_raw_value(
                    public_key.to_encoded_point(false).as_bytes()
            );
        }
        chip_ok!()
    }

    fn serialize(&self, output: &mut P256SerializedKeypair) -> ChipErrorResult {
        let len = K_P256_PUBLIC_KEY_LENGTH + K_P256_PRIVATE_KEY_LENGTH;
        verify_or_return_error!(
            P256SerializedKeypair::capacity() >= len,
            Err(chip_error_internal!())
        );
        let serialized_keypair: &mut [u8] = output.bytes();

        serialized_keypair[0..len].copy_from_slice(&self.m_key_context.m_bytes[0..len]);

        output.set_length(len);

        chip_ok!()
    }

    fn deserialize(&mut self, input: &P256SerializedKeypair) -> ChipErrorResult {
        verify_or_return_error!(input.length() <= self.m_key_context.m_bytes.len(), Err(chip_error_invalid_argument!()));
        self.clear();
        self.m_key_context.m_bytes[..input.length()].copy_from_slice(input.const_bytes());
        self.m_initialized = true;

        chip_ok!()
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

    #[test]
    fn drive_secret() {
        let mut alice = P256KeypairJust::default();
        let mut rand = CryptoRng::default_with_seed(1);
        let secret_key = SecretKey::random(&mut rand);
        let public_key_alice = secret_key.public_key();
        &alice.m_key_context.m_bytes[0..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(public_key_alice.to_encoded_point(false).as_bytes());
        &alice.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH].copy_from_slice(secret_key.to_bytes().as_slice());


        let mut bob = P256KeypairJust::default();
        let mut rand = CryptoRng::default_with_seed(2);
        let secret_key = SecretKey::random(&mut rand);
        let public_key_bob = secret_key.public_key();
        &bob.m_key_context.m_bytes[0..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(public_key_bob.to_encoded_point(false).as_bytes());
        &bob.m_key_context.m_bytes[K_P256_PUBLIC_KEY_LENGTH..][..K_P256_PRIVATE_KEY_LENGTH].copy_from_slice(secret_key.to_bytes().as_slice());
        let pk_alice = P256PublicKey::default_with_raw_value(public_key_alice.to_encoded_point(false).as_bytes());
        let pk_bob = P256PublicKey::default_with_raw_value(public_key_bob.to_encoded_point(false).as_bytes());

        let mut s1: P256EcdhDeriveSecret = P256EcdhDeriveSecret::default();
        let mut s2: P256EcdhDeriveSecret = P256EcdhDeriveSecret::default();
        assert_eq!(true, alice.ecdh_derive_secret(&pk_bob, &mut s1).is_ok());
        assert_eq!(true, bob.ecdh_derive_secret(&pk_alice, &mut s2).is_ok());
        assert_eq!(s1.const_bytes(), s2.const_bytes());
    }

    #[test]
    fn serialize() {
        let mut keypair = P256KeypairJust::default();
        let _ = keypair.initialize(ECPKeyTarget::Ecdh);
        let mut bytes = P256SerializedKeypair::default();
        assert_eq!(true, keypair.serialize(&mut bytes).is_ok());
    }

    #[test]
    fn dserialize() {
        let mut keypair = P256KeypairJust::default();
        let _ = keypair.initialize(ECPKeyTarget::Ecdh);
        let mut bytes = P256SerializedKeypair::default();
        assert_eq!(true, keypair.serialize(&mut bytes).is_ok());
        let mut keypair1 = P256KeypairJust::default();
        assert_eq!(true, keypair1.deserialize(&bytes).is_ok());
        assert_eq!(keypair.m_key_context.m_bytes, keypair1.m_key_context.m_bytes);
    }
} // end of mod test
