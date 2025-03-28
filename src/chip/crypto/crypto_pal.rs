use crate::chip_static_assert;
use crate::chip::chip_lib::core::chip_config::{CHIP_CONFIG_SHA256_CONTEXT_SIZE};

use crate::ChipErrorResult;
use crate::chip_ok;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_invalid_argument;

use core::slice;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

pub const K_MAX_X509_CERTIFICATE_LENGTH: usize = 600;

pub const K_P256_FE_LENGTH: usize = 32;
pub const K_P256_ECDSA_SIGNATURE_LENGTH_RAW: usize = 2 * K_P256_FE_LENGTH;
pub const K_P256_POINT_LENGTH: usize = 2 * K_P256_FE_LENGTH + 1;
pub const K_SHA256_HASH_LENGTH: usize = 32;
pub const K_SHA1_HASH_LENGTH: usize = 20;
pub const K_SUBJECT_KEY_IDENTIFIER_LENGTH: usize = K_SHA1_HASH_LENGTH;
pub const K_AUTHORITY_KEY_IDENTIFIER_LENGTH: usize = K_SHA1_HASH_LENGTH;
pub const K_MAX_CERTIFICATE_SERIAL_NUMBER_LENGTH: usize = 20;
pub const K_MAX_CERTIFICATE_DISTINGUISHED_NAME_LENGTH: usize = 200;
pub const K_MAX_CRL_DISTRIBUTION_POINT_URL_LENGTH: usize = 100;

pub const K_VALID_CDP_URI_HTTP_PREFIX: &str = "http://";
pub const K_VALID_CDP_URI_HTTPS_PREFIX: &str = "https://";

pub const CHIP_CRYPTO_GROUP_SIZE_BYTES: usize = K_P256_FE_LENGTH;
pub const CHIP_CRYPTO_PUBLIC_KEY_SIZE_BYTES: usize = K_P256_POINT_LENGTH;

pub const CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
pub const CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;

pub const K_MAX_ECDH_SECRET_LENGTH: usize = K_P256_FE_LENGTH;
pub const K_MAX_ECDSA_SIGNATURE_LENGTH: usize = K_P256_ECDSA_SIGNATURE_LENGTH_RAW;
pub const K_MAX_FE_LENGTH: usize = K_P256_FE_LENGTH;
pub const K_MAX_POINT_LENGTH: usize = K_P256_POINT_LENGTH;
pub const K_MAX_HASH_LENGTH: usize = K_SHA256_HASH_LENGTH;

pub const K_MIN_CSR_BUFFER_SIZE: usize = 255;

pub const CHIP_CRYPTO_HASH_LEN_BYTES: usize = K_SHA256_HASH_LENGTH;

pub const K_SPAKE2P_MIN_PBKDF_SALT_LENGTH: usize = 16;
pub const K_SPAKE2P_MAX_PBKDF_SALT_LENGTH: usize = 32;
pub const K_SPAKE2P_MIN_PBKDF_ITERATIONS: u32 = 1000;
pub const K_SPAKE2P_MAX_PBKDF_ITERATIONS: u32 = 100000;

pub const K_P256_PRIVATE_KEY_LENGTH: usize = CHIP_CRYPTO_GROUP_SIZE_BYTES;
pub const K_P256_PUBLIC_KEY_LENGTH: usize = CHIP_CRYPTO_PUBLIC_KEY_SIZE_BYTES;

pub const K_AES_CCM128_KEY_LENGTH: usize = 128 / 8;
pub const K_AES_CCM128_BLOCK_LENGTH: usize = K_AES_CCM128_KEY_LENGTH;
pub const K_AES_CCM128_NONCE_LENGTH: usize = 13;
pub const K_AES_CCM128_TAG_LENGTH: usize = 16;
pub const K_HMAC_CCM128_KEY_LENGTH: usize = 128 / 8;

pub const CHIP_CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = K_AES_CCM128_NONCE_LENGTH;

/* These sizes are hardcoded here to remove header dependency on underlying crypto library
 * in a public interface file. The validity of these sizes is verified by static_assert in
 * the implementation files.
 */
pub const K_MAX_SPAKE2P_CONTEXT_SIZE: usize = 1024;
pub const K_MAX_P256_KEYPAIR_CONTEXT_SIZE: usize = 512;

pub const K_EMIT_DER_INTEGER_WITHOUT_TAG_OVERHEAD: usize = 1;
pub const K_EMIT_DER_INTEGER_OVERHEAD: usize = 3;

pub const K_MAX_HASH_SHA256_CONTEXT_SIZE: usize = CHIP_CONFIG_SHA256_CONTEXT_SIZE;

pub const K_SPAKE2P_WS_LENGTH: usize = K_P256_FE_LENGTH + 8;
pub const K_SPAKE2P_VERIFIER_SERIALIZED_LENGTH: usize = K_P256_FE_LENGTH + K_P256_POINT_LENGTH;

pub const K_VID_PREFIX_FOR_CN_ENCODING: &str = "Mvid:";
pub const K_PID_PREFIX_FOR_CN_ENCODING: &str = "Mpid:";
pub const K_VID_AND_PID_HEX_LENGTH: usize = core::mem::size_of::<u16>() * 2;
pub const K_MAX_COMMON_NAME_ATTR_LENGTH: usize = 64;


/*
 * Overhead to encode a raw ECDSA signature in X9.62 format in ASN.1 DER
 *
 * Ecdsa-Sig-Value ::= SEQUENCE {
 *     r       INTEGER,
 *     s       INTEGER
 * }
 *
 * --> SEQUENCE, universal constructed tag (0x30), length over 2 bytes, up to 255 (to support future larger sizes up to 512 bits)
 *   -> SEQ_OVERHEAD = 3 bytes
 * --> INTEGER, universal primitive tag (0x02), length over 1 byte, one extra byte worst case
 *     over max for 0x00 when MSB is set.
 *       -> INT_OVERHEAD = 3 bytes
 *
 * There is 1 sequence of 2 integers. Overhead is SEQ_OVERHEAD + (2 * INT_OVERHEAD) = 3 + (2 * 3) = 9.
 */
pub const K_MAX_ECDSA_X9DOT62_ASN1_OVERHEAD: usize = 9;
pub const K_MAX_ECDSA_SIGNATURE_LENGTH_DER: usize = K_MAX_ECDSA_SIGNATURE_LENGTH + K_MAX_ECDSA_X9DOT62_ASN1_OVERHEAD;

chip_static_assert!(K_MAX_ECDH_SECRET_LENGTH >= K_P256_FE_LENGTH, "ECDH shared secret is too short for crypto suite");
chip_static_assert!(K_MAX_ECDSA_SIGNATURE_LENGTH >= K_P256_ECDSA_SIGNATURE_LENGTH_RAW,
              "ECDSA signature buffer length is too short for crypto suite");

pub const K_COMPRESSED_FABRIC_IDENTIFIER_SIZE: usize = 8;

pub const SPAKE2P_M_P256: [u8; 65] = [
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];

pub const SPAKE2P_N_P256: [u8; 65] = [
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

#[repr(u8)]
pub enum ChipSpake2pState {
    Preinit = 0, // Before any initialization
    Init,        // First initialization
    Started,     // Prover & Verifier starts
    R1,          // Round one complete
    R2,          // Round two complete
    Kc,          // Key confirmation complete
}

#[repr(u8)]
pub enum ChipSpake2pRole {
    Verifier = 0,
    Prover,
}

#[repr(u8)]
pub enum SupportedECPKeyTypes {
    Ecp256r1 = 0,
}

#[repr(u8)]
pub enum ECPKeyTaget {
    Ecdh  = 0,
    Ecdsa = 1,
}

pub fn clear_secret_data(buf: &mut [u8])
{}

pub fn clear_secret_data_with_raw(buf: * mut u8, len: usize) {
    unsafe {
        clear_secret_data(slice::from_raw_parts_mut(buf, len));
    }
}

pub fn is_buffer_content_equal_constant_time(a: &[u8], b: &[u8], n: usize) -> bool {
    false
}

pub fn is_buffer_content_equal_constant_time_with_raw(a: * const u8, b: * const u8, n: usize) -> bool {
    unsafe {
        return is_buffer_content_equal_constant_time(
            slice::from_raw_parts(a, n),
            slice::from_raw_parts(b, n),
            n);
    }
}

pub trait ECPKey {
    type Sig;

    fn the_type(&self) -> SupportedECPKeyTypes;
    fn length(&self) -> usize;
    fn is_uncompressed(&self) -> bool;
    //fn raw(&mut self) -> * mut u8;
    fn const_bytes_raw(&self) -> * const u8;
    fn bytes_raw(&mut self) -> * mut u8;
    fn const_bytes(&self) -> &[u8];
    fn bytes(&mut self) -> &mut [u8];

    fn matches(&self, other: &Self) -> bool {
        return (self.length() == other.length()) && (is_buffer_content_equal_constant_time_with_raw(
                self.const_bytes_raw(), other.const_bytes_raw(), self.length()));
    }

    fn ecdsa_validate_msg_signature(&self, msg: &[u8], signature: &Self::Sig) -> ChipErrorResult;
    fn ecdsa_validate_msg_signature_with_raw(&self, msg: * const u8, msg_length: usize, signature: &Self::Sig) -> ChipErrorResult {
        unsafe {
            return self.ecdsa_validate_msg_signature(slice::from_raw_parts(msg, msg_length), signature);
        }
    }

    fn ecdsa_validate_hash_signature(&self, hash: &[u8], signature: &Self::Sig) -> ChipErrorResult;
    fn ecdsa_validate_hash_signature_with_raw(&self,hash: * const u8, hash_length: usize, signature: &Self::Sig) -> ChipErrorResult {
        unsafe {
            return self.ecdsa_validate_msg_signature(slice::from_raw_parts(hash, hash_length), signature);
        }
    }
}

pub struct SensitiveDataBuffer<const KCAPACITY: usize> {
    m_bytes: [u8; KCAPACITY],
    m_length: usize,
}

impl<const KCAPACITY: usize> Default for SensitiveDataBuffer<KCAPACITY> {
    fn default() -> Self {
        return SensitiveDataBuffer::<KCAPACITY>::const_default();
    }
}

impl<const KCAPACITY: usize> SensitiveDataBuffer<KCAPACITY> {
    pub const fn const_default() -> Self {
        Self {
            m_bytes: [0; KCAPACITY],
            m_length: 0,
        }
    }

    pub fn length(&self) -> usize {
        return self.m_length;
    }

    pub fn set_length(&mut self, length: usize) -> ChipErrorResult {
        verify_or_return_error!(length <= KCAPACITY, Err(chip_error_invalid_argument!()));
        self.m_length = length;
        chip_ok!()
    }

    pub fn bytes(&mut self) -> &mut [u8] {
        return &mut self.m_bytes[..];
    }

    pub fn bytes_raw(&mut self) -> * mut u8 {
        return self.m_bytes[..].as_mut_ptr();
    }

    pub fn const_bytes(&self) -> &[u8] {
        return &self.m_bytes[..];
    }

    pub fn const_bytes_raw(&self) -> * const u8 {
        return self.m_bytes.as_ptr();
    }

    pub const fn capacity(&self) -> usize { KCAPACITY }
}

impl<const KCAPACITY: usize> Drop for SensitiveDataBuffer<KCAPACITY> {
    fn drop(&mut self) {
        clear_secret_data(self.bytes());
    }
}

impl<const KCAPACITY: usize> Clone for SensitiveDataBuffer<KCAPACITY> {
    fn clone(&self) -> Self {
        let mut clone: Self = Self::default();

        clear_secret_data(clone.bytes());
        let _ = clone.set_length(self.length());
        clone.bytes().copy_from_slice(self.const_bytes());
        return clone;
    }
}

pub struct SensitiveDataFixedBuffer<const KCAPACITY: usize> {
    m_bytes: [u8; KCAPACITY],
}

impl<const KCAPACITY: usize> Default for SensitiveDataFixedBuffer<KCAPACITY> {
    fn default() -> Self {
        return SensitiveDataFixedBuffer::<KCAPACITY>::const_default();
    }
}

impl<const KCAPACITY: usize> SensitiveDataFixedBuffer<KCAPACITY> {
    pub const fn const_default() -> Self {
        Self {
            m_bytes: [0; KCAPACITY],
        }
    }

    pub const fn length(&self) -> usize {
        return KCAPACITY;
    }

    pub fn bytes(&mut self) -> &mut [u8] {
        return &mut self.m_bytes[..];
    }

    pub fn bytes_raw(&mut self) -> * mut u8 {
        return self.m_bytes[..].as_mut_ptr();
    }

    pub fn const_bytes(&self) -> &[u8] {
        return &self.m_bytes[..];
    }

    pub fn const_bytes_raw(&self) -> * const u8 {
        return self.m_bytes.as_ptr();
    }

    pub const fn capacity(&self) -> usize { KCAPACITY }
}

impl<const KCAPACITY: usize> Drop for SensitiveDataFixedBuffer<KCAPACITY> {
    fn drop(&mut self) {
        clear_secret_data(self.bytes());
    }
}

impl<const KCAPACITY: usize> Clone for SensitiveDataFixedBuffer<KCAPACITY> {
    fn clone(&self) -> Self {
        let mut clone: Self = Self::default();

        clear_secret_data(clone.bytes());
        clone.bytes().copy_from_slice(self.const_bytes());
        return clone;
    }
}

pub type P256EcdsaSignature = SensitiveDataBuffer<K_MAX_ECDSA_SIGNATURE_LENGTH>;
pub type P256EcdhDeriveSecret = SensitiveDataBuffer<K_MAX_ECDH_SECRET_LENGTH>;
pub type IdentityProtectionKey = SensitiveDataFixedBuffer<CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES>;
pub type IdentityProtectionKeySpan = [u8; CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
pub type AttestationChallenge = SensitiveDataFixedBuffer<CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES>;

#[derive(Clone)]
pub struct P256PublicKey {
    m_bytes: [u8; K_P256_PUBLIC_KEY_LENGTH],
}

impl Default for P256PublicKey {
    fn default() -> Self {
        P256PublicKey::const_default()
    }
}

impl P256PublicKey {
    pub const fn const_default() -> Self {
        Self {
            m_bytes: [0; K_P256_PUBLIC_KEY_LENGTH],
        }
    }

    pub const fn const_default_with_raw_value(raw_value: &[u8; K_P256_PUBLIC_KEY_LENGTH]) -> Self {
        let mut key = Self::const_default();
        key.m_bytes.copy_from_slice(raw_value);
        key
    }
}

impl ECPKey for P256PublicKey {
    type Sig = P256EcdsaSignature;

    fn the_type(&self) -> SupportedECPKeyTypes {
        return SupportedECPKeyTypes::Ecp256r1;
    }

    fn length(&self) -> usize {
        return K_P256_PUBLIC_KEY_LENGTH;
    }

    fn is_uncompressed(&self) -> bool {
        const K_UNCOMPRESSED_POINT_MARKER: u8 = 0x04;

        // SEC1 definition of an uncompressed point is (0x04 || X || Y) where X and Y are
        // raw zero-padded big-endian large integers of the group size.
        return (self.length() == (K_P256_FE_LENGTH * 2 + 1)) && (self.const_bytes()[0] == K_UNCOMPRESSED_POINT_MARKER);
    }

    fn const_bytes_raw(&self) -> * const u8 {
        return self.m_bytes.as_ptr();
    }

    fn bytes_raw(&mut self) -> * mut u8 {
        return self.m_bytes.as_mut_ptr();
    }

    fn const_bytes(&self) -> &[u8] {
        return &self.m_bytes[..];
    }

    fn bytes(&mut self) -> &mut [u8] {
        return &mut self.m_bytes[..];
    }

    fn matches(&self, other: &Self) -> bool {
        return (self.length() == other.length()) && (is_buffer_content_equal_constant_time_with_raw(
                self.const_bytes_raw(), other.const_bytes_raw(), self.length()));
    }

    fn ecdsa_validate_msg_signature(&self, msg: &[u8], signature: &Self::Sig) -> ChipErrorResult {
        chip_ok!()
    }
    fn ecdsa_validate_msg_signature_with_raw(&self, msg: * const u8, msg_length: usize, signature: &Self::Sig) -> ChipErrorResult {
        unsafe {
            return self.ecdsa_validate_msg_signature(slice::from_raw_parts(msg, msg_length), signature);
        }
    }

    fn ecdsa_validate_hash_signature(&self, hash: &[u8], signature: &Self::Sig) -> ChipErrorResult {
        chip_ok!()
    }
    fn ecdsa_validate_hash_signature_with_raw(&self,hash: * const u8, hash_length: usize, signature: &Self::Sig) -> ChipErrorResult {
        unsafe {
            return self.ecdsa_validate_msg_signature(slice::from_raw_parts(hash, hash_length), signature);
        }
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod test_sensitive_data_buffer {
      use super::*;
      use super::super::*;
      use std::*;

      #[test]
      fn new_one() {
          let buf: SensitiveDataBuffer<10> = SensitiveDataBuffer::<10>::default();
          assert_eq!(0, buf.length());
          assert_eq!(10, buf.capacity());
      }

      #[test]
      fn new_fix_one() {
          let buf: SensitiveDataFixedBuffer<10> = SensitiveDataFixedBuffer::<10>::default();
          assert_eq!(10, buf.length());
          assert_eq!(10, buf.capacity());
      }
  }
}
