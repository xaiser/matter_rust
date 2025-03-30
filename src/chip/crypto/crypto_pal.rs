use crate::chip_static_assert;
use crate::chip::chip_lib::core::chip_config::{CHIP_CONFIG_SHA256_CONTEXT_SIZE, CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE};
use crate::chip::chip_lib::support::buffer_reader as encoding;
use crate::chip::VendorId;

use crate::ChipErrorResult;
use crate::chip_ok;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_invalid_argument;

use core::slice;
use core::cell::UnsafeCell;

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

pub trait ECPKeypair<PK, Secret, Sig> {

    fn new_certificate_signing_request(&self, csr: &mut [u8]) -> ChipErrorResult;

    fn ecdsa_sign_msg(&self, msg: &[u8], out_signature: &mut Sig) ->  ChipErrorResult;

    fn ecdh_derive_secret(&self, remote_public_key: &PK, out_secret: &mut Secret) ->  ChipErrorResult;

    fn pubkey(&self) -> &PK;
}

#[repr(align(8))]
pub struct P256KeypairContext {
    m_bytes: [u8; K_MAX_P256_KEYPAIR_CONTEXT_SIZE],
}

impl P256KeypairContext {
    pub const fn const_default() -> Self {
        Self {
            m_bytes: [0; K_MAX_P256_KEYPAIR_CONTEXT_SIZE],
        }
    }
}

impl Default for P256KeypairContext {
    fn default() -> Self {
        P256KeypairContext::const_default()
    }
}



pub type P256SerializedKeypair = SensitiveDataBuffer<{K_P256_PUBLIC_KEY_LENGTH + K_P256_PRIVATE_KEY_LENGTH}>;

pub trait P256KeypairBase: ECPKeypair<P256PublicKey, P256EcdhDeriveSecret, P256EcdsaSignature>
{
    fn initialize(key_target: ECPKeyTaget) -> ChipErrorResult;

    fn Serialize(output: &mut P256SerializedKeypair) -> ChipErrorResult;

    fn deserialize(input: &mut P256SerializedKeypair) -> ChipErrorResult;
}

#[derive(Default)]
pub struct P256Keypair
{
    m_public_key: P256PublicKey,
    m_keypair: UnsafeCell<P256KeypairContext>,
    m_initialized: bool,
}

impl P256Keypair {
    pub const fn const_default() -> Self {
        Self {
            m_public_key: P256PublicKey::const_default(),
            m_keypair: UnsafeCell::new(P256KeypairContext::const_default()),
            m_initialized: false,
        }
    }

    pub fn clear() {
    }
}

impl ECPKeypair<P256PublicKey, P256EcdhDeriveSecret, P256EcdsaSignature> for P256Keypair {
    fn new_certificate_signing_request(&self, csr: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    fn ecdsa_sign_msg(&self, msg: &[u8], out_signature: &mut P256EcdsaSignature) ->  ChipErrorResult {
        chip_ok!()
    }

    fn ecdh_derive_secret(&self, remote_public_key: &P256PublicKey, out_secret: &mut P256EcdhDeriveSecret) ->  ChipErrorResult {
        chip_ok!()
    }

    fn pubkey(&self) -> &P256PublicKey {
        return &self.m_public_key;
    }
}

impl P256KeypairBase for P256Keypair {
    fn initialize(key_target: ECPKeyTaget) -> ChipErrorResult {
        chip_ok!()
    }

    fn Serialize(output: &mut P256SerializedKeypair) -> ChipErrorResult {
        chip_ok!()
    }

    fn deserialize(input: &mut P256SerializedKeypair) -> ChipErrorResult {
        chip_ok!()
    }
}

#[derive(Default)]
struct SymmetricKeyHandle<const CONTEXT_SIZE: usize> {
    m_context: OpaqueContext<CONTEXT_SIZE>,
}

impl<const CONTEXT_SIZE: usize> SymmetricKeyHandle<CONTEXT_SIZE> {
    pub fn as_ref<T>(&self) -> &T {
        unsafe { &*(self.m_context.m_opaque.as_ptr() as *const T) }
    }

    pub fn as_mut<T>(&mut self) -> &mut T {
        unsafe { &mut *(self.m_context.m_opaque.as_mut_ptr() as *mut T) }
    }
}

impl<const CONTEXT_SIZE: usize> Drop for SymmetricKeyHandle<CONTEXT_SIZE> {
    fn drop(&mut self) {
        clear_secret_data(&mut self.m_context.m_opaque[..]);
    }
}

#[repr(align(8))]
struct OpaqueContext<const CONTEXT_SIZE: usize> {
    pub m_opaque: [u8; CONTEXT_SIZE],
}

impl<const CONTEXT_SIZE: usize>  Default for OpaqueContext<CONTEXT_SIZE> {
    fn default() -> Self {
        Self {
            m_opaque: [0; CONTEXT_SIZE],
        }
    }
}

pub type Symmetric128BitsKeyByteArray = [u8; CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];

pub type Symmetric128BitsKeyHandle = SymmetricKeyHandle<CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES>;

pub type Aes128KeyHandle = Symmetric128BitsKeyHandle;

pub type Hmac128KeyHandle = Symmetric128BitsKeyHandle;

pub type HkdfKeyHandle = SymmetricKeyHandle<CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE>;

pub fn ecdsa_raw_signature_to_asn1(fe_legnth_bytes: usize, raw_sig: &[u8], out_asn1_sig: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn ecdsa_asn1_signature_to_raw(fe_length_bytes: usize, asn1_sig: &[u8], out_raw_sig: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn read_der_length(reader: &encoding::little_endian::Reader, length: &mut usize) -> ChipErrorResult {
    chip_ok!()
}

pub fn convert_integer_raw_to_der(raw_integer: &[u8], out_der_integer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn convert_integer_raw_to_der_without_tag(raw_integer: &[u8], out_der_integer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn aes_ccm_encrypt(plaintext: &[u8], aad: &[u8], key: &Aes128KeyHandle, nonce: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn aes_ccm_decrypt(ciphertext: &[u8], aad: &[u8], tag: &[u8], key: &Aes128KeyHandle, nonce: &[u8], plaintext: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn aes_ctr_crypt(input: &[u8], key: &Aes128KeyHandle, nonce: &[u8], output: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn generate_certificate_signing_request(keypair: &P256Keypair, csr: &mut [u8]) -> ChipErrorResult{
    chip_ok!()
}

pub fn verify_certificate_signing_request_format(csr: &[u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn verify_certificate_signing_request(csr: &[u8], pubkey: &mut P256PublicKey) -> ChipErrorResult {
    chip_ok!()
}

pub fn hash_sha256(data: &[u8], out_buffer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn hash_sha1(data: &[u8], out_buffer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

#[cfg(feature="chip_config_sha256_context_align_8")]
#[repr(align(8))]
pub struct HashSHA256OpaqueContext {
    pub m_opaque: [u8; K_MAX_HASH_SHA256_CONTEXT_SIZE],
}

impl HashSHA256OpaqueContext {
    pub const fn const_default() -> Self {
        Self {
            m_opaque: [0; K_MAX_HASH_SHA256_CONTEXT_SIZE],
        }
    }
}

impl Default for HashSHA256OpaqueContext {
    fn default() -> Self {
        HashSHA256OpaqueContext::const_default()
    }
}

#[derive(Default)]
pub struct HashSHA256Stream {
    m_context: HashSHA256OpaqueContext,
}

impl HashSHA256Stream {
    pub const fn const_default() -> Self {
        Self {
            m_context: HashSHA256OpaqueContext::const_default(),
        }
    }

    pub fn begin(&mut self) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn add_data(&mut self, data: &[u8]) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn get_digest(&mut self, out_buffer: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn finish(&mut self, out_buffer: &mut [u8]) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn clear(&mut self) {}

    fn is_initialized(&self) -> bool {
        false
    }
}

pub fn drbg_get_bytes(out_buffer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub type EntropySource = fn(data: * mut u8, output: &mut [u8], olen: &mut usize) -> i32;

pub fn add_entropy_source(fn_source: EntropySource, p_source: * mut u8, threashold: usize) -> ChipErrorResult {
    chip_ok!()
}

pub struct SessionKeystore;

pub trait Spake2p {
    fn init(&mut self, context: &[u8]) -> ChipErrorResult;

    fn clear(&mut self);

    fn begin_verifier(&mut self, my_identity: &[u8], peer_identity: &[u8], w0in: &[u8], lin: &[u8]) -> ChipErrorResult;

    fn begin_prover(&mut self, my_identity: &[u8], peer_identity: &[u8], w0sin: &[u8], s1sin: &[u8]) -> ChipErrorResult;

    fn compute_round_one(&mut self, pab: &[u8], out: &mut [u8]) -> ChipErrorResult;

    fn compute_round_two(&mut self, input: &[u8], out: &mut[u8]) -> ChipErrorResult;

    fn key_cofirm(&mut self, input: &[u8]) -> ChipErrorResult;

    fn get_keys(&self, keystore: &mut SessionKeystore, key: &mut HkdfKeyHandle) -> ChipErrorResult;

    fn internal_hash(&mut self, input: &[u8]) -> ChipErrorResult;

    fn write_mn(&mut self) -> ChipErrorResult;

    fn generate_keys(&mut self) -> ChipErrorResult;

    fn fe_load(&mut self, input: &[u8], fe: * mut ()) -> ChipErrorResult;

    fn fe_write(&mut self, fe: * mut (), out: &mut [u8]) -> ChipErrorResult;

    fn fe_generate(&mut self, fe: * mut ()) -> ChipErrorResult;

    fn fe_mul(&mut self, fer: * mut (), fe1: * const (), fe2: * const ()) -> ChipErrorResult;

    fn point_load(&mut self, input: &[u8], r: * mut ()) -> ChipErrorResult;

    fn point_write(&mut self, r: * const (), out: &mut [u8]) -> ChipErrorResult;

    fn point_mut(&mut self, r: * mut (), p1: * const (), p2: * const ()) -> ChipErrorResult;

    fn point_add_mut(&mut self, r: * mut (), p1: * const (), fe1: * const (), p2: * const (), fe2: * const ()) -> ChipErrorResult;

    fn point_invert(&mut self, r: * mut ()) -> ChipErrorResult;

    fn point_cofactor_mut(&mut self, r: * mut ()) -> ChipErrorResult;

    fn point_is_valid(&self, r: * mut ()) -> ChipErrorResult;

    fn compute_w0(&mut self, w0out: &mut [u8], w0sin: &[u8]) -> ChipErrorResult;

    fn compute_l(&mut self, lout: &mut [u8], w1sin: &[u8]) -> ChipErrorResult;
}

pub struct Spake2pP256Sha256HKDFHMAX {
    pub m: * mut (),
    pub n: * mut (),
    pub g: * const (),
    pub x: * mut (),
    pub y: * mut (),
    pub l: * mut (),
    pub z: * mut (),
    pub v: * mut (),
    pub w0: * mut (),
    pub w1: * mut (),
    pub xy: * mut (),
    pub order: * mut (),
    pub tempbn: * mut (),

    fe_size: usize,
    hash_size: usize,
    point_size: usize,
    k_cab: [u8; K_MAX_HASH_LENGTH],
    k_ae: [u8; K_MAX_HASH_LENGTH],
    k_ca: * mut u8,
    k_cb: * mut u8,
    k_a: * mut u8,
    k_e: * mut u8,

    m_sha256_hash_ctx: HashSHA256Stream,
    m_spake2p_context: Spake2pOpaqueContext,
}

pub type Spake2pVerifierSerialized = [u8; K_SPAKE2P_VERIFIER_SERIALIZED_LENGTH];

pub fn generate_compressed_fabricId(root_public_key: &P256PublicKey, fabrid_id: u64, out_compressed_fabrid_id: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn generate_compressed_fabricId_u64(root_public_key: &P256PublicKey, fabrid_id: u64, out_compressed_fabrid_id: &mut u64) -> ChipErrorResult {
    chip_ok!()
}

pub enum CertificateChainValidationResult {
    KSuccess = 0,

    KRootFormatInvalid   = 100,
    KRootArgumentInvalid = 101,

    KICAFormatInvalid   = 200,
    KICAArgumentInvalid = 201,

    KLeafFormatInvalid   = 300,
    KLeafArgumentInvalid = 301,

    KChainInvalid = 400,

    KNoMemory = 500,

    KInternalFrameworkError = 600,
}

pub fn validate_certificate_chain(root_certificate: &[u8], ca_certificate: &[u8], leaf_certificate: &[u8], result: &mut CertificateChainValidationResult) -> ChipErrorResult {
    chip_ok!()
}

pub enum AttestationCertType {
    KPAA = 0,
    KPAI = 1,
    KDAC = 2,
}

pub fn verify_attestaction_certification_format(cert: &[u8], cert_type: AttestationCertType) -> ChipErrorResult {
    chip_ok!()
}

pub fn is_certificate_valid_at_issuance(candiate_certificate: &[u8], issuer_certificate: &[u8]) -> ChipErrorResult {
    chip_ok!()
}

#[repr(align(8))]
pub struct Spake2pOpaqueContext {
    pub m_opaque: [u8; K_MAX_SPAKE2P_CONTEXT_SIZE],
}

fn is_certificate_valid_at_current_time(certificate: &[u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_pubkey_from_x509_cert(certificate: &[u8], pubkey: &mut P256PublicKey) -> ChipErrorResult {
    chip_ok!()
}

fn extract_skid_from_x509_cert(certificate: &[u8], skid: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_akid_from_x509_cert(certificate: &[u8], akid: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_crl_distribution_point_uri_from_x509_cert(certificate: &[u8], cdpurl: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_cdp_extension_crl_issuer_from_x509_cert(certificate: &[u8], crl_issuer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_serial_number_from_x509_cert(certificate: &[u8], serial_number: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_subject_from_x509_cert(certificate: &[u8], subject: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn extract_issuer_from_x509_cert(certificate: &[u8], issuer: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

fn replace_cert_if_resigned_cert_found(reference_certificate: &[u8], candiate_certifiace: &[&[u8]], out_certificate: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub enum DNAttrType {
    KUnspecified = 0,
    KCommonName  = 1,
    KMatterVID   = 2,
    KMatterPID   = 3,
}

pub struct AttestationCertVidPid {
    pub m_vendor_id: Option<VendorId>,
    pub m_production_id: Option<u16>,
}

impl AttestationCertVidPid {
    pub fn is_initialized(&self) -> bool {
        return self.m_vendor_id.is_some() || self.m_production_id.is_some();
    }
}

pub fn extract_vid_pid_from_attribute_setting(arrt_type: DNAttrType, attr: &[u8], vid_pid_from_matter_attr: &mut AttestationCertVidPid, vid_pid_from_cn_attr: &mut AttestationCertVidPid) -> ChipErrorResult {
    chip_ok!()
}

pub fn extract_vid_pid_from_x509_cert(x509_cert: &[u8], vid_pid: &mut AttestationCertVidPid) -> ChipErrorResult {
    chip_ok!()
}

pub struct GroupOperationalCredentials {
    pub m_start_time: u64,
    pub m_hash: u16,
    pub m_encryption_key: [u8; CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub m_private_key: [u8; CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
}

pub fn derive_group_operation_key(epoch_key: &[u8], compressed_fabric_id: &[u8], out_key: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn derive_gropu_session(operational_key: &[u8], session_id: &mut u16) -> ChipErrorResult {
    chip_ok!()
}

pub fn derive_group_private(epoch_key: &[u8], out_key: &mut [u8]) -> ChipErrorResult {
    chip_ok!()
}

pub fn derive_group_operational_credentials(epoch_key: &[u8], compressed_fabrc_id: &[u8], operational_credentials: &mut GroupOperationalCredentials) -> ChipErrorResult {
    chip_ok!()
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
