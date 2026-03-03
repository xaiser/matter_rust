/*
 * @brief Interface for deriving session keys and managing their lifetime.
 *
 * The session keystore interface provides an abstraction that allows the application to store
 * session keys in a secure environment. It uses the concept of key handles that isolate the
 * application from the actual key material.
 *
 * @note Refactor has begun to refactor this API into two disctinct APIs : SymmetrycKeyStore & SessionKeyDerivation
 *       Work has not been completed so the  SessionKeystore has APIs that shouldn't go together for the time being
 *       The SessionKeystore APIs are split into two sections, one for each futur API.
 */
use crate::{
    ChipError,
    chip::{
        crypto::{
            Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
            P256EcdhDeriveSecret, AttestationChallenge,
        },
    },
};

#[derive(Default)]
pub struct SessionKeys{
    pub i2r_key: Aes128KeyHandle,
    pub r2i_key: Aes128KeyHandle,
    pub attestation_challenge: AttestationChallenge,
}

pub trait SessionKeystore {
    /*
     * @brief Import raw key material and return a key handle for a key that be used to do AES 128 encryption.
     *
     * @note This method should only be used when using the raw key material in the Matter stack
     * cannot be avoided. Ideally, crypto interfaces should allow platforms to perform all the
     * cryptographic operations in a secure environment.
     *
     * If the method returns no error, the application is responsible for destroying the handle
     * using the DestroyKey() method when the key is no longer needed.
     */
    fn create_key_aes128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Aes128KeyHandle, ChipError>;

    /*
     * @brief Import raw key material and return a key handle for a key that can be used to do 128-bit HMAC.
     *
     * @note This method should only be used when using the raw key material in the Matter stack
     * cannot be avoided. Ideally, crypto interfaces should allow platforms to perform all the
     * cryptographic operations in a secure environment.
     *
     * If the method returns no error, the application is responsible for destroying the handle
     * using the DestroyKey() method when the key is no longer needed.
     */
    fn create_key_hmac128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Hmac128KeyHandle, ChipError>;

    /*
     * @brief Import raw key material and return a key handle for an HKDF key.
     *
     * @note This method should only be used when using the raw key material in the Matter stack
     * cannot be avoided. Ideally, crypto interfaces should allow platforms to perform all the
     * cryptographic operations in a secure environment.
     *
     * If the method returns no error, the application is responsible for destroying the handle
     * using the DestroyKey() method when the key is no longer needed.
     */
    fn create_key_hkdf(&mut self, key_material: &[u8]) -> Result<HkdfKeyHandle, ChipError>;

    /*
     * @brief Destroy key.
     *
     * The method can take an uninitialized handle in which case it is a no-op.
     * As a result of calling this method, the handle is put in the uninitialized state.
     */

    fn destroy_key_128bits(&mut self, key: &mut Symmetric128BitsKeyHandle);
    fn destroy_key_hkdf(&mut self, key: &mut HkdfKeyHandle);

    /****************************
     * SessionKeyDerivation APIs
     *****************************/
    /*
     * @brief Derive key from a session establishment's `SharedSecret`.
     *
     * Use `Crypto_KDF` (HKDF) primitive as defined in the Matter specification to derive
     * a symmetric (AES) key from the session establishment's `SharedSecret`.
     *
     * If the method returns no error, the caller is responsible for destroying the symmetric key
     * using the DestroyKey() method when the key is no longer needed.
     */
    fn drive_key(&mut self, secret: &P256EcdhDeriveSecret, salt: &[u8], info: &[u8]) -> Result<Aes128KeyHandle, ChipError>;

    /*
     * @brief Derive session keys from a session establishment's `SharedSecret`.
     *
     * Use `Crypto_KDF` (HKDF) primitive as defined in the Matter specification to derive symmetric
     * (AES) session keys for both directions, and the attestation challenge from the session
     * establishment's `SharedSecret`.
     *
     * If the method returns no error, the caller is responsible for destroying the symmetric keys
     * using the DestroyKey() method when the keys are no longer needed. On failure, the method is
     * responsible for releasing all keys that it allocated so far.
     *
     * Output is (i2rKey, r2iKey, attestation_challenge)
     */
    fn derive_session_keys_aes128(&mut self, secret: &[u8], salt: &[u8], info: &[u8]) -> Result<SessionKeys, ChipError>;

    fn derive_session_keys_hkdf(&mut self, secret: &HkdfKeyHandle, salt: &[u8], info: &[u8]) -> Result<SessionKeys, ChipError>;

    /*
     * @brief Persistently store an ICD key.
     *
     * If input is already a persistent key handle, the function is a no-op and the original handle is returned.
     * If input is a volatile key handle, key is persisted and the handle may be updated.
     *
     * If the method returns no error, the application is responsible for destroying the handle
     * using the DestroyKey() method when the key is no longer needed.
     */
    fn persist_icd_key(&mut self) -> Result<Symmetric128BitsKeyHandle, ChipError>;
}
