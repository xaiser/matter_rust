use crate::{
    ChipError,
    ChipErrorResult,
    chip::{
        crypto::{
            session_keystore::SessionKeystore,
            Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
            P256EcdhDeriveSecret, AttestationChallenge,
        },
    },
};

pub struct RawKeySessionKeystore;

/*
impl SessionKeystore for RawKeySessionKeystore {
    fn create_key_aes128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Aes128KeyHandle, ChipError>;
    fn create_key_hmac128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Hmac128KeyHandle, ChipError>;
    fn create_key_hkdf(&mut self, key_material: &[u8]) -> Result<HkdfKeyHandle, ChipError>;
    fn destroy_key_128bits(&mut self, key: &mut Symmetric128BitsKeyHandle) -> ChipErrorResult;
    fn destroy_key_hkdf(&mut self, key: &mut HkdfKeyHandle) -> ChipErrorResult;
    fn drive_key(&mut self, secret: &P256EcdhDeriveSecret, salt: &[u8], info: &[u8]) -> Result<Aes128KeyHandle, ChipError>;
    fn derive_session_keys_aes128(&mut self, secret: &[u8], salt: &[u8], info: &[u8]) -> Result<(Aes128KeyHandle, Aes128KeyHandle, AttestationChallenge), ChipError>;
    fn derive_session_keys_hkdf(&mut self, secret: &HkdfKeyHandle, salt: &[u8], info: &[u8]) -> Result<(Aes128KeyHandle, Aes128KeyHandle, AttestationChallenge), ChipError>;
    fn persist_icd_key(&mut self) -> Result<Symmetric128BitsKeyHandle, ChipError>;
}
*/
