use crate::{
    ChipError,
    ChipErrorResult,
    chip_core_error,
    chip_error_internal,
    chip_no_error,
    chip_ok,
    chip_sdk_error,
    chip::{
        chip_lib::core::chip_config::CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE,
        crypto::{
            session_keystore::SessionKeystore,
            Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
            P256EcdhDeriveSecret, AttestationChallenge, 
        },
    },
};

#[derive(Default)]
struct RawHkdfKeyHandle {
    pub data: [u8; CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE - core::mem::size_of::<u8>()],
    pub size: u8,
}

impl RawHkdfKeyHandle {
    const K_MAX_DATA_SIZE: usize = CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE - core::mem::size_of::<u8>();

    pub fn as_ref(&self) -> Option<&[u8]> {
        let size = self.size as usize;
        if size > Self::K_MAX_DATA_SIZE {
            return None;
        }

        Some(&self.data[..size])
    }
}

#[derive(Default)]
pub struct RawKeySessionKeystore;

impl SessionKeystore for RawKeySessionKeystore {
    fn create_key_aes128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Aes128KeyHandle, ChipError> {
        let mut key = Aes128KeyHandle::default();
        key.as_mut::<Symmetric128BitsKeyByteArray>().copy_from_slice(key_material);

        Ok(key)
    }

    fn create_key_hmac128(&mut self, _key_material: &Symmetric128BitsKeyByteArray) -> Result<Hmac128KeyHandle, ChipError> {
        Err(chip_error_internal!())
    }

    fn create_key_hkdf(&mut self, _key_material: &[u8]) -> Result<HkdfKeyHandle, ChipError> {
        Err(chip_error_internal!())
    }

    fn destroy_key_128bits(&mut self, _key: &mut Symmetric128BitsKeyHandle) -> ChipErrorResult {
        Err(chip_error_internal!())
    }

    fn destroy_key_hkdf(&mut self, _key: &mut HkdfKeyHandle) -> ChipErrorResult {
        Err(chip_error_internal!())
    }

    fn drive_key(&mut self, _secret: &P256EcdhDeriveSecret, _salt: &[u8], _info: &[u8]) -> Result<Aes128KeyHandle, ChipError> {
        Err(chip_error_internal!())
    }

    fn derive_session_keys_aes128(&mut self, _secret: &[u8], _salt: &[u8], _info: &[u8]) -> Result<(Aes128KeyHandle, Aes128KeyHandle, AttestationChallenge), ChipError> {
        Err(chip_error_internal!())
    }

    fn derive_session_keys_hkdf(&mut self, _secret: &HkdfKeyHandle, _salt: &[u8], _info: &[u8]) -> Result<(Aes128KeyHandle, Aes128KeyHandle, AttestationChallenge), ChipError> {
        Err(chip_error_internal!())
    }

    fn persist_icd_key(&mut self) -> Result<Symmetric128BitsKeyHandle, ChipError> {
        Err(chip_error_internal!())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_key_aes128_successfully() {
        let key_material = Symmetric128BitsKeyByteArray::default();
        assert!(false);
    }
} // end of tests
