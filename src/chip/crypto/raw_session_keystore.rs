use crate::{
    ChipError,
    ChipErrorResult,
    chip_core_error,
    chip_no_error,
    chip_ok,
    chip_sdk_error,
    verify_or_return_error,
    verify_or_return_value,
    chip_error_internal,
    chip_error_buffer_too_small,
    chip::{
        chip_lib::{
            core::chip_config::CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE,
            support::buffer_reader::{self, BufferReader},
        },
        crypto::{
            session_keystore::{SessionKeystore, SessionKeys},
            Symmetric128BitsKeyByteArray, Aes128KeyHandle, Hmac128KeyHandle, HkdfKeyHandle, Symmetric128BitsKeyHandle,
            P256EcdhDeriveSecret, AttestationChallenge, FromOpaqueContext, OpaqueContext, HKDFSha,
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

impl<const CONTEXT_SIZE: usize> FromOpaqueContext<CONTEXT_SIZE> for RawHkdfKeyHandle {
    fn from_opaque_context(context: &OpaqueContext<CONTEXT_SIZE>) -> &Self {
        unsafe { &*(context.m_opaque.as_ptr() as *const Self) }
    }

    fn from_opaque_context_mut(context: &mut OpaqueContext<CONTEXT_SIZE>) -> &mut Self {
        unsafe { &mut *(context.m_opaque.as_mut_ptr() as *mut Self) }
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

    fn create_key_hmac128(&mut self, key_material: &Symmetric128BitsKeyByteArray) -> Result<Hmac128KeyHandle, ChipError> {
        let mut key = Hmac128KeyHandle::default();
        key.as_mut::<Symmetric128BitsKeyByteArray>().copy_from_slice(key_material);

        Ok(key)
    }

    fn create_key_hkdf(&mut self, key_material: &[u8]) -> Result<HkdfKeyHandle, ChipError> {
        let mut key = HkdfKeyHandle::default();
        verify_or_return_error!(key_material.len() <= RawHkdfKeyHandle::K_MAX_DATA_SIZE, Err(chip_error_buffer_too_small!()));
        let mut_key = key.as_mut::<RawHkdfKeyHandle>();

        mut_key.data[..key_material.len()].copy_from_slice(&key_material[..key_material.len()]);
        mut_key.size = key_material.len() as u8;

        Ok(key)
    }

    fn destroy_key_128bits(&mut self, _key: &mut Symmetric128BitsKeyHandle) -> ChipErrorResult {
        Err(chip_error_internal!())
    }

    fn destroy_key_hkdf(&mut self, _key: &mut HkdfKeyHandle) -> ChipErrorResult {
        Err(chip_error_internal!())
    }

    fn drive_key(&mut self, secret: &P256EcdhDeriveSecret, salt: &[u8], info: &[u8]) -> Result<Aes128KeyHandle, ChipError> {
        let mut key = Aes128KeyHandle::default();
        let mut_key = key.as_mut::<Symmetric128BitsKeyByteArray>();

        HKDFSha::hkdf_sha(secret.const_bytes(), salt, info, mut_key)?;

        return Ok(key);
    }

    fn derive_session_keys_aes128(&mut self, secret: &[u8], salt: &[u8], info: &[u8]) -> Result<SessionKeys, ChipError> {
        let mut session_keys = SessionKeys::default();
        let mut key_material = [0u8; 2 * size_of::<Symmetric128BitsKeyByteArray>() + AttestationChallenge::capacity()];

        HKDFSha::hkdf_sha(secret, salt, info, &mut key_material)?;

        let mut reader = buffer_reader::little_endian::Reader::default(&key_material);

        let e = reader.read_bytes(session_keys.i2r_key.as_mut::<Symmetric128BitsKeyByteArray>())
            .read_bytes(session_keys.r2i_key.as_mut::<Symmetric128BitsKeyByteArray>())
            .read_bytes(&mut session_keys.attestation_challenge.bytes()[..AttestationChallenge::capacity()])
            .status_code();

        if e == chip_no_error!() {
            Ok(session_keys)
        } else {
            Err(e)
        }
    }

    fn derive_session_keys_hkdf(&mut self, _secret: &HkdfKeyHandle, _salt: &[u8], _info: &[u8]) -> Result<SessionKeys, ChipError> {
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
        let mut key_material = Symmetric128BitsKeyByteArray::default();
        // fill up stub value
        key_material.fill(0x1);

        let mut store = RawKeySessionKeystore::default();

        let aes_key = store.create_key_aes128(&key_material);

        assert!(aes_key.is_ok_and(|key| {
            let d = key.as_ref::<Symmetric128BitsKeyByteArray>();

            d == &key_material
        }));
    }

    #[test]
    fn create_key_hmac_successfully() {
        let mut key_material = Symmetric128BitsKeyByteArray::default();
        // fill up stub value
        key_material.fill(0x1);

        let mut store = RawKeySessionKeystore::default();

        let hmac_key = store.create_key_hmac128(&key_material);

        assert!(hmac_key.is_ok_and(|key| {
            let d = key.as_ref::<Symmetric128BitsKeyByteArray>();

            d == &key_material
        }));
    }

    #[test]
    fn create_key_hkdf_successfully() {
        const DATA_SIZE: usize = 2;
        let key_material = [1u8; DATA_SIZE];

        let mut store = RawKeySessionKeystore::default();

        let hkdf_key = store.create_key_hkdf(&key_material);

        assert!(hkdf_key.is_ok_and(|key| {
            let d = key.as_ref::<RawHkdfKeyHandle>();

            &d.data[0..DATA_SIZE] == &key_material && d.size == (DATA_SIZE as u8)
        }));
    }

    #[test]
    fn drive_key_aes128_successfully() {
        let mut secret = P256EcdhDeriveSecret::default();
        // fill up stub value
        secret.bytes().fill(0x1);

        let info = [1u8; 2];
        let salt = [1u8; 2];

        let mut store = RawKeySessionKeystore::default();

        let aes_key = store.drive_key(&secret, &info, &salt);

        assert!(aes_key.is_ok());
    }
} // end of tests
