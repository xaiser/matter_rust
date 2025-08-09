use crate::chip::chip_lib::core::{
    chip_persistent_storage_delegate::PersistentStorageDelegate,
    data_model_types::{is_valid_fabric_index, FabricIndex, KUNDEFINED_FABRIC_INDEX},
};
use crate::chip::crypto::{self, ECPKey, ECPKeypair, OperationalKeystore, P256KeypairBase};

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_error_buffer_too_small;
use crate::chip_error_incorrect_state;
use crate::chip_error_invalid_fabric_index;
use crate::chip_error_invalid_public_key;
use crate::chip_ok;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::ptr;

struct PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    m_storage: *mut PA,
    m_pending_fabric_index: FabricIndex,
    //m_pending_keypair: * mut crypto::P256Keypair,
    m_pending_keypair: Option<crypto::P256Keypair>,
    m_is_pending_keypair_active: bool,
    //m_is_externally_owned_keypair: bool,
}

impl<PA> Default for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    fn default() -> Self {
        Self {
            m_storage: ptr::null_mut(),
            m_pending_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_pending_keypair: None,
            m_is_pending_keypair_active: false,
            //m_is_externally_owned_keypair: false
        }
    }
}

impl<PA> PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    pub fn init(&mut self, storage: *mut PA) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
        //self.m_is_externally_owned_keypair = false;
        self.m_storage = storage;
        self.m_pending_keypair = None;
        self.m_is_pending_keypair_active = false;

        chip_ok!()
    }

    fn reset_pending_key(&mut self) {
        self.m_pending_keypair = None;
        self.m_is_pending_keypair_active = false;
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
    }
}

impl<PA> OperationalKeystore for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    fn has_pending_op_keypair(&self) -> bool {
        false
    }

    fn has_op_keypair_for_fabric(&self, fabric_index: FabricIndex) -> bool {
        false
    }

    fn new_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        out_certificate_siging_request: &mut [u8],
    ) -> Result<usize, ChipError> {
        verify_or_return_error!(
            self.m_storage.is_null() != false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        // If a key is pending, we cannot generate for a different fabric index until we commit or revert.
        if (self.m_pending_fabric_index != KUNDEFINED_FABRIC_INDEX)
            && (self.m_pending_fabric_index != fabric_index)
        {
            return Err(chip_error_invalid_fabric_index!());
        }

        verify_or_return_error!(
            out_certificate_siging_request.len() >= crypto::K_MIN_CSR_BUFFER_SIZE,
            Err(chip_error_buffer_too_small!())
        );

        // Replace previous pending keypair, if any was previously allocated
        self.reset_pending_key();

        let mut pending_keypair = crypto::P256Keypair::default();
        pending_keypair.initialize(crypto::ECPKeyTarget::Ecdh);

        match pending_keypair
            .new_certificate_signing_request(&mut out_certificate_siging_request[..])
        {
            Ok(csr_length) => {
                self.m_pending_keypair = Some(pending_keypair);
                self.m_pending_fabric_index = fabric_index;
                return Ok(csr_length);
            }
            Err(e) => {
                self.reset_pending_key();
                return Err(e);
            }
        }
    }

    fn activate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc_public_key: &crypto::P256PublicKey,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() != false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            (is_valid_fabric_index(fabric_index)) && (fabric_index == self.m_pending_fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        if let Some(keypair) = &self.m_pending_keypair {
            verify_or_return_error!(
                keypair.ecdsa_pubkey().matches(noc_public_key),
                Err(chip_error_invalid_public_key!())
            );
        } else {
            return Err(chip_error_invalid_fabric_index!());
        }

        self.m_is_pending_keypair_active = true;

        chip_ok!()
    }

    fn commit_op_keypair_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn export_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        out_keypair: &mut crypto::P256SerializedKeypair,
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn migrate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        operational_keystore: &Self,
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn remove_op_keyapir_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn revert_pending_keypair(&mut self) {}

    fn supports_sign_with_op_keypair_in_background(&self) -> bool {
        false
    }

    fn sign_with_op_keyapir(
        &self,
        fabric_index: FabricIndex,
        message: &[u8],
        out_signature: &mut crypto::P256EcdsaSignature,
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn allocate_ephemeral_keypair_for_case(&self) -> *mut crypto::P256Keypair {
        ptr::null_mut()
    }

    fn release_ephemeral_keypair(keypair: *mut crypto::P256Keypair) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::crypto::P256PublicKey;
    use crate::chip::chip_lib::support::test_persistent_storage::TestPersistentStorage;

    type Store = PersistentStorageOperationalKeystore<TestPersistentStorage>;

    fn setup(pa: *mut TestPersistentStorage) -> Store {
        let mut store = Store::default();
        let _ = store.init(pa);
        store
    }

    #[test]
    fn new_op_keypair_for_fabric() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(2, &mut out_csr[..])
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
    }

    #[test]
    fn invalid_fabric_index() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(u8::MAX, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn pending_keypair() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(2, &mut out_csr[..])
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );

        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(3, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn small_csr_buffer() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 0] = [];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(u8::MAX, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn activate_op_keyapir() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _  = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey = P256PublicKey::default_with_raw_value(keypair.ecdsa_pubkey().const_bytes());
        } else {
            assert!(false);
        }
        assert_eq!(true, store.activate_op_keypair_for_fabric(2, &noc_pubkey).inspect_err(|e| {
            println!("err is {}", e);
        }).is_ok());
        assert_eq!(true, store.m_is_pending_keypair_active);
    }

    #[test]
    fn activate_op_keyapir_with_wrong_pubkey() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _  = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        assert_eq!(true, store.activate_op_keypair_for_fabric(2, &noc_pubkey).is_err());
        assert_eq!(false, store.m_is_pending_keypair_active);
    }
} // end of mod tests
