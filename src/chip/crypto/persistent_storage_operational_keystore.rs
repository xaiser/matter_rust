use crate::chip::chip_lib::core::{
    data_model_types::{FabricIndex, KUNDEFINED_FABRIC_INDEX},
    chip_persistent_storage_delegate::PersistentStorageDelegate,
};
use crate::chip::crypto::{self, OperationalKeystore};

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipErrorResult;

use crate::chip_ok;
use crate::chip_error_incorrect_state;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::ptr;

struct PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    m_storage: * mut PA,
    m_pending_fabric_index: FabricIndex,
    m_pending_keypair: * mut crypto::P256Keypair,
    m_is_pending_keypair_active: bool,
    m_is_externally_owned_keypair: bool,
}

impl<PA> Default for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate
{
    fn default() -> Self {
        Self {
            m_storage: ptr::null_mut(),
            m_pending_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_pending_keypair: ptr::null_mut(),
            m_is_pending_keypair_active: false,
            m_is_externally_owned_keypair: false
        }
    }
}

impl<PA> PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate
{
    pub fn init(&mut self, storage: * mut PA) -> ChipErrorResult {
        verify_or_return_error!(self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
        self.m_is_externally_owned_keypair = false;
        self.m_storage = storage;
        self.m_pending_keypair = ptr::null_mut();
        self.m_is_pending_keypair_active = false;

        chip_ok!()
    }

    fn reset_pending_key(&mut self) {
    }
}

impl<PA> OperationalKeystore for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate
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
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn activate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc_public_key: &crypto::P256PublicKey,
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
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
