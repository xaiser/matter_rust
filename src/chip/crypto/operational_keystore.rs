use crate::chip::chip_lib::core::data_model_types::FabricIndex;
use crate::chip::crypto;

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

pub trait OperationalKeystore {
    fn has_pending_op_keypair(&self) -> bool;

    fn has_op_keypair_for_fabric(&self, fabric_index: FabricIndex) -> bool;

    fn new_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        out_certificate_siging_request: &mut [u8],
    ) -> Result<usize, ChipError>;

    fn activate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc_public_key: &crypto::P256PublicKey,
    ) -> ChipErrorResult;

    fn commit_op_keypair_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;

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
        operational_keystore: &mut Self,
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn remove_op_keypair_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;

    fn revert_pending_keypair(&mut self);

    fn supports_sign_with_op_keypair_in_background(&self) -> bool {
        false
    }

    fn sign_with_op_keyapir(
        &self,
        fabric_index: FabricIndex,
        message: &[u8],
        out_signature: &mut crypto::P256EcdsaSignature,
    ) -> ChipErrorResult;

    fn allocate_ephemeral_keypair_for_case(&self) -> *mut crypto::P256Keypair;

    fn release_ephemeral_keypair(keypair: *mut crypto::P256Keypair);
}
