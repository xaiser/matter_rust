use crate::chip::chip_lib::core::data_model_types::FabricIndex;

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum CertChainElement {
    Krcac = 0,
    Kicac = 1,
    Knoc = 2,
}

pub trait OperationalCertificateStore {
    fn has_pending_root_cert(&self) -> bool;
    fn has_pending_noc_chain(&self) -> bool;
    fn has_certificate_for_fabric(
        &self,
        fabric_index: FabricIndex,
        element: CertChainElement,
    ) -> bool;
    fn add_new_trusted_root_cert_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        rcac: &[u8],
    ) -> ChipErrorResult;
    fn add_new_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult;
    fn update_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult;
    fn commit_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;
    fn remove_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;
    fn revert_pending_op_certs(&mut self);
    fn revert_pending_op_certs_except_root(&mut self);
    fn get_certificate(
        &self,
        fabric_index: FabricIndex,
        out_certificate: &mut [u8],
    ) -> ChipErrorResult;
}

pub struct OpCertStoreTransaction<'a, OCS>
where
    OCS: OperationalCertificateStore,
{
    m_store: &'a mut OCS,
}

impl<'a, OCS> OpCertStoreTransaction<'a, OCS>
where
    OCS: OperationalCertificateStore,
{
    pub fn default_with(store: &'a mut OCS) -> Self {
        Self { m_store: store }
    }
    pub fn as_mut_ref(&mut self) -> &mut OCS {
        return self.m_store;
    }
}

impl<'a, OCS> Drop for OpCertStoreTransaction<'a, OCS>
where
    OCS: OperationalCertificateStore,
{
    fn drop(&mut self) {
        self.m_store.revert_pending_op_certs();
    }
}
