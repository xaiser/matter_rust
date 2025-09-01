use crate::chip::chip_lib::core::{
    chip_persistent_storage_delegate::PersistentStorageDelegate,
    data_model_types::{FabricIndex, KUNDEFINED_FABRIC_INDEX},
};
use crate::chip::credentials::{self, OperationalCertificateStore, operational_certificate_store::CertChainElement};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_ok;
use crate::chip_error_incorrect_state;
use crate::chip_error_not_implemented;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use bitflags::{bitflags, Flags};
use core::ptr;

const DUMMY_CERT_SIZE: usize = 4;

bitflags! {
    #[derive(Copy,Clone)]
    struct StateFlags: u8 {
        const KaddNewOpCertsCalled = 1;
        const KaddNewTrustedRootCalled = 2;
        const KupdateOpCertsCalled = 4;
        const KvidVerificationStatementUpdated = 8;
        const KvvscUpdated = 16;
    }
}

pub struct PersistentStorageOpCertStore<PS>
where
    PS: PersistentStorageDelegate,
{
    m_storage: *mut PS,
    m_pending_fabric_index: FabricIndex,
    // TODO: make this in the heap once we use the real certificate
    m_pending_rcac: Option<[u8; DUMMY_CERT_SIZE]>,
    m_pending_icac: Option<[u8; DUMMY_CERT_SIZE]>,
    m_pending_noc: Option<[u8; DUMMY_CERT_SIZE]>,
    m_pending_vvsc: Option<[u8; DUMMY_CERT_SIZE]>,
    m_pending_vid_verification_statement: Option<[u8; DUMMY_CERT_SIZE]>,
    m_state_flag: StateFlags,
}

impl<PS> Default for PersistentStorageOpCertStore<PS>
where
    PS: PersistentStorageDelegate,
{
    fn default() -> Self {
        PersistentStorageOpCertStore::<PS>::const_default()
    }
}


impl<PS> PersistentStorageOpCertStore<PS>
where
    PS: PersistentStorageDelegate,
{
    pub fn const_default() -> Self {
        Self {
            m_storage: ptr::null_mut(),
            m_pending_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_pending_rcac: None,
            m_pending_icac: None,
            m_pending_noc: None,
            m_pending_vvsc: None,
            m_pending_vid_verification_statement: None,
            m_state_flag: StateFlags::from_bits_retain(0),
            
        }
    }

    pub fn init(&mut self, storage: * mut PS) -> ChipErrorResult {
        // make sure we haven't init yet.
        verify_or_return_error!(self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        self.revert_pending_op_certs();
        self.m_storage = storage;

        chip_ok!()
    }

    pub fn finish(&mut self) {
        if self.m_storage.is_null() {
            return;
        }
        self.revert_pending_op_certs();
        self.m_storage = ptr::null_mut();
    }

    fn revert_vid_verification_statement(&mut self) {
        self.m_pending_vvsc = None;
        self.m_pending_vid_verification_statement = None;
        self.m_state_flag.remove(StateFlags::KvidVerificationStatementUpdated);
        self.m_state_flag.remove(StateFlags::KvvscUpdated);
    }
}

impl<PS> OperationalCertificateStore for PersistentStorageOpCertStore<PS>
where
    PS: PersistentStorageDelegate,
{
    fn has_pending_root_cert(&self) -> bool {
        if self.m_storage.is_null() {
            return false;
        }

        return self.m_pending_rcac.is_some() && self.m_state_flag.contains(StateFlags::KaddNewTrustedRootCalled);
    }

    fn has_pending_noc_chain(&self) -> bool {
        if self.m_storage.is_null() {
            return false;
        }

        return self.m_pending_noc.is_some() && self.m_state_flag.intersects(StateFlags::KaddNewOpCertsCalled | StateFlags::KupdateOpCertsCalled);
    }

    fn has_certificate_for_fabric(
        &self,
        fabric_index: FabricIndex,
        element: CertChainElement,
    ) -> bool {
        false
    }

    fn add_new_trusted_root_cert_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        rcac: &[u8],
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn add_new_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn update_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn commit_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn remove_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn revert_pending_op_certs(&mut self) {
        self.revert_pending_op_certs_except_root();

        self.m_pending_rcac = None;
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
        self.m_state_flag.clear();
    }

    fn revert_pending_op_certs_except_root(&mut self) {
        self.m_pending_icac = None;
        self.m_pending_noc = None;

        if self.m_pending_rcac.is_none() {
            self.m_pending_fabric_index == KUNDEFINED_FABRIC_INDEX;
        }

        self.m_state_flag.remove(StateFlags::KaddNewOpCertsCalled);
        self.m_state_flag.remove(StateFlags::KupdateOpCertsCalled);
        self.revert_vid_verification_statement();
    }

    fn get_certificate(
        &self,
        fabric_index: FabricIndex,
        out_certificate: &mut [u8],
    ) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::chip_lib::support::test_persistent_storage::TestPersistentStorage;

    type Store = PersistentStorageOpCertStore<TestPersistentStorage>;

    fn setup(pa: *mut TestPersistentStorage) -> Store {
        let mut store = Store::default();
        let _ = store.init(pa);
        store
    }

    #[test]
    fn init() {
        let mut pa = TestPersistentStorage::default();
        let mut store = Store::default();
        assert_eq!(true, store.init(ptr::addr_of_mut!(pa)).is_ok());
    }
} // end of tests
