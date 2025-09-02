use crate::chip::chip_lib::{
    core::{
    chip_persistent_storage_delegate::PersistentStorageDelegate,
    data_model_types::{is_valid_fabric_index, FabricIndex, KUNDEFINED_FABRIC_INDEX},
    },
    support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
};
use crate::chip::credentials::{self, OperationalCertificateStore, operational_certificate_store::CertChainElement, chip_cert::{CertBuffer, K_MAX_CHIP_CERT_LENGTH}};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_ok;
use crate::chip_error_incorrect_state;
use crate::chip_error_not_implemented;
use crate::chip_error_invalid_fabric_index;
use crate::chip_error_invalid_argument;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use bitflags::{bitflags, Flags};
use core::ptr;

const DUMMY_CERT_SIZE: usize = K_MAX_CHIP_CERT_LENGTH;

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

fn get_storage_key_for_cert(fabric_index: FabricIndex, element: CertChainElement) -> Option<StorageKeyName> {
    match element {
        CertChainElement::Knoc => {
            return Some(DefaultStorageKeyAllocator::fabric_noc(fabric_index));
        },
        CertChainElement::Kicac => {
            return Some(DefaultStorageKeyAllocator::fabric_icac(fabric_index));
        },
        CertChainElement::Krcac => {
            return Some(DefaultStorageKeyAllocator::fabric_rcac(fabric_index));
        },
    }

    None
}

fn storage_has_certificate<PS: PersistentStorageDelegate>(storage: &PS, fabric_index: FabricIndex, element: CertChainElement) -> bool {
    if let Some(storage_key) = get_storage_key_for_cert(fabric_index, element) {
        let mut place_holder_cert_buffer = CertBuffer::default();

        return storage.sync_get_key_value(storage_key.key_name_str(), place_holder_cert_buffer.bytes()).is_ok();
    } else {
        false
    }
}

pub struct PersistentStorageOpCertStore<PS>
where
    PS: PersistentStorageDelegate,
{
    m_storage: *mut PS,
    m_pending_fabric_index: FabricIndex,
    // TODO: make this in the heap once we use the real certificate
    m_pending_rcac: Option<CertBuffer>,
    m_pending_icac: Option<CertBuffer>,
    m_pending_noc: Option<CertBuffer>,
    m_pending_vvsc: Option<CertBuffer>,
    m_pending_vid_verification_statement: Option<CertBuffer>,
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
        if self.m_storage.is_null() || !is_valid_fabric_index(fabric_index) {
            return false;
        }

        if fabric_index == self.m_pending_fabric_index {
            match element {
                CertChainElement::Knoc => {
                    return self.m_pending_noc.is_some();
                },
                CertChainElement::Kicac => {
                    return self.m_pending_icac.is_some();
                },
                CertChainElement::Krcac => {
                    return self.m_pending_rcac.is_some();
                },
            }
        }

        unsafe {
            return storage_has_certificate(self.m_storage.as_mut().unwrap(), fabric_index, element);
        }
    }

    fn add_new_trusted_root_cert_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        rcac: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(self.m_storage.is_null() == false, Err(chip_error_incorrect_state!()));
        verify_or_return_error!(is_valid_fabric_index(fabric_index), Err(chip_error_invalid_fabric_index!()));
        verify_or_return_error!(rcac.is_empty() == false && rcac.len() <= K_MAX_CHIP_CERT_LENGTH, Err(chip_error_invalid_argument!()));
        verify_or_return_error!(false == self.m_state_flag.intersects(StateFlags::KupdateOpCertsCalled | StateFlags::KaddNewTrustedRootCalled | StateFlags::KaddNewOpCertsCalled), Err(chip_error_incorrect_state!()));
        unsafe {
            verify_or_return_error!(!storage_has_certificate(self.m_storage.as_mut().unwrap(), fabric_index, CertChainElement::Krcac), Err(chip_error_incorrect_state!()));
        }

        let mut buf = CertBuffer::default();
        buf.init(rcac)?;

        self.m_pending_rcac = Some(buf);
        self.m_pending_fabric_index = fabric_index;
        self.m_state_flag.insert(StateFlags::KaddNewTrustedRootCalled);

        chip_ok!()
    }

    fn add_new_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(self.m_storage.is_null() == false, Err(chip_error_incorrect_state!()));
        verify_or_return_error!(is_valid_fabric_index(fabric_index), Err(chip_error_invalid_fabric_index!()));
        verify_or_return_error!(noc.is_empty() == false && noc.len() <= K_MAX_CHIP_CERT_LENGTH, Err(chip_error_invalid_argument!()));
        verify_or_return_error!(icac.len() <= K_MAX_CHIP_CERT_LENGTH, Err(chip_error_invalid_argument!()));
        verify_or_return_error!(false == self.m_state_flag.intersects(StateFlags::KupdateOpCertsCalled | StateFlags::KaddNewOpCertsCalled), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(self.m_state_flag.intersects(StateFlags::KaddNewTrustedRootCalled), Err(chip_error_incorrect_state!()));
        verify_or_return_error!(fabric_index == self.m_pending_fabric_index, Err(chip_error_incorrect_state!()));
        unsafe {
            verify_or_return_error!(!storage_has_certificate(self.m_storage.as_mut().unwrap(), fabric_index, CertChainElement::Knoc), Err(chip_error_incorrect_state!()));
            verify_or_return_error!(!storage_has_certificate(self.m_storage.as_mut().unwrap(), fabric_index, CertChainElement::Kicac), Err(chip_error_incorrect_state!()));
        }

        let mut noc_buf = CertBuffer::default();
        noc_buf.init(noc)?;

        let mut icac_buf = CertBuffer::default();
        if icac.len() > 0 {
            icac_buf.init(icac)?;
        }

        self.m_pending_noc = Some(noc_buf);
        self.m_pending_icac = Some(icac_buf);

        self.m_state_flag.insert(StateFlags::KaddNewOpCertsCalled);

        chip_ok!()
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
    use core::ptr;
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

    #[test]
    fn add_root_cert() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut cert = CertBuffer::default();
        let _ = cert.init(&[1]);

        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &cert.const_bytes()[..cert.length()]).is_ok());
        assert_eq!(true, store.has_certificate_for_fabric(0, CertChainElement::Krcac));
    }

    #[test]
    fn cannot_add_root_cert_twice() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut cert = CertBuffer::default();
        let _ = cert.init(&[1]);

        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &cert.const_bytes()[..cert.length()]).is_ok());
        assert_eq!(false, store.add_new_trusted_root_cert_for_fabric(0, &cert.const_bytes()[..cert.length()]).is_ok());
    }

    #[test]
    fn cannot_add_empty_root_cert() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut cert = CertBuffer::default();

        assert_eq!(false, store.add_new_trusted_root_cert_for_fabric(0, &cert.const_bytes()[..cert.length()]).is_ok());
    }

    #[test]
    fn add_noc_cert() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &root_cert.const_bytes()[..root_cert.length()]).is_ok());

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(true, store.add_new_op_certs_for_fabric(0, &noc_cert.const_bytes()[..noc_cert.length()], &icac_cert.const_bytes()[..icac_cert.length()]).is_ok());
    }

    #[test]
    fn add_noc_cert_with_root() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(false, store.add_new_op_certs_for_fabric(0, &noc_cert.const_bytes()[..noc_cert.length()], &icac_cert.const_bytes()[..icac_cert.length()]).is_ok());
    }

    #[test]
    fn cannot_add_noc_cert_twice() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &root_cert.const_bytes()[..root_cert.length()]).is_ok());

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(true, store.add_new_op_certs_for_fabric(0, &noc_cert.const_bytes()[..noc_cert.length()], &icac_cert.const_bytes()[..icac_cert.length()]).is_ok());
        assert_eq!(false, store.add_new_op_certs_for_fabric(0, &noc_cert.const_bytes()[..noc_cert.length()], &icac_cert.const_bytes()[..icac_cert.length()]).is_ok());
    }

    #[test]
    fn add_noc_cert_without_icac() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &root_cert.const_bytes()[..root_cert.length()]).is_ok());

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(true, store.add_new_op_certs_for_fabric(0, &noc_cert.const_bytes()[..noc_cert.length()], &[]).is_ok());
    }

    #[test]
    fn add_empty_noc_icac() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(false, store.has_certificate_for_fabric(0, CertChainElement::Krcac));

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(true, store.add_new_trusted_root_cert_for_fabric(0, &root_cert.const_bytes()[..root_cert.length()]).is_ok());

        assert_eq!(false, store.add_new_op_certs_for_fabric(0, &[], &[]).is_ok());
    }
} // end of tests
