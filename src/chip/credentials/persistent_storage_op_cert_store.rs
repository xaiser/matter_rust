use crate::chip::chip_lib::{
    core::{
        chip_persistent_storage_delegate::PersistentStorageDelegate,
        data_model_types::{is_valid_fabric_index, FabricIndex, KUNDEFINED_FABRIC_INDEX},
    },
    support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
};
use crate::chip::credentials::{
    self,
    chip_cert::{CertBuffer, K_MAX_CHIP_CERT_LENGTH},
    operational_certificate_store::{CertChainElement, VidVerificationElement},
    OperationalCertificateStore,
};
use crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE;

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_error_incorrect_state;
use crate::chip_error_internal;
use crate::chip_error_invalid_argument;
use crate::chip_error_invalid_fabric_index;
use crate::chip_error_not_found;
use crate::chip_error_not_implemented;
use crate::chip_error_persisted_storage_value_not_found;
use crate::chip_ok;

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

fn get_storage_key_for_cert(
    fabric_index: FabricIndex,
    element: CertChainElement,
) -> Option<StorageKeyName> {
    match element {
        CertChainElement::Knoc => {
            return Some(DefaultStorageKeyAllocator::fabric_noc(fabric_index));
        }
        CertChainElement::Kicac => {
            return Some(DefaultStorageKeyAllocator::fabric_icac(fabric_index));
        }
        CertChainElement::Krcac => {
            return Some(DefaultStorageKeyAllocator::fabric_rcac(fabric_index));
        }
    }

    None
}

fn storage_has_certificate<PS: PersistentStorageDelegate>(
    storage: &PS,
    fabric_index: FabricIndex,
    element: CertChainElement,
) -> bool {
    if let Some(storage_key) = get_storage_key_for_cert(fabric_index, element) {
        let mut place_holder_cert_buffer = CertBuffer::default();

        return storage
            .sync_get_key_value(
                storage_key.key_name_str(),
                place_holder_cert_buffer.all_bytes(),
            )
            .is_ok();
    } else {
        false
    }
}

fn save_vid_verification_element_to_storage<PS: PersistentStorageDelegate>(
    storage: &mut PS,
    fabric_index: FabricIndex,
    element: VidVerificationElement,
    element_data: &[u8],
) -> ChipErrorResult {
    let mut storage_key = StorageKeyName::default();
    match element {
        VidVerificationElement::KvidVerificationStatement => {
            storage_key =
                DefaultStorageKeyAllocator::fabric_vid_verification_statement(fabric_index);
        }
        VidVerificationElement::Kvvsc => {
            storage_key = DefaultStorageKeyAllocator::fabric_vvsc(fabric_index);
        }
    }

    if element_data.is_empty() {
        match storage.sync_delete_key_value(storage_key.key_name_str()) {
            Ok(_) => {
                return chip_ok!();
            }
            Err(e) => {
                if e == chip_error_persisted_storage_value_not_found!() {
                    return chip_ok!();
                } else {
                    return Err(e);
                }
            }
        }
    }

    return storage.sync_set_key_value(storage_key.key_name_str(), element_data);
}

fn save_cert_to_storage<PS: PersistentStorageDelegate>(
    storage: &mut PS,
    fabric_index: FabricIndex,
    element: CertChainElement,
    cert: &[u8],
) -> ChipErrorResult {
    let storage_key =
        get_storage_key_for_cert(fabric_index, element).ok_or(chip_error_internal!())?;

    if element == CertChainElement::Kicac && cert.is_empty() {
        match storage.sync_delete_key_value(storage_key.key_name_str()) {
            Err(e) => {
                if e == chip_error_persisted_storage_value_not_found!() {
                    return chip_ok!();
                } else {
                    return Err(e);
                }
            }
            _ => {
                return chip_ok!();
            }
        }
    }

    return storage.sync_set_key_value(storage_key.key_name_str(), cert);
}

fn delete_vid_verification_element_from_storage<PS: PersistentStorageDelegate>(
    storage: &mut PS,
    fabric_index: FabricIndex,
    element: VidVerificationElement,
) -> ChipErrorResult {
    // Saving an empty bytespan actually deletes the element.
    return save_vid_verification_element_to_storage(storage, fabric_index, element, &[]);
}

fn delete_cert_from_storage<PS: PersistentStorageDelegate>(
    storage: &mut PS,
    fabric_index: FabricIndex,
    element: CertChainElement,
) -> ChipErrorResult {
    if let Some(storage_key_name) = get_storage_key_for_cert(fabric_index, element) {
        return storage.sync_delete_key_value(storage_key_name.key_name_str());
    } else {
        return Err(chip_error_internal!());
    }
}

fn load_cert_from_stroage<PS: PersistentStorageDelegate>(
    storage: &mut PS,
    fabric_index: FabricIndex,
    element: CertChainElement,
    out_certificate: &mut [u8],
) -> Result<usize, ChipError> {
    let storage_key =
        get_storage_key_for_cert(fabric_index, element).ok_or(chip_error_internal!())?;

    return storage.sync_get_key_value(storage_key.key_name_str(), out_certificate);
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

    pub fn init(&mut self, storage: *mut PS) -> ChipErrorResult {
        // make sure we haven't init yet.
        verify_or_return_error!(self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        self.revert_pending_op_certs();
        self.m_storage = storage;

        chip_ok!()
    }

    #[allow(dead_code)]
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
        self.m_state_flag
            .remove(StateFlags::KvidVerificationStatementUpdated);
        self.m_state_flag.remove(StateFlags::KvvscUpdated);
    }

    fn has_noc_chain_for_fabric(&self, fabric_index: FabricIndex) -> bool {
        return self.has_certificate_for_fabric(fabric_index, CertChainElement::Krcac)
            && self.has_certificate_for_fabric(fabric_index, CertChainElement::Knoc);
    }

    fn basic_vid_verification_assumptions_are_met(
        &self,
        fabric_index: FabricIndex,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        // Must already have a valid NOC chain.
        verify_or_return_error!(
            self.has_noc_chain_for_fabric(fabric_index),
            Err(chip_error_incorrect_state!())
        );

        chip_ok!()
    }

    fn commit_vid_verification_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        verify_or_return_error!(
            !self.m_storage.is_null(),
            Err(chip_error_incorrect_state!())
        );

        if !self.has_pending_vid_verification_elements() {
            return chip_ok!();
        }

        verify_or_return_error!(
            is_valid_fabric_index(fabric_index) && fabric_index == self.m_pending_fabric_index,
            Err(chip_error_invalid_fabric_index!())
        );

        let mut vvsc_err = chip_ok!();
        let mut vvs_err = chip_ok!();
        if self.m_state_flag.contains(StateFlags::KvvscUpdated) {
            if let Some(vvsc) = self.m_pending_vvsc.as_ref() {
                unsafe {
                    vvsc_err = save_vid_verification_element_to_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        VidVerificationElement::Kvvsc,
                        vvsc.const_bytes(),
                    );
                }
            } else {
                vvsc_err = Err(chip_error_incorrect_state!());
            }
        }
        if self
            .m_state_flag
            .contains(StateFlags::KvidVerificationStatementUpdated)
        {
            if let Some(vvs) = self.m_pending_vid_verification_statement.as_ref() {
                unsafe {
                    vvs_err = save_vid_verification_element_to_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        VidVerificationElement::KvidVerificationStatement,
                        vvs.const_bytes(),
                    );
                }
            } else {
                vvs_err = Err(chip_error_incorrect_state!());
            }
        }

        // return the frist error
        if vvsc_err.is_err() {
            return vvsc_err;
        }

        return vvs_err;
    }

    fn has_any_certificate_for_fabric(&self, fabric_index: FabricIndex) -> bool {
        verify_or_return_error!(self.m_storage.is_null() == false, false);
        verify_or_return_error!(is_valid_fabric_index(fabric_index), false);

        unsafe {
            let rcac_missing = !storage_has_certificate(
                self.m_storage.as_mut().unwrap(),
                fabric_index,
                CertChainElement::Krcac,
            );
            let icac_missing = !storage_has_certificate(
                self.m_storage.as_mut().unwrap(),
                fabric_index,
                CertChainElement::Kicac,
            );
            let noc_missing = !storage_has_certificate(
                self.m_storage.as_mut().unwrap(),
                fabric_index,
                CertChainElement::Knoc,
            );
            let any_pending = self.m_pending_rcac.is_some()
                || self.m_pending_icac.is_some()
                || self.m_pending_noc.is_some();

            if rcac_missing && icac_missing && noc_missing && !any_pending {
                return false;
            }
        }

        true
    }

    fn get_pending_certificate(
        &self,
        fabric_index: FabricIndex,
        element: CertChainElement,
        out_certificate: &mut [u8],
    ) -> Result<usize, ChipError> {
        verify_or_return_error!(
            fabric_index == self.m_pending_fabric_index,
            Err(chip_error_not_found!())
        );
        match element {
            CertChainElement::Krcac => {
                if let Some(cert) = self.m_pending_rcac.as_ref() {
                    out_certificate[0..cert.length()].copy_from_slice(cert.const_bytes());
                    return Ok(cert.length());
                }
            }
            CertChainElement::Kicac => {
                if let Some(cert) = self.m_pending_icac.as_ref() {
                    out_certificate[0..cert.length()].copy_from_slice(cert.const_bytes());
                    return Ok(cert.length());
                }
            }
            CertChainElement::Knoc => {
                if let Some(cert) = self.m_pending_noc.as_ref() {
                    out_certificate[0..cert.length()].copy_from_slice(cert.const_bytes());
                    return Ok(cert.length());
                }
            }
        }
        return Err(chip_error_not_found!());
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

        return self.m_pending_rcac.is_some()
            && self
                .m_state_flag
                .contains(StateFlags::KaddNewTrustedRootCalled);
    }

    fn has_pending_noc_chain(&self) -> bool {
        if self.m_storage.is_null() {
            return false;
        }

        return self.m_pending_noc.is_some()
            && self
                .m_state_flag
                .intersects(StateFlags::KaddNewOpCertsCalled | StateFlags::KupdateOpCertsCalled);
    }

    fn has_pending_vid_verification_elements(&self) -> bool {
        self.m_state_flag
            .intersects(StateFlags::KvidVerificationStatementUpdated | StateFlags::KvvscUpdated)
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
                }
                CertChainElement::Kicac => {
                    return self.m_pending_icac.is_some();
                }
                CertChainElement::Krcac => {
                    return self.m_pending_rcac.is_some();
                }
            }
        }

        unsafe {
            return storage_has_certificate(
                self.m_storage.as_mut().unwrap(),
                fabric_index,
                element,
            );
        }
    }

    fn add_new_trusted_root_cert_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        rcac: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );
        verify_or_return_error!(
            rcac.is_empty() == false && rcac.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );
        verify_or_return_error!(
            false
                == self.m_state_flag.intersects(
                    StateFlags::KupdateOpCertsCalled
                        | StateFlags::KaddNewTrustedRootCalled
                        | StateFlags::KaddNewOpCertsCalled
                ),
            Err(chip_error_incorrect_state!())
        );
        unsafe {
            verify_or_return_error!(
                !storage_has_certificate(
                    self.m_storage.as_mut().unwrap(),
                    fabric_index,
                    CertChainElement::Krcac
                ),
                Err(chip_error_incorrect_state!())
            );
        }

        let mut buf = CertBuffer::default();
        buf.init(rcac)?;

        self.m_pending_rcac = Some(buf);
        self.m_pending_fabric_index = fabric_index;
        self.m_state_flag
            .insert(StateFlags::KaddNewTrustedRootCalled);

        chip_ok!()
    }

    fn add_new_op_certs_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc: &[u8],
        icac: &[u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );
        verify_or_return_error!(
            noc.is_empty() == false && noc.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );
        verify_or_return_error!(
            icac.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );
        verify_or_return_error!(
            false
                == self.m_state_flag.intersects(
                    StateFlags::KupdateOpCertsCalled | StateFlags::KaddNewOpCertsCalled
                ),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            self.m_state_flag
                .intersects(StateFlags::KaddNewTrustedRootCalled),
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            fabric_index == self.m_pending_fabric_index,
            Err(chip_error_incorrect_state!())
        );
        unsafe {
            verify_or_return_error!(
                !storage_has_certificate(
                    self.m_storage.as_mut().unwrap(),
                    fabric_index,
                    CertChainElement::Knoc
                ),
                Err(chip_error_incorrect_state!())
            );
            verify_or_return_error!(
                !storage_has_certificate(
                    self.m_storage.as_mut().unwrap(),
                    fabric_index,
                    CertChainElement::Kicac
                ),
                Err(chip_error_incorrect_state!())
            );
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
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );
        verify_or_return_error!(
            noc.is_empty() == false && noc.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );
        verify_or_return_error!(
            icac.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );
        // Can't have called AddNewOpCertsForFabric first, and should never get here after AddNewTrustedRootCertForFabric.
        verify_or_return_error!(
            !self.m_state_flag.intersects(
                StateFlags::KaddNewOpCertsCalled | StateFlags::KaddNewTrustedRootCalled
            ),
            Err(chip_error_incorrect_state!())
        );
        // Can't have already pending NOC from UpdateOpCerts not yet committed
        verify_or_return_error!(
            !self
                .m_state_flag
                .intersects(StateFlags::KupdateOpCertsCalled),
            Err(chip_error_incorrect_state!())
        );
        unsafe {
            // Need to have trusted roots installed to make the chain valid
            verify_or_return_error!(
                storage_has_certificate(
                    self.m_storage.as_mut().unwrap(),
                    fabric_index,
                    CertChainElement::Krcac
                ),
                Err(chip_error_incorrect_state!())
            );
            // Must have persisted NOC for same fabric if updating
            verify_or_return_error!(
                storage_has_certificate(
                    self.m_storage.as_mut().unwrap(),
                    fabric_index,
                    CertChainElement::Knoc
                ),
                Err(chip_error_incorrect_state!())
            );
            // Don't check for ICAC, we may not have had one before, but assume that if NOC is there, a
            // previous chain was at least partially there
        }

        let mut noc_buf = CertBuffer::default();
        noc_buf.init(noc)?;

        let mut icac_buf = CertBuffer::default();
        if icac.len() > 0 {
            icac_buf.init(icac)?;
        }

        self.m_pending_noc = Some(noc_buf);
        self.m_pending_icac = Some(icac_buf);

        self.m_pending_fabric_index = fabric_index;

        self.m_state_flag.insert(StateFlags::KupdateOpCertsCalled);

        chip_ok!()
    }

    fn commit_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index) && fabric_index == self.m_pending_fabric_index,
            Err(chip_error_invalid_fabric_index!())
        );

        verify_or_return_error!(
            self.has_pending_noc_chain(),
            Err(chip_error_incorrect_state!())
        );

        if self.has_pending_root_cert() {
            // Neither of these conditions should have occurred based on other interlocks, but since
            // committing certificates is a dangerous operation, we absolutely validate our assumptions.
            verify_or_return_error!(
                !self.m_state_flag.contains(StateFlags::KupdateOpCertsCalled),
                Err(chip_error_incorrect_state!())
            );
            verify_or_return_error!(
                self.m_state_flag
                    .contains(StateFlags::KaddNewTrustedRootCalled),
                Err(chip_error_incorrect_state!())
            );
        }

        unsafe {
            // Start committing NOC first so we don't have dangling roots if one was added.
            // We have check the pending_noc, so just call unwrap
            let noc_err = save_cert_to_storage(
                self.m_storage.as_mut().unwrap(),
                self.m_pending_fabric_index,
                CertChainElement::Knoc,
                self.m_pending_noc.as_ref().unwrap().const_bytes(),
            );

            // ICAC storage handles deleting on empty/missing
            let icac_err = save_cert_to_storage(
                self.m_storage.as_mut().unwrap(),
                self.m_pending_fabric_index,
                CertChainElement::Kicac,
                self.m_pending_icac
                    .as_ref()
                    .unwrap_or(&CertBuffer::const_default())
                    .const_bytes(),
            );

            let mut rcac_err = chip_ok!();
            if self.has_pending_root_cert() {
                rcac_err = save_cert_to_storage(
                    self.m_storage.as_mut().unwrap(),
                    self.m_pending_fabric_index,
                    CertChainElement::Krcac,
                    self.m_pending_rcac.as_ref().unwrap().const_bytes(),
                );
            }

            let vid_verify_err =
                self.commit_vid_verification_for_fabric(self.m_pending_fabric_index);

            // Remember which was the first error, and if any error occurred.
            if let Some(sticky_err) = [noc_err, icac_err, rcac_err, vid_verify_err]
                .iter()
                .find(|e| e.is_err())
            {
                // On Adds rather than updates, remove anything possibly stored for the new fabric on partial
                // failure.
                if self.m_state_flag.contains(StateFlags::KaddNewOpCertsCalled) {
                    let _ = delete_cert_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        CertChainElement::Knoc,
                    );
                    let _ = delete_cert_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        CertChainElement::Kicac,
                    );
                    let _ = delete_vid_verification_element_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        VidVerificationElement::Kvvsc,
                    );
                    let _ = delete_vid_verification_element_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        VidVerificationElement::KvidVerificationStatement,
                    );
                }
                if self
                    .m_state_flag
                    .contains(StateFlags::KaddNewTrustedRootCalled)
                {
                    let _ = delete_cert_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        self.m_pending_fabric_index,
                        CertChainElement::Krcac,
                    );
                }

                return sticky_err.clone();
            }
        }

        self.revert_pending_op_certs();

        chip_ok!()
    }

    fn remove_certs_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        // If there was *no* state, pending or persisted, we have an error
        verify_or_return_error!(
            self.has_any_certificate_for_fabric(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        // Clear any pending state
        self.revert_pending_op_certs();

        let storage;

        unsafe {
            storage = self.m_storage.as_mut().unwrap();
        }

        // Remove all persisted certs for the given fabric, blindly
        let errs = [
            delete_cert_from_storage(storage, fabric_index, CertChainElement::Knoc),
            delete_cert_from_storage(storage, fabric_index, CertChainElement::Kicac),
            delete_cert_from_storage(storage, fabric_index, CertChainElement::Krcac),
            delete_vid_verification_element_from_storage(
                storage,
                fabric_index,
                VidVerificationElement::Kvvsc,
            ),
            delete_vid_verification_element_from_storage(
                storage,
                fabric_index,
                VidVerificationElement::KvidVerificationStatement,
            ),
        ];

        // Find the first error and return that
        // Ignore missing data errors
        let not_found = chip_error_persisted_storage_value_not_found!();
        if let Some(sticky_err) = errs.iter().find(|e| e.is_err_and(|e| e != not_found)) {
            return sticky_err.clone();
        }

        chip_ok!()
    }

    fn update_vid_verification_signer_cert_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        vvsc: &[u8],
    ) -> ChipErrorResult {
        self.basic_vid_verification_assumptions_are_met(fabric_index)?;
        verify_or_return_error!(
            vvsc.is_empty() || vvsc.len() <= K_MAX_CHIP_CERT_LENGTH,
            Err(chip_error_invalid_argument!())
        );

        if vvsc.is_empty() {
            if fabric_index == self.m_pending_fabric_index {
                self.m_pending_vvsc = None;
                self.m_state_flag.insert(StateFlags::KvvscUpdated);
            } else {
                unsafe {
                    let _ = delete_vid_verification_element_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        fabric_index,
                        VidVerificationElement::Kvvsc,
                    )?;
                }
            }
        } else {
            if fabric_index == self.m_pending_fabric_index {
                let mut buf = CertBuffer::default();
                buf.init(vvsc)?;
                self.m_pending_vvsc = Some(buf);
                self.m_state_flag.insert(StateFlags::KvvscUpdated);
            } else {
                unsafe {
                    let _ = save_vid_verification_element_to_storage(
                        self.m_storage.as_mut().unwrap(),
                        fabric_index,
                        VidVerificationElement::Kvvsc,
                        vvsc,
                    )?;
                }
            }
        }

        chip_ok!()
    }

    fn update_vid_verification_statement_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        vid_verification_statement: &[u8],
    ) -> ChipErrorResult {
        self.basic_vid_verification_assumptions_are_met(fabric_index)?;
        verify_or_return_error!(
            vid_verification_statement.is_empty()
                || vid_verification_statement.len() == K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE,
            Err(chip_error_invalid_argument!())
        );

        if vid_verification_statement.is_empty() {
            if fabric_index == self.m_pending_fabric_index {
                self.m_pending_vid_verification_statement = None;
                self.m_state_flag
                    .insert(StateFlags::KvidVerificationStatementUpdated);
            } else {
                unsafe {
                    let _ = delete_vid_verification_element_from_storage(
                        self.m_storage.as_mut().unwrap(),
                        fabric_index,
                        VidVerificationElement::KvidVerificationStatement,
                    );
                }
            }
        } else {
            if fabric_index == self.m_pending_fabric_index {
                let mut buf = CertBuffer::default();
                buf.init(vid_verification_statement)?;
                self.m_pending_vid_verification_statement = Some(buf);
                self.m_state_flag
                    .insert(StateFlags::KvidVerificationStatementUpdated);
            } else {
                unsafe {
                    let _ = save_vid_verification_element_to_storage(
                        self.m_storage.as_mut().unwrap(),
                        fabric_index,
                        VidVerificationElement::KvidVerificationStatement,
                        vid_verification_statement,
                    );
                }
            }
        }

        chip_ok!()
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
            self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
        }

        self.m_state_flag.remove(StateFlags::KaddNewOpCertsCalled);
        self.m_state_flag.remove(StateFlags::KupdateOpCertsCalled);
        self.revert_vid_verification_statement();
    }

    fn get_certificate(
        &self,
        fabric_index: FabricIndex,
        element: CertChainElement,
        out_certificate: &mut [u8],
    ) -> Result<usize, ChipError> {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );
        // Handle case of pending data
        match self.get_pending_certificate(fabric_index, element, out_certificate) {
            Ok(length) => {
                return Ok(length);
            }
            Err(e) => {
                let not_found = chip_error_not_found!();
                if e != chip_error_not_found!() {
                    return Err(e);
                }

                // now we have not_found error
                // If we have a pending NOC and no pending ICAC, don't delegate to storage, return not found here
                // since in the pending state, there truly is nothing.
                if element == CertChainElement::Kicac && self.m_pending_noc.is_some() {
                    // Don't delegate to storage if we just have a pending NOC and are missing the ICAC
                    return Err(not_found);
                }
            }
        }

        // Not found in pending, let's look in persisted
        unsafe {
            return load_cert_from_stroage(
                self.m_storage.as_mut().unwrap(),
                fabric_index,
                element,
                out_certificate,
            );
        }
    }

    fn get_vid_verification_element(
        &self,
        fabric_index: FabricIndex,
        element: VidVerificationElement,
        out_certificate: &mut [u8],
    ) -> Result<usize, ChipError> {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        let mut key_name: StorageKeyName = StorageKeyName::default();

        if element == VidVerificationElement::KvidVerificationStatement {
            if self
                .m_state_flag
                .contains(StateFlags::KvidVerificationStatementUpdated)
                && fabric_index == self.m_pending_fabric_index
            {
                if let Some(cert) = self.m_pending_vid_verification_statement.as_ref() {
                    out_certificate[0..cert.length()].copy_from_slice(cert.const_bytes());
                    return Ok(cert.length());
                }
            }
            key_name = DefaultStorageKeyAllocator::fabric_vid_verification_statement(fabric_index);
        } else if element == VidVerificationElement::Kvvsc {
            if self.m_state_flag.contains(StateFlags::KvvscUpdated)
                && fabric_index == self.m_pending_fabric_index
            {
                if let Some(cert) = self.m_pending_vvsc.as_ref() {
                    out_certificate[0..cert.length()].copy_from_slice(cert.const_bytes());
                    return Ok(cert.length());
                }
            }
            key_name = DefaultStorageKeyAllocator::fabric_vvsc(fabric_index);
        }

        if key_name.is_uninitialized() {
            return Err(chip_error_invalid_argument!());
        }

        unsafe {
            let err = self
                .m_storage
                .as_ref()
                .unwrap()
                .sync_get_key_value(key_name.key_name_str(), out_certificate);

            if err.as_ref().is_err_and(|e| {
                *e == chip_error_persisted_storage_value_not_found!()
                    || *e == chip_error_not_found!()
            }) {
                out_certificate.fill(0);
                return Ok(0);
            }

            return err;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::chip_lib::core::data_model_types::KMIN_VALID_FABRIC_INDEX;
    use crate::chip::chip_lib::support::test_persistent_storage::TestPersistentStorage;
    use core::ptr;

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
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );
        assert_eq!(
            false,
            store.has_any_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX)
        );

        let mut cert = CertBuffer::default();
        let _ = cert.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &cert.const_bytes()[..cert.length()]
                )
                .is_ok()
        );
        assert_eq!(
            true,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );
        assert_eq!(
            true,
            store.has_any_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX)
        );
    }

    #[test]
    fn cannot_add_root_cert_twice() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut cert = CertBuffer::default();
        let _ = cert.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &cert.const_bytes()[..cert.length()]
                )
                .is_ok()
        );
        assert_eq!(
            false,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &cert.const_bytes()[..cert.length()]
                )
                .is_ok()
        );
    }

    #[test]
    fn cannot_add_empty_root_cert() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(0, CertChainElement::Krcac)
        );

        let cert = CertBuffer::default();

        assert_eq!(
            false,
            store
                .add_new_trusted_root_cert_for_fabric(0, &cert.const_bytes()[..cert.length()])
                .is_ok()
        );
    }

    #[test]
    fn add_noc_cert() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &root_cert.const_bytes()[..root_cert.length()]
                )
                .is_ok()
        );

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes()[..noc_cert.length()],
                    &icac_cert.const_bytes()[..icac_cert.length()]
                )
                .is_ok()
        );
    }

    #[test]
    fn add_noc_cert_with_root() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(
            false,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes()[..noc_cert.length()],
                    &icac_cert.const_bytes()[..icac_cert.length()]
                )
                .is_ok()
        );
    }

    #[test]
    fn cannot_add_noc_cert_twice() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &root_cert.const_bytes()[..root_cert.length()]
                )
                .is_ok()
        );

        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[1]);

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes()[..noc_cert.length()],
                    &icac_cert.const_bytes()[..icac_cert.length()]
                )
                .is_ok()
        );
        assert_eq!(
            false,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes()[..noc_cert.length()],
                    &icac_cert.const_bytes()[..icac_cert.length()]
                )
                .is_ok()
        );
    }

    #[test]
    fn add_noc_cert_without_icac() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &root_cert.const_bytes()[..root_cert.length()]
                )
                .is_ok()
        );

        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes()[..noc_cert.length()],
                    &[]
                )
                .is_ok()
        );
    }

    #[test]
    fn add_empty_noc_icac() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        let mut root_cert = CertBuffer::default();
        let _ = root_cert.init(&[1]);

        //  must insert root first
        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &root_cert.const_bytes()[..root_cert.length()]
                )
                .is_ok()
        );

        assert_eq!(
            false,
            store
                .add_new_op_certs_for_fabric(KMIN_VALID_FABRIC_INDEX, &[], &[])
                .is_ok()
        );
    }

    #[test]
    fn update_noc_cert() {
        // TODO: test this after we can commit the pending certs
    }

    #[test]
    fn update_vvsc() {
        // TODO: test this after we can commit the pending certs
    }

    #[test]
    fn update_vid_verification_statement() {
        // TODO: test this after we can commit the pending certs
    }

    #[test]
    fn commit_vid_verification_for_fabric() {
        // TODO: test this after we can commit the pending certs
    }

    #[test]
    fn commit_cert_for_fabric() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_for_fabric_but_noc_save_failed() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        // posion noc key so that the pa will reject the noc key name
        let noc_key = get_storage_key_for_cert(KMIN_VALID_FABRIC_INDEX, CertChainElement::Knoc)
            .unwrap_or(StorageKeyName::default());
        pa.add_posion_key(noc_key.key_name_str());

        // commit
        assert_eq!(
            false,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_for_fabric_but_icac_save_failed() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        // posion noc key so that the pa will reject the noc key name
        let icac_key = get_storage_key_for_cert(KMIN_VALID_FABRIC_INDEX, CertChainElement::Kicac)
            .unwrap_or(StorageKeyName::default());
        pa.add_posion_key(icac_key.key_name_str());

        // commit
        assert_eq!(
            false,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_for_fabric_but_rcac_save_failed() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        // posion rcac key so that the pa will reject the noc key name
        let rcac_key = get_storage_key_for_cert(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
            .unwrap_or(StorageKeyName::default());
        pa.add_posion_key(rcac_key.key_name_str());

        // commit
        assert_eq!(
            false,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_and_vcs_vvsc_for_fabric() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_and_vcs_vvsc_for_fabric_but_vvsc_failed() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        let storage_key =
            DefaultStorageKeyAllocator::fabric_vid_verification_statement(KMIN_VALID_FABRIC_INDEX);
        pa.add_posion_key(storage_key.key_name_str());

        // commit
        assert_eq!(
            false,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn commit_cert_and_vcs_vvsc_for_fabric_but_vvs_failed() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        let storage_key = DefaultStorageKeyAllocator::fabric_vvsc(KMIN_VALID_FABRIC_INDEX);
        pa.add_posion_key(storage_key.key_name_str());

        // commit
        assert_eq!(
            false,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
    }

    #[test]
    fn remove_all_certs() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(0, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );
        // remove
        assert_eq!(
            true,
            store
                .remove_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .inspect_err(|e| println!("{:?}", e))
                .is_ok()
        );
        assert_eq!(
            false,
            store.has_any_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX)
        );
    }

    #[test]
    fn remove_empty_index() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));

        // remove
        assert_eq!(
            false,
            store
                .remove_certs_for_fabric(0)
                .inspect_err(|e| println!("{:?}", e))
                .is_ok()
        );
    }

    #[test]
    fn remove_pending_certs() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // remove
        assert_eq!(
            true,
            store
                .remove_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .inspect_err(|e| println!("{:?}", e))
                .is_ok()
        );
        assert_eq!(
            false,
            store.has_any_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX)
        );
    }

    #[test]
    fn commit_and_get() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            true,
            store
                .get_certificate(KMIN_VALID_FABRIC_INDEX, CertChainElement::Knoc, &mut out)
                .is_ok_and(|l| l == 1)
        );
    }

    #[test]
    fn get_pending_noc() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            true,
            store
                .get_certificate(KMIN_VALID_FABRIC_INDEX, CertChainElement::Knoc, &mut out)
                .is_ok_and(|l| l == 1)
        );
    }

    #[test]
    fn get_empty_fabric_index() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            false,
            store
                .get_certificate(
                    KMIN_VALID_FABRIC_INDEX + 1,
                    CertChainElement::Knoc,
                    &mut out
                )
                .is_ok()
        );
    }

    #[test]
    fn commit_and_get_vvsc() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            true,
            store
                .get_vid_verification_element(
                    KMIN_VALID_FABRIC_INDEX,
                    VidVerificationElement::Kvvsc,
                    &mut out
                )
                .is_ok_and(|l| l == 1)
        );
    }

    #[test]
    fn commit_and_get_vvsc_empty_fabric() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // commit
        assert_eq!(
            true,
            store
                .commit_certs_for_fabric(KMIN_VALID_FABRIC_INDEX)
                .is_ok()
        );

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            true,
            store
                .get_vid_verification_element(
                    KMIN_VALID_FABRIC_INDEX + 1,
                    VidVerificationElement::Kvvsc,
                    &mut out
                )
                .is_ok_and(|l| l == 0)
        );
    }

    #[test]
    fn commit_and_get_pending_vvsc() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(ptr::addr_of_mut!(pa));
        assert_eq!(
            false,
            store.has_certificate_for_fabric(KMIN_VALID_FABRIC_INDEX, CertChainElement::Krcac)
        );

        // add root
        let mut rcac = CertBuffer::default();
        let _ = rcac.init(&[1]);

        assert_eq!(
            true,
            store
                .add_new_trusted_root_cert_for_fabric(KMIN_VALID_FABRIC_INDEX, &rcac.const_bytes())
                .is_ok()
        );

        // add icac and no
        let mut icac_cert = CertBuffer::default();
        let _ = icac_cert.init(&[2]);
        let mut noc_cert = CertBuffer::default();
        let _ = noc_cert.init(&[3]);
        assert_eq!(
            true,
            store
                .add_new_op_certs_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    &noc_cert.const_bytes(),
                    &icac_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvsc_cert = CertBuffer::default();
        let _ = vvsc_cert.init(&[4]);
        assert_eq!(
            true,
            store
                .update_vid_verification_signer_cert_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvsc_cert.const_bytes()
                )
                .is_ok()
        );

        let mut vvs_cert = CertBuffer::default();
        let _ = vvs_cert.init(&[0; K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE]);
        assert_eq!(
            true,
            store
                .update_vid_verification_statement_for_fabric(
                    KMIN_VALID_FABRIC_INDEX,
                    vvs_cert.const_bytes()
                )
                .is_ok()
        );
        assert_eq!(true, store.has_pending_vid_verification_elements());

        // get
        let mut out: [u8; 1] = [0; 1];
        assert_eq!(
            true,
            store
                .get_vid_verification_element(
                    KMIN_VALID_FABRIC_INDEX,
                    VidVerificationElement::Kvvsc,
                    &mut out
                )
                .is_ok_and(|l| l == 1)
        );
    }
} // end of tests
