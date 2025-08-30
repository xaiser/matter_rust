use crate::chip::chip_lib::core::{
    chip_persistent_storage_delegate::PersistentStorageDelegate,
    data_model_types::{FabricIndex, KUNDEFINED_FABRIC_INDEX},
};
use crate::chip::credentials::{self, OperationalCertificateStore};

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use bitflags::{bitflags, Flags};

const DUMMY_CERT_SIZE: usize = 4;

bitflags! {
    #[derive(Copy,Clone)]
    struct StateFlags: u8 {
        const KaddNewOpCertsCalled = 1;
        const KaddNewTrustedRootCalled = 2;
        const KupdateOpCertsCalled = 4;
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
    m_state_flag: StateFlags,
}
