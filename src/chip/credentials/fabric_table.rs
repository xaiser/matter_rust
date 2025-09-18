use crate::chip::chip_lib::core::data_model_types::{
    KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX,
};
use crate::chip::chip_lib::core::node_id::{is_operational_node_id, KUNDEFINED_NODE_ID};
use crate::chip::chip_lib::core::{
    chip_config::CHIP_CONFIG_MAX_FABRICS, chip_encoding,
    chip_persistent_storage_delegate::PersistentStorageDelegate,
};
use crate::chip::{CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId};

use crate::chip::chip_lib::core::data_model_types::FabricIndex;

use crate::chip::crypto::{
    self,
    crypto_pal::{P256EcdsaSignature, P256Keypair, P256PublicKey},
};

use crate::chip::credentials::{self, last_known_good_time::LastKnownGoodTime};

use crate::chip_core_error;
use crate::chip_error_invalid_argument;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::ChipErrorResult;

use core::cell::UnsafeCell;

use bitflags::{bitflags, Flags};
use core::{ptr, str};

const KFABRIC_LABEL_MAX_LENGTH_IN_BYTES: usize = 32;

pub struct FabricInfo {
    m_node_id: NodeId,
    m_fabric_id: FabricId,
    m_compressed_fabric_id: CompressedFabricId,
    m_root_publick_key: P256PublicKey,
    m_fabric_label: [u8; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
    m_fabric_index: FabricIndex,
    m_vendor_id: VendorId,
    m_has_externally_owned_operation_key: bool,
    m_should_advertise_identity: bool,
    m_operation_key: UnsafeCell<*mut P256Keypair>,
}

impl Default for FabricInfo {
    fn default() -> Self {
        FabricInfo::const_default()
    }
}

impl FabricInfo {
    pub const fn const_default() -> Self {
        Self {
            m_node_id: KUNDEFINED_NODE_ID,
            m_fabric_id: KUNDEFINED_FABRIC_ID,
            m_compressed_fabric_id: KUNDEFINED_COMPRESSED_FABRIC_ID,
            m_root_publick_key: P256PublicKey::const_default(),
            m_fabric_label: [0; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_vendor_id: VendorId::NotSpecified,
            m_has_externally_owned_operation_key: false,
            m_should_advertise_identity: true,
            m_operation_key: UnsafeCell::new(ptr::null_mut()),
        }
    }

    pub fn get_fabric_label(&self) -> Option<&str> {
        match str::from_utf8(&self.m_fabric_label[..]) {
            Ok(s) => Some(s),
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                unsafe {
                    Some(str::from_utf8_unchecked(
                        &self.m_fabric_label[..valid_up_to],
                    ))
                }
            }
        }
    }

    pub fn get_node_id(&self) -> NodeId {
        self.m_node_id
    }

    pub fn get_scoped_node_id(&self) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(self.m_node_id, self.m_fabric_index)
    }

    pub fn get_scoped_node_id_for_node(&self, node: NodeId) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(node, self.m_fabric_index)
    }

    pub fn get_fabric_id(&self) -> FabricId {
        self.m_fabric_id
    }

    pub fn get_fabric_index(&self) -> FabricIndex {
        self.m_fabric_index
    }

    pub fn get_compressed_fabric_id(&self) -> CompressedFabricId {
        self.m_compressed_fabric_id
    }

    pub fn get_compressed_fabric_id_bytes(
        &self,
        compressed_fabric_id: &mut [u8],
    ) -> ChipErrorResult {
        verify_or_return_error!(
            compressed_fabric_id.len() == (core::mem::size_of::<u64>()),
            Err(chip_error_invalid_argument!())
        );
        chip_encoding::big_endian::put_u64(compressed_fabric_id, self.get_compressed_fabric_id());
        chip_ok!()
    }

    pub fn fetch_root_pubkey(&self, out_public_key: &mut P256PublicKey) -> ChipErrorResult {
        chip_ok!()
    }

    pub fn get_vendor_id(&self) -> VendorId {
        self.m_vendor_id
    }

    pub fn is_initialized(&self) -> bool {
        return (self.m_fabric_index != KUNDEFINED_FABRIC_INDEX)
            && is_operational_node_id(self.m_node_id);
    }

    pub fn has_operational_key(&self) -> bool {
        unsafe { (*self.m_operation_key.get()).is_null() == false }
    }

    pub fn should_advertise_identity(&self) -> bool {
        self.m_should_advertise_identity
    }
}

mod fabric_info_private {
    use super::FabricInfo;
    use super::KFABRIC_LABEL_MAX_LENGTH_IN_BYTES;

    use crate::chip::chip_lib::core::chip_persistent_storage_delegate::PersistentStorageDelegate;
    use crate::chip::chip_lib::core::data_model_types::{
        FabricIndex, KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX,
    };
    use crate::chip::chip_lib::core::node_id::{is_operational_node_id, KUNDEFINED_NODE_ID};
    use crate::chip::{CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId};

    use crate::chip::crypto::crypto_pal::{
        P256EcdsaSignature, P256Keypair, P256PublicKey, P256SerializedKeypair,
    };
    use crate::chip_core_error;
    use crate::chip_error_invalid_argument;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipErrorResult;

    use core::cell::UnsafeCell;
    use core::{ptr, str};

    pub(super) struct InitParams {
        pub m_node_id: NodeId,
        pub m_fabric_id: FabricId,
        pub m_compressed_fabric_id: CompressedFabricId,
        pub m_root_publick_key: P256PublicKey,
        pub m_fabric_index: FabricIndex,
        pub m_vendor_id: VendorId,
        pub m_has_externally_owned_operation_key: bool,
        pub m_should_advertise_identity: bool,
        pub m_operation_key: *mut P256Keypair,
    }

    impl InitParams {
        pub(super) const fn const_default() -> Self {
            Self {
                m_node_id: KUNDEFINED_NODE_ID,
                m_fabric_id: KUNDEFINED_FABRIC_ID,
                m_compressed_fabric_id: KUNDEFINED_COMPRESSED_FABRIC_ID,
                m_root_publick_key: P256PublicKey::const_default(),
                m_fabric_index: KUNDEFINED_FABRIC_INDEX,
                m_vendor_id: VendorId::NotSpecified,
                m_has_externally_owned_operation_key: false,
                m_should_advertise_identity: true,
                m_operation_key: ptr::null_mut(),
            }
        }

        pub(super) fn are_valid(&self) -> ChipErrorResult {
            verify_or_return_error!(
                (self.m_fabric_id != KUNDEFINED_FABRIC_ID)
                    && (self.m_fabric_index != KUNDEFINED_FABRIC_INDEX),
                Err(chip_error_invalid_argument!())
            );
            verify_or_return_error!(
                is_operational_node_id(self.m_node_id),
                Err(chip_error_invalid_argument!())
            );

            chip_ok!()
        }
    }

    impl FabricInfo {
        pub(super) fn init(&mut self, init_params: InitParams) -> ChipErrorResult {
            init_params.are_valid()?;

            self.reset();

            self.m_node_id = init_params.m_node_id;
            self.m_fabric_id = init_params.m_fabric_id;
            self.m_fabric_index = init_params.m_fabric_index;
            self.m_compressed_fabric_id = init_params.m_compressed_fabric_id;
            self.m_root_publick_key = init_params.m_root_publick_key;
            self.m_vendor_id = init_params.m_vendor_id;
            self.m_should_advertise_identity = init_params.m_should_advertise_identity;

            if init_params.m_operation_key.is_null() == false {
                self.set_externally_owned_operational_keypair(init_params.m_operation_key)?;
            } else {
                self.set_operational_keypair(init_params.m_operation_key)?;
            }

            chip_ok!()
        }

        pub(super) fn set_operational_keypair(
            &mut self,
            keypair: *const P256Keypair,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn set_externally_owned_operational_keypair(
            &mut self,
            keypair: *mut P256Keypair,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn sign_with_op_keypair(
            &self,
            message: &mut [u8],
            out_signature: &mut P256EcdsaSignature,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn reset(&mut self) {
            self.m_node_id = KUNDEFINED_NODE_ID;
            self.m_fabric_id = KUNDEFINED_FABRIC_ID;
            self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
            self.m_compressed_fabric_id = KUNDEFINED_COMPRESSED_FABRIC_ID;

            self.m_vendor_id = VendorId::NotSpecified;
            self.m_fabric_label = [0; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES];

            unsafe {
                if !self.m_has_externally_owned_operation_key
                    && (*self.m_operation_key.get()).is_null() == false
                {
                    // TODO: delete by platform
                }
            }

            self.m_operation_key = UnsafeCell::new(ptr::null_mut());

            self.m_has_externally_owned_operation_key = false;
            self.m_should_advertise_identity = true;

            self.m_node_id = KUNDEFINED_NODE_ID;
            self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
        }

        pub(super) fn set_should_advertise_identity(&mut self, advertise_identity: bool) {
            self.m_should_advertise_identity = advertise_identity;
        }

        pub(super) const fn metadata_tlv_max_size() -> usize {
            tlv_estimate_struct_overhead!(
                core::mem::size_of::<u16>(),
                KFABRIC_LABEL_MAX_LENGTH_IN_BYTES
            )
        }

        pub(super) const fn op_key_tlv_max_size() -> usize {
            tlv_estimate_struct_overhead!(
                core::mem::size_of::<u16>(),
                P256SerializedKeypair::capacity()
            )
        }

        pub(super) fn commit_to_storge<Storage: PersistentStorageDelegate>(
            &self,
            storage: *mut Storage,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn load_from_storge<Storage: PersistentStorageDelegate>(
            &self,
            storage: *mut Storage,
            new_fabric_index: FabricIndex,
            rcac: &[u8],
            noc: &[u8],
        ) -> ChipErrorResult {
            chip_ok!()
        }
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    struct StateFlags: u16 {
        // If true, we are in the process of a fail-safe and there was at least one
        // operation that caused partial data in the fabric table.
        const KisPendingFabricDataPresent = (1u16 << 0);
        const KisTrustedRootPending = (1u16 << 1);
        const KisUpdatePending = (1u16 << 2);
        const KisAddPending = (1u16 << 3);

        // Only true when `AllocatePendingOperationalKey` has been called
        const KisOperationalKeyPending = (1u16 << 4);
        // True if `AllocatePendingOperationalKey` was for an existing fabric
        const KisPendingKeyForUpdateNoc = (1u16 << 5);

        // True if we allow more than one fabric with same root and fabricId in the fabric table
        // for test purposes. This disables a collision check.
        const KareCollidingFabricsIgnored = (1u16 << 6);

        // If set to true (only possible on test builds), will cause `CommitPendingFabricData()` to early
        // return during commit, skipping clean-ups, so that we can validate commit marker fabric removal.
        const KabortCommitForTest = (1u16 << 7);
    }
}

#[derive(Default)]
struct CommitMarker {
    pub fabric_index: FabricIndex,
    pub is_addition: bool,
}

impl CommitMarker {
    pub fn new(fabric_index: FabricIndex, is_addition: bool) -> Self {
        Self {
            fabric_index,
            is_addition,
        }
    }
}

struct Delegate {
    next: *mut Self,
}

pub struct FabricTable<PSD, OK, OCS>
where
    PSD: PersistentStorageDelegate,
    OK: crypto::OperationalKeystore,
    OCS: credentials::OperationalCertificateStore,
{
    m_states: [FabricInfo; CHIP_CONFIG_MAX_FABRICS],
    // Used for UpdateNOC pending fabric updates
    m_pendingFabric: FabricInfo,
    m_storage: *mut PSD,
    m_operational_keystore: *mut OK,
    m_op_cert_store: *mut OCS,
    // FabricTable::Delegate link to first node, since FabricTable::Delegate is a form
    // of intrusive linked-list item.
    m_delegate_list_root: *mut Delegate,

    // When mStateFlags.Has(kIsPendingFabricDataPresent) is true, this holds the index of the fabric
    // for which there is currently pending data.
    m_fabric_index_with_pending_state: FabricIndex,

    // For when a revert occurs during init, so that more clean-up can be scheduled by caller.
    m_deleted_fabric_index_from_init: FabricIndex,

    //create the last known good time
    m_last_known_good_time: LastKnownGoodTime<PSD>,

    // We may not have an mNextAvailableFabricIndex if our table is as large as
    // it can go and is full.
    m_next_available_fabric_index: Option<FabricIndex>,

    m_fabric_count: u8,

    m_state_flag: StateFlags,
}
