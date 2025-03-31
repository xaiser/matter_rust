use crate::chip::{NodeId,FabricId,VendorId};

use crate::chip::chip_lib::core::data_model_types::{FabricIndex};

use crate::chip::crypto::crypto_pal::{P256PublicKey,P256Keypair};

use core::cell::UnsafeCell;

const KFABRIC_LABEL_MAX_LENGTH_IN_BYTES: usize = 32;

pub struct FabricInfo {
    m_node_id: NodeId,
    m_fabric_id: FabricId,
    m_compressed_fabric_id: CompressedFabricId,
    m_root_publick_key: P256PublicKey,
    m_fabric_label: [u8, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
    m_fabric_index: FabricIndex,
    m_vendor_id: VendorId,
    m_has_externally_owned_operation_key: bool,
    m_should_advertise_identity: bool,
    m_operation_key: UnsafeCell<* mut P256Keypair>;
}

/*
impl FabricInfo {
    pub const fn const_default() -> Self {
        Self {
            m_node_id: 0,
            m_fabric_id: 0,
            m_compressed_fabric_id: 0,
        }
    }
}
*/
