use crate::chip::{NodeId,FabricId,VendorId};
use crate::chip::chip_lib::core::node_id::KUNDEFINED_NODE_ID;
use crate::chip::chip_lib::core::data_mode_types::{KUNDEFINED_FABRIC_ID, KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX};

use crate::chip::chip_lib::core::data_model_types::{FabricIndex};

use crate::chip::crypto::crypto_pal::{P256PublicKey,P256Keypair};

use core::cell::UnsafeCell;

use core::{ptr,str};

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
            m_fabric_label: [0, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
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
                    str::from_utf8_unchecked(&self.m_fabric_label[..valid_up_to])
                }
            }
        }
    }

    pub fn get_node_id(&self) -> NodeId {
        self.m_node_id
    }


    fn reset(&mut self) {
        self.m_node_id = KUNDEFINED_NODE_ID;
        self.m_fabric_id = KUNDEFINED_FABRIC_ID;
        self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
        self.m_compressed_fabric_id = KUNDEFINED_COMPRESSED_FABRIC_ID;

        self.m_vendor_id = VendorId::NotSpecified;
        self.m_fabric_label = [0, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES];

        if !self.m_has_externally_owned_operation_key && self.m_operation_key.get().is_null() == false {
            // TODO: delete by platform
        }

        self.m_operation_key = UnsafeCell::new(ptr::null_mut());

        self.m_has_externally_owned_operation_key = false;
        self.m_should_advertise_identity = true;

        self.m_node_id = KUNDEFINED_NODE_ID;
        self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
    }
}
