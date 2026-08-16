/* NOTE: PeerId should be only used by mDNS, because it contains a compressed fabric id which is not unique, and the compressed
 * fabric id is only used for mDNS announcement. ScopedNodeId which contains a node id and fabirc index, should be used in prefer of
 * PeerId. ScopedNodeId is locally unique.
 */
use crate::{
    chip::{
        chip_lib::{
            core::{
                node_id::KUNDEFINED_NODE_ID,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
            },
        },
        NodeId, CompressedFabricId,
    },
};

#[derive(Debug, Clone)]
pub struct PeerId {
    m_node_id: NodeId,
    m_compressed_fabric_id: CompressedFabricId,
}

impl PeerId {
    pub const fn new() -> Self {
        Self {
            m_node_id: KUNDEFINED_NODE_ID as NodeId,
            m_compressed_fabric_id: KUNDEFINED_FABRIC_INDEX as CompressedFabricId,
        }
    }

    pub const fn new_with(compressed_fabric_id: CompressedFabricId, node_id: NodeId) -> Self {
        Self {
            m_node_id: node_id,
            m_compressed_fabric_id: compressed_fabric_id,
        }
    }

    pub fn get_node_id(&self) -> NodeId {
        self.m_node_id
    }

    pub fn set_node_id(mut self, id: NodeId) -> Self {
        self.m_node_id = id;

        self
    }

    pub fn get_compressed_fabric_id(&self) -> CompressedFabricId { 
        self.m_compressed_fabric_id
    }

    pub fn set_compressed_fabric_id(mut self, id: CompressedFabricId) -> Self {
        self.m_compressed_fabric_id = id;

        self
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        (self.m_node_id == other.m_node_id) && (self.m_compressed_fabric_id == other.m_compressed_fabric_id)
    }
}

impl Eq for PeerId {}
