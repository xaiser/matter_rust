use crate::chip::{NodeId, FabricIndex};
use crate::chip::chip_lib::core::node_id::{KUNDEFINED_NODE_ID, is_operational_node_id};
use crate::chip::chip_lib::core::data_model_types::KUNDEFINED_FABRIC_INDEX;


#[derive(PartialEq)]
pub struct ScopedNodeId {
    m_node_id: NodeId,
    m_fabric_index: FabricIndex,
}

impl Default for ScopedNodeId {
    fn default() -> Self {
        ScopedNodeId::const_default()
    }
}

impl ScopedNodeId {
    pub const fn const_default() -> Self {
        Self {
            m_node_id: KUNDEFINED_NODE_ID,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
        }
    }

    pub fn default_with_ids(node_id: NodeId, fabric_index: FabricIndex) -> Self {
        Self {
            m_node_id: node_id,
            m_fabric_index: fabric_index
        }
    }

    pub fn get_node_id(&self) -> NodeId {
        self.m_node_id
    }

    pub fn get_fabric_index(&self) -> FabricIndex {
        self.m_fabric_index
    }

    pub fn is_operational(&self) -> bool {
        return (self.m_fabric_index != KUNDEFINED_FABRIC_INDEX) && is_operational_node_id(self.m_node_id);
    }
}

