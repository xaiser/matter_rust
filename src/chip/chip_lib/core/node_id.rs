pub type NodeId = u64;

pub const KUNDEFINED_NODE_ID: NodeId = 0;
pub const KMAX_OPERATIONAL_NODE_ID: NodeId = 0xFFFFFFEFFFFFFFFF;

pub fn is_operational_node_id(node_id: NodeId) -> bool {
    return (node_id != KUNDEFINED_NODE_ID) && (node_id <= KMAX_OPERATIONAL_NODE_ID);
}
