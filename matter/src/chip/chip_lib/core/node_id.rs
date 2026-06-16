use super::group_id::GroupId;

pub type NodeId = u64;

pub const KUNDEFINED_NODE_ID: NodeId = 0;
pub const K_MIN_GROUP_NODE_ID: NodeId = 0xFFFF_FFFF_FFFF_0000;
pub const KMAX_OPERATIONAL_NODE_ID: NodeId = 0xFFFFFFEFFFFFFFFF;

pub const K_MIN_CASE_AUTH_TAG: NodeId = 0xFFFF_FFFD_0000_0000;
pub const K_MAX_CASE_AUTH_TAG: NodeId = 0xFFFF_FFFF_FFFF_FFFF;
pub const K_MASK_CASE_AUTH_TAG: NodeId = 0x0000_0000_FFFF_FFFF;

pub const K_MIN_PAKE_KEY_ID: NodeId = 0xFFFF_FFFB_0000_0000;
pub const K_MAX_PAKE_KEY_ID: NodeId = 0xFFFF_FFFB_FFFF_FFFF;
pub const K_MASK_PAKE_KEY_ID: NodeId = 0x0000_0000_0000_FFFF;
pub const K_MASK_UNUSED_PAKE_KEY_ID: NodeId = 0x0000_0000_FFFF_0000;

pub fn is_operational_node_id(node_id: NodeId) -> bool {
    return (node_id != KUNDEFINED_NODE_ID) && (node_id <= KMAX_OPERATIONAL_NODE_ID);
}

pub fn is_case_auth_tag(node_id: NodeId) -> bool {
    return (node_id >= K_MIN_CASE_AUTH_TAG) && (node_id <= K_MAX_CASE_AUTH_TAG);
}

#[inline]
pub const fn is_pake_key_id(node_id: NodeId) -> bool {
    return (node_id >= K_MIN_PAKE_KEY_ID) && (node_id <= K_MAX_PAKE_KEY_ID);
}

#[inline]
pub const fn node_id_from_group_id(group_id: GroupId) -> NodeId {
    return K_MIN_GROUP_NODE_ID | (group_id as NodeId);
}
