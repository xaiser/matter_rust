use crate::chip::{
    chip_lib::core::{
        case_auth_tag::CATValues,
        data_model_types::KUNDEFINED_FABRIC_INDEX,
        node_id::KUNDEFINED_NODE_ID,
    },
    access::auth_mode::AuthMode,
    NodeId, FabricIndex,
};

#[derive(Clone, Copy)]
pub struct SubjectDescriptor {
    pub fabric_index: FabricIndex,
    pub auth_mode: AuthMode,
    pub sujbect: NodeId,
    pub cats: CATValues,
    pub is_commissioning: bool,
}

impl SubjectDescriptor {
    pub const fn new() -> Self {
        Self {
            fabric_index: KUNDEFINED_FABRIC_INDEX,
            auth_mode: AuthMode::KNone,
            sujbect: KUNDEFINED_NODE_ID,
            cats: CATValues::new(),
            is_commissioning: false,
        }
    }
}

impl Default for SubjectDescriptor {
    fn default() -> Self {
        Self::new()
    }
}
