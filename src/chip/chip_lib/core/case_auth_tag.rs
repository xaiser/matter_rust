// Just mock it first
pub struct CatValues(u8);

pub type CaseAuthTag = u32;

const KtagVersionMask: crate::chip::NodeId = 0x0000_0000_0000_FFFF;

pub fn is_valid_case_auth_tag(a_cat: CaseAuthTag) -> bool {
    a_cat & (KtagVersionMask as u32) > 0
}
