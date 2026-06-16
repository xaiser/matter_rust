pub type FabricId = u64;
pub type CompressedFabricId = u64;
pub type FabricIndex = u8;

pub const KUNDEFINED_FABRIC_ID: FabricId = 0;
pub const KMIN_VALID_FABRIC_INDEX: FabricIndex = 1;
pub const KMAX_VALID_FABRIC_INDEX: FabricIndex = u8::MAX - 1;
pub const KUNDEFINED_COMPRESSED_FABRIC_ID: CompressedFabricId = 0;
pub const KUNDEFINED_FABRIC_INDEX: FabricIndex = 0;

pub fn is_valid_fabric_index(index: FabricIndex) -> bool {
    return index >= KMIN_VALID_FABRIC_INDEX && index <= KMAX_VALID_FABRIC_INDEX;
}

#[inline]
pub fn is_valid_fabric_id(fabrid_id: FabricId) -> bool {
    return fabrid_id != KUNDEFINED_FABRIC_ID;
}
