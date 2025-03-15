#[derive(PartialEq,Copy,Clone)]
pub enum VendorId {
    Common = 0x0,
    TestVendor1 = 0xFFF1,
    NotSpecified = 0xFFFF
}
