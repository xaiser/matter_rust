#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VendorId {
    Common = 0x0,
    TestVendor1 = 0xFFF1,
    NotSpecified = 0xFFFF,
}

impl From<u16> for VendorId {
    fn from(value: u16) -> Self {
        match value {
            0 => VendorId::Common,
            0xFFF1 => VendorId::TestVendor1,
            _ => VendorId::NotSpecified,
        }
    }
}

impl Into<u16> for VendorId {
    fn into(self) -> u16 {
        self as u16
    }
}
