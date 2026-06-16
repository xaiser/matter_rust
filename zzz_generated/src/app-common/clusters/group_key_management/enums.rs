#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum GroupKeySecurityPolicyEnum {
    KtrustFirst = 0x00,
    KcacheAndSync = 0x01,
    KunknownEnumValue = 0x02,
}

#[repr(u32)]
#[derive(Clone, Copy, PartialEq)]
pub enum Feature {
    KcacheAndSync = 0x01,
}
