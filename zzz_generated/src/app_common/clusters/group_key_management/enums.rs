#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum GroupKeySecurityPolicyEnum {
    KtrustFirst = 0x00,
    KcacheAndSync = 0x01,
    KunknownEnumValue = 0x02,
}

impl TryFrom<u16> for GroupKeySecurityPolicyEnum {
    type Error = ();

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0 => {
                Ok(GroupKeySecurityPolicyEnum::KtrustFirst)
            },
            1 => {
                Ok(GroupKeySecurityPolicyEnum::KcacheAndSync)
            },
            2 => {
                Ok(GroupKeySecurityPolicyEnum::KunknownEnumValue)
            },
            _ => {
                Err(())
            }
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, PartialEq)]
pub enum Feature {
    KcacheAndSync = 0x01,
}
