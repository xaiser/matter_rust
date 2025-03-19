use crate::chip::VendorId;

#[derive(Debug,PartialEq,Copy,Clone)]
pub struct Id {
    m_vendor_id: VendorId,
    m_protocol_id: u16,
}

impl Id {
    pub const KVENDOR_ID_SHIFT: u32 = 16;
    pub const fn const_default(vendor_id: VendorId, protocol_id: u16) -> Self {
        Id {
            m_vendor_id: vendor_id,
            m_protocol_id: protocol_id,
        }
    }
    pub fn default(vendor_id: VendorId, protocol_id: u16) -> Self {
        Id {
            m_vendor_id: vendor_id,
            m_protocol_id: protocol_id,
        }
    }

    pub const fn const_not_specified() -> Self {
        Id {
            m_vendor_id: VendorId::NotSpecified,
            m_protocol_id: 0xFFFF,
        }
    }

    pub fn get_vendor_id(&self) -> VendorId {
        self.m_vendor_id.clone()
    }

    pub fn get_protocol_id(&self) -> u16 {
        self.m_protocol_id
    }

    fn to_uint32(&self) -> u32 {
        return (self.m_vendor_id as u32) << Self::KVENDOR_ID_SHIFT | (self.m_protocol_id as u32);
    }
}

macro_rules! chip_standard_protocol {
    ($name:ident, $id:expr) => {
        pub mod $name {
            use crate::chip::VendorId;
            pub const ID: super::Id = super::Id::const_default(VendorId::Common, $id);
        }
    };
}

chip_standard_protocol!(secure_channel, 0x0000);
chip_standard_protocol!(interaction_model, 0x0001);
chip_standard_protocol!(bdx, 0x0002);
chip_standard_protocol!(user_directed_commissioning, 0x0003);
chip_standard_protocol!(echo, 0x0004);

pub const NOT_SPECIFIED: Id = Id::const_not_specified();
