use crate::chip::VendorId;

pub const SUNKNOWN_TYPE_NAME: &str = "----";
pub const NOT_SPECIFIED: Id = Id::const_not_specified();

enum StandardProtocol {
    SecureChannel,
}

impl StandardProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            StandardProtocol::SecureChannel => super::secure_channel::NAME,
            _ => SUNKNOWN_TYPE_NAME,
        }
    }

    pub fn msg_name(&self, msg_type: u8) -> &'static str {
        match self {
            StandardProtocol::SecureChannel => {
                if let Ok(mt) = super::secure_channel::MsgType::try_from(msg_type) {
                    mt.to_string()
                } else {
                    SUNKNOWN_TYPE_NAME
                }
            },
            _ => SUNKNOWN_TYPE_NAME,
        }
    }
}

impl TryFrom<Id> for StandardProtocol {
    type Error = ();

    fn try_from(id: Id) -> Result<StandardProtocol, ()> {
        let val = id.get_protocol_id();

        match val {
            val if val == super::secure_channel::ID.get_protocol_id() => Ok(StandardProtocol::SecureChannel),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
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
}

pub fn get_protocol_name(id: Id) -> &'static str {
    if let Ok(p) = StandardProtocol::try_from(id) {
        p.name()
    } else {
        SUNKNOWN_TYPE_NAME
    }
}

pub fn get_message_type_name<'a>(protocol_id: Id, msg_type: u8) -> &'a str {
    if let Ok(p) = StandardProtocol::try_from(protocol_id) {
        p.msg_name(msg_type)
    } else {
        SUNKNOWN_TYPE_NAME
    }
}

/*
macro_rules! chip_standard_protocol {
    ($name:ident, $id:expr) => {
        pub mod $name {
            use crate::chip::VendorId;
            pub const ID: super::Id = super::Id::const_default(VendorId::Common, $id);
        }
    };
}
*/

//chip_standard_protocol!(secure_channel, 0x0000);
//chip_standard_protocol!(interaction_model, 0x0001);
//chip_standard_protocol!(bdx, 0x0002);
//chip_standard_protocol!(user_directed_commissioning, 0x0003);
//chip_standard_protocol!(echo, 0x0004);

