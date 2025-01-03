use create::chip::*;

#[repr(u8)]
pub enum Type
{
    kUndefined,
    kUdp,
    kBle,
    kTcp,
    kWiFiPAF,
    kLast = kWiFiPAF, // This is not an actual transport type, it just refers to the last transport type
};

pub struct PeerAddress
{
    m_transport_type: Type,
    m_remote_id: NodeId,
};

impl PeerAddress
{
    pub fn default() -> Self {
        Self { m_transport_type: Type::kUndefined, m_remote_id: 0 }
    }

    pub fn new_full_address(the_type: Type, id: NodeId) -> Self {
        Self { m_transport_type: the_type, m_remote_id: id }
    }

    pub fn get_remote_id(&self) -> NodeId {
        self.m_remote_id
    }

    pub fn get_transport_type(&self) -> Type {
        self.m_transport_type
    }

    pub fn set_transport_type(self, the_type: Type) -> Self {
        Self { m_transport_type: the_type, m_remote_id: self.m_remote_id}
    }
};
