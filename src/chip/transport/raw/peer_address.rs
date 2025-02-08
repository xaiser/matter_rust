use crate::chip::NodeId;

pub trait LastTransportType {
    fn last_type(&self) -> Self;
}

#[repr(u8)]
#[derive(Clone,Copy)]
pub enum Type {
    KUndefined,
    KUdp,
    KBle,
    KTcp,
    KWiFiPAF,
}

impl LastTransportType for Type {
    fn last_type(&self) -> Self {
        return Type::KWiFiPAF;
    }
}

pub struct PeerAddress {
    m_transport_type: Type,
    m_remote_id: NodeId,
}

impl Default for PeerAddress {
    fn default() -> Self {
        Self { m_transport_type: Type::KUndefined, m_remote_id: 0 }
    }
}

impl PeerAddress {
    pub fn new_full_address(the_type: Type, id: NodeId) -> Self {
        Self { m_transport_type: the_type, m_remote_id: id }
    }

    pub fn get_remote_id(&self) -> NodeId {
        self.m_remote_id
    }

    pub fn get_transport_type(&self) -> Type {
        self.m_transport_type.clone()
    }

    pub fn set_transport_type(self, the_type: Type) -> Self {
        Self { m_transport_type: the_type, m_remote_id: self.m_remote_id}
    }
}
