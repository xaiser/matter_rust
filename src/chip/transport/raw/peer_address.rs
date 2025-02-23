use crate::chip::NodeId;

use crate::chip::inet::ip_address::IPAddress;
use crate::chip::inet::inet_interface::InterfaceId;

pub trait LastTransportType {
    fn last_type(&self) -> Self;
}

#[repr(u8)]
#[derive(Clone,Copy,PartialEq)]
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

#[derive(Clone, Copy)]
pub struct PeerAddress {
    m_transport_type: Type,
    m_remote_id: NodeId,
    m_ip_address: IPAddress,
    m_interface: InterfaceId,
    m_port: u16,
}

impl Default for PeerAddress {
    fn default() -> Self {
        Self { 
            m_transport_type: Type::KUndefined,
            m_remote_id: 0 ,
            m_ip_address: IPAddress::default(),
            m_interface: InterfaceId::default(),
            m_port: 0,
        }
    }
}

impl PeerAddress {
    /*
    pub fn new_full_address(the_type: Type, id: NodeId) -> Self {
        Self { m_transport_type: the_type, m_remote_id: id }
    }
    */

    pub fn new_addr_type(addr: IPAddress, the_type: Type) -> Self {
        Self { 
            m_transport_type: the_type,
            m_remote_id: 0 ,
            m_ip_address: addr,
            m_interface: InterfaceId::default(),
            m_port: 0,
        }
    }

    pub fn get_remote_id(&self) -> NodeId {
        self.m_remote_id
    }

    pub fn get_transport_type(&self) -> Type {
        self.m_transport_type.clone()
    }

    pub fn get_address(&self) -> IPAddress {
        self.m_ip_address.clone()
    }

    pub fn get_port(&self) -> u16 {
        self.m_port
    }

    pub fn get_interface(&self) -> InterfaceId {
        self.m_interface.clone()
    }

    pub fn set_transport_type(mut self, the_type: Type) -> Self {
        //Self { m_transport_type: the_type, m_remote_id: self.m_remote_id}
        self.m_transport_type = the_type;
        self
    }

    pub fn set_port(mut self, port: u16) -> Self {
        self.m_port = port;
        self
    }

    pub fn set_interface(mut self, interface_id: InterfaceId) -> Self {
        self.m_interface = interface_id;
        self
    }

    pub fn udp(addr: IPAddress) -> Self {
        Self::new_addr_type(addr, Type::KUdp)
    }

    pub fn udp_addr_port_interface(addr: IPAddress, port: u16, interface: InterfaceId) -> Self {
        Self::udp(addr).set_port(port).set_interface(interface)
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  use crate::chip::inet::ip_address::IPAddress;
  //use crate::chip::inet::inet_interface::InterfaceId;

  #[test]
  fn new_udp() {
      let a = PeerAddress::udp(IPAddress::ANY.clone());
      assert_eq!(a.get_address() == IPAddress::ANY.clone(), true);
  }

  #[test]
  fn new_udp_with_addr_port_interface() {
      let a = PeerAddress::udp_addr_port_interface(IPAddress::ANY.clone(), 666, InterfaceId::default());
      assert_eq!(a.get_address(), IPAddress::ANY.clone());
      assert_eq!(a.get_port(), 666);
  }
}
