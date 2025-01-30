use super::ip_address::IPAddress;
use super::inet_interface::InterfaceId;

pub struct IPPacketInfo
{
    pub src_address: IPAddress,
    pub dest_address: IPAddress,
    pub interface: Option<InterfaceId>,
    pub src_port: u16,
    pub dest_port: u16
}

impl IPPacketInfo
{
    pub fn default() -> Self {
        IPPacketInfo {
            src_address : IPAddress::ANY,
            dest_address : IPAddress::ANY,
            interface : None,
            src_port : 0,
            dest_port : 0,
        }
    }

    pub fn clear(&mut self) {
        self.src_address = IPAddress::ANY;
        self.dest_address = IPAddress::ANY;
        self.interface = None;
        self.src_port = 0;
        self.dest_port = 0;
    }
}
