use super::ip_address::IPAddress;

pub struct IPPacketInfo
{
    pub src_address: IPAddress,
    pub dest_address: IPAddress,
    pub src_port: u16,
    pub dest_port: u16
}

impl IPPacketInfo
{
    pub fn clear(&mut self) {
        self.src_address = IPAddress::Any;
        self.dest_address = IPAddress::Any;
        self.src_port = 0;
        self.dest_port = 0;
    }
}
