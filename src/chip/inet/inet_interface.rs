use core::fmt;

pub enum InterfaceType {
    Unknown,
    Wifi,
    Ethernet,
    Cellular,
    Thread,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InterfaceId {}

impl InterfaceId {
    pub const K_MAX_IF_NAME_LENGTH: u32 = 13;
}

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InterfaceId: default")
    }
}
