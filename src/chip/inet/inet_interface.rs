pub enum InterfaceType
{
    Unknown,
    Wifi,
    Ethernet,
    Cellular,
    Thread,
}

pub struct InterfaceId
{
}

impl InterfaceId
{
    pub const K_MAX_IF_NAME_LENGTH: u32 = 13;
}
