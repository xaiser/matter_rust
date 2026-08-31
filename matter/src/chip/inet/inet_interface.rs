use core::fmt;

pub enum InterfaceType {
    Unknown,
    Wifi,
    Ethernet,
    Cellular,
    Thread,
}

#[derive(Debug, Clone, Copy)]
pub struct PlatformType(u8);

impl PlatformType {
    pub const fn new() -> Self {
        PlatformType(0)
    }

    pub fn is_present(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for PlatformType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "stub {}", self.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InterfaceId {
    m_platform_interface: PlatformType,
}

impl InterfaceId {
    pub const K_MAX_IF_NAME_LENGTH: u32 = 13;

    pub const fn default() -> Self {
        Self {
            m_platform_interface: PlatformType::new(),
        }
    }

    pub fn is_present(&self) -> bool {
        self.m_platform_interface.is_present()
    }
}

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.m_platform_interface)
    }
}
