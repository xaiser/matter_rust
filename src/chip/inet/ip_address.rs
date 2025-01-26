#[repr(u8)]
pub enum IPAddressType
{
    kUnknown,
    kIPv4,
    kIPv6,
    kAny,
}

#[derive(PartialEq)]
pub struct IPAddress
{
    pub addr: (u32, u32, u32, u32),
}

impl IPAddress
{
    pub const Any: IPAddress = IPAddress {
        addr: (0, 0, 0, 0)
    };

    pub const fn default() -> Self {
        IPAddress {
            addr: (0, 0, 0, 0)
        }
    }

    pub const fn init(ip: (u32, u32, u32, u32)) -> Self {
        IPAddress {
            addr: ip,
        }
    }

    pub const fn type(&self) -> IPAddressType {
        if self.addr == IPAddress::Any().addr {
            return IPAddressType::Any;
        }
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  fn set_up() {
  }

  #[test]
  fn compare_eq() {
      set_up();
      let a = IPAddress::init((0,1,2,3));
      let b = IPAddress::init((0,1,2,3));
      assert_eq!(a == b, true);
  }

  fn compare_ne() {
      set_up();
      let a = IPAddress::init((0,1,2,4));
      let b = IPAddress::init((0,1,2,3));
      assert_eq!(a != b, true);
  }
}
