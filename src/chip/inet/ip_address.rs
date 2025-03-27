use core::fmt;

#[repr(u8)]
#[derive(PartialEq,Clone,Copy,Debug)]
pub enum IPAddressType
{
    KUnknown,
    KIPv4,
    KIPv6,
    KAny,
}

#[derive(PartialEq,Clone,Copy,Debug)]
pub struct IPAddress
{
    pub addr: (u32, u32, u32, u32),
}

impl IPAddress
{
    pub const ANY: IPAddress = IPAddress {
        addr: (0, 0, 0, 0)
    };

    pub const ANY_IPV4: IPAddress = IPAddress {
        addr: (0, 0, 0xFFFF_u32.to_be(), 0)
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

    pub fn ip_type(&self) -> IPAddressType {
        if self.addr == IPAddress::ANY.addr {
            return IPAddressType::KAny;
        }
        if self.addr.0 == 0 && self.addr.1 == 0 && self.addr.2 == 0xFFFF_u32.to_be() {
            return IPAddressType::KIPv4;
        }

        return IPAddressType::KIPv6;
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPAddress ( {}.{}.{}.{} )", self.addr.0, self.addr.1, self.addr.2, self.addr.3)
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

  #[test]
  fn compare_ne() {
      set_up();
      let a = IPAddress::init((0,1,2,4));
      let b = IPAddress::init((0,1,2,3));
      assert_eq!(a != b, true);
  }

  #[test]
  fn compare_any() {
      set_up();
      let a = IPAddress::ANY;
      let b = IPAddress::ANY;
      assert_eq!(a == b, true);
  }
}
