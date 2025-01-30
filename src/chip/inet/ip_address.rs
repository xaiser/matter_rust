#[repr(u8)]
#[derive(PartialEq,Clone,Copy)]
pub enum IPAddressType
{
    KUnknown,
    KIPv4,
    KIPv6,
    KAny,
}

#[derive(PartialEq,Clone,Copy)]
pub struct IPAddress
{
    pub addr: (u32, u32, u32, u32),
}

impl IPAddress
{
    pub const ANY: IPAddress = IPAddress {
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

    pub fn ip_type(&self) -> IPAddressType {
        if self.addr == IPAddress::ANY.addr {
            return IPAddressType::KAny;
        }

        return IPAddressType::KUnknown;
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
