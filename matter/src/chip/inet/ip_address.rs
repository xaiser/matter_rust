use core::fmt;
use bitflags::bitflags;

const NL_INT_IPV6_MCAST_GROUP_LEN_IN_BYTES: usize = 14;

bitflags! {
    #[derive(Copy,Clone)]
    pub struct IPv6MulticastFlag: u8 {
        /* The multicast address is (1) transient (i.e., dynamically-assigned) rather than (0) well-known (i.e, IANA-assigned). */
        const Ktransient  = 0x01;

        /* The multicast address is (1) based on a network prefix. */
        const Kprefix     = 0x02;
    }
}

#[repr(u8)]
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum IPAddressType {
    KUnknown,
    KIPv4,
    KIPv6,
    KAny,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct IPAddress {
    pub addr: (u32, u32, u32, u32),
}

impl IPAddress {
    pub const ANY: IPAddress = IPAddress { addr: (0, 0, 0, 0) };

    pub const ANY_IPV4: IPAddress = IPAddress {
        addr: (0, 0, 0xFFFF_u32.to_be(), 0),
    };

    pub const fn default() -> Self {
        IPAddress { addr: (0, 0, 0, 0) }
    }

    pub const fn init(ip: (u32, u32, u32, u32)) -> Self {
        IPAddress { addr: ip }
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

    pub fn make_ipv6_multicast(flags: IPv6MulticastFlag, scope: u8, group_id: [u8; NL_INT_IPV6_MCAST_GROUP_LEN_IN_BYTES]) -> Self {
        let flags_and_scope: u32 = (((flags.bits() as u32) & 0xF) << 20) | (((scope as u32) & 0xF) << 16);

        IPAddress { addr: ( 
            ((0xFF000000u32 | flags_and_scope) | ((group_id[0] as u32) << 8) | ((group_id[1] as u32) << 0)).to_be(),
            (((group_id[2] as u32) << 24) | ((group_id[3] as u32) << 16) | ((group_id[4] as u32) << 8) | ((group_id[5] as u32) << 0)).to_be(),
            (((group_id[6] as u32) << 24) | ((group_id[7] as u32) << 16) | ((group_id[8] as u32) << 8) | ((group_id[9] as u32) << 0)).to_be(),
            (((group_id[10] as u32) << 24) | ((group_id[11] as u32) << 16) | ((group_id[12] as u32) << 8) | ((group_id[13] as u32) << 0)).to_be()
            )}
    }

    pub fn make_ipv6_prefix_multicast(scope: u8, prefix_length: u8, prefix: u64, group_id: u32) -> Self {
        const RESERVED: u8 = 0;
        const FLAGS: IPv6MulticastFlag = IPv6MulticastFlag::Kprefix;

        let group_ids = [ RESERVED, prefix_length,
        ((prefix & 0xFF00000000000000u64) >> 56) as u8,
        ((prefix & 0x00FF000000000000u64) >> 48) as u8,
        ((prefix & 0x0000FF0000000000u64) >> 40) as u8,
        ((prefix & 0x000000FF00000000u64) >> 32) as u8,
        ((prefix & 0x00000000FF000000u64) >> 24) as u8,
        ((prefix & 0x0000000000FF0000u64) >> 16) as u8,
        ((prefix & 0x000000000000FF00u64) >> 8) as u8,
        ((prefix & 0x00000000000000FFu64) >> 0) as u8,
        ((group_id & 0xFF000000u32) >> 24) as u8,
        ((group_id & 0x00FF0000u32) >> 16) as u8,
        ((group_id & 0x0000FF00u32) >> 8) as u8,
        ((group_id & 0x000000FFu32) >> 0) as u8
        ];

        Self::make_ipv6_multicast(FLAGS, scope, group_ids)
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPAddress ( {}.{}.{}.{} )",
            self.addr.0, self.addr.1, self.addr.2, self.addr.3
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    fn set_up() {}

    #[test]
    fn compare_eq() {
        set_up();
        let a = IPAddress::init((0, 1, 2, 3));
        let b = IPAddress::init((0, 1, 2, 3));
        assert_eq!(a == b, true);
    }

    #[test]
    fn compare_ne() {
        set_up();
        let a = IPAddress::init((0, 1, 2, 4));
        let b = IPAddress::init((0, 1, 2, 3));
        assert_eq!(a != b, true);
    }

    #[test]
    fn compare_any() {
        set_up();
        let a = IPAddress::ANY;
        let b = IPAddress::ANY;
        assert_eq!(a == b, true);
    }

    #[test]
    fn make_ipv6_mlticast_addr() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let scope = 0x5u8;
        let flags = IPv6MulticastFlag::Ktransient;

        let expected = IPAddress::init((0x020115FF, 0x06050403, 0x0a090807, 0x0e0d0c0b));

        assert_eq!(expected, IPAddress::make_ipv6_multicast(flags, scope, group_id));
    }
}
