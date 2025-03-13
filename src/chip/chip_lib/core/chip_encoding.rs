#![no_std]

use core::convert::{TryFrom, TryInto};

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_u8(in_value: u8) -> u8 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_u8(in_value: u8) -> u8 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_u16(in_value: u16) -> u16 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_u16(in_value: u16) -> u16 {
    let bytes = in_value.to_le_bytes();
    return u16::from_le_bytes(bytes);
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_u32(in_value: u32) -> u32 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_u32(in_value: u32) -> u32 {
    let bytes = in_value.to_le_bytes();
    return u32::from_le_bytes(bytes);
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_u64(in_value: u64) -> u64 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_u64(in_value: u64) -> u64 {
    let bytes = in_value.to_le_bytes();
    return u64::from_le_bytes(bytes);
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_i8(in_value: i8) -> i8 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_i8(in_value: i8) -> i8 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_i16(in_value: i16) -> i16 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_i16(in_value: i16) -> i16 {
    let bytes = in_value.to_le_bytes();
    return i16::from_le_bytes(bytes);
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_i32(in_value: i32) -> i32 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_i32(in_value: i32) -> i32 {
    let bytes = in_value.to_le_bytes();
    return i32::from_le_bytes(bytes);
}

#[cfg(target_endian = "little")]
pub fn swap_little_to_host_i64(in_value: i64) -> i64 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_little_to_host_i64(in_value: i64) -> i64 {
    let bytes = in_value.to_le_bytes();
    return i64::from_le_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_u8(in_value: u8) -> u8 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_u8(in_value: u8) -> u8 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_u16(in_value: u16) -> u16 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_u16(in_value: u16) -> u16 {
    let bytes = in_value.to_be_bytes();
    return u16::from_be_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_u32(in_value: u32) -> u32 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_u32(in_value: u32) -> u32 {
    let bytes = in_value.to_be_bytes();
    return u32::from_be_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_u64(in_value: u64) -> u64 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_u64(in_value: u64) -> u64 {
    let bytes = in_value.to_be_bytes();
    return u64::from_be_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_i8(in_value: i8) -> i8 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_i8(in_value: i8) -> i8 {
    in_value
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_i16(in_value: i16) -> i16 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_i16(in_value: i16) -> i16 {
    let bytes = in_value.to_be_bytes();
    return i16::from_be_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_i32(in_value: i32) -> i32 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_i32(in_value: i32) -> i32 {
    let bytes = in_value.to_be_bytes();
    return i32::from_be_bytes(bytes);
}

#[cfg(target_endian = "big")]
pub fn swap_big_to_host_i64(in_value: i64) -> i64 {
    in_value
}

#[cfg(target_endian = "little")]
pub fn swap_big_to_host_i64(in_value: i64) -> i64 {
    let bytes = in_value.to_be_bytes();
    return i64::from_be_bytes(bytes);
}

pub mod little_endian {
    pub trait HostSwap {
        type ValueType;
        fn host_swap(v: Self::ValueType) -> Self::ValueType;
    }

    impl HostSwap for bool {
        type ValueType = bool;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            v
        }
    }

    impl HostSwap for u8 {
        type ValueType = u8;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_u8(v)
        }
    }

    impl HostSwap for i8 {
        type ValueType = i8;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_i8(v)
        }
    }

    impl HostSwap for u16 {
        type ValueType = u16;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_u16(v)
        }
    }

    impl HostSwap for i16 {
        type ValueType = i16;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_i16(v)
        }
    }

    impl HostSwap for u32 {
        type ValueType = u32;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_u32(v)
        }
    }

    impl HostSwap for i32 {
        type ValueType = i32;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_i32(v)
        }
    }

    impl HostSwap for u64 {
        type ValueType = u64;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_u64(v)
        }
    }

    impl HostSwap for i64 {
        type ValueType = i64;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_little_to_host_i64(v)
        }
    }

}

pub mod big_endian {
    pub trait HostSwap {
        type ValueType;
        fn host_swap(v: Self::ValueType) -> Self::ValueType;
    }

    impl HostSwap for bool {
        type ValueType = bool;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            v
        }
    }

    impl HostSwap for u8 {
        type ValueType = u8;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_u8(v)
        }
    }

    impl HostSwap for i8 {
        type ValueType = i8;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_i8(v)
        }
    }

    impl HostSwap for u16 {
        type ValueType = u16;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_u16(v)
        }
    }

    impl HostSwap for i16 {
        type ValueType = i16;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_i16(v)
        }
    }

    impl HostSwap for u32 {
        type ValueType = u32;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_u32(v)
        }
    }

    impl HostSwap for i32 {
        type ValueType = i32;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_i32(v)
        }
    }

    impl HostSwap for u64 {
        type ValueType = u64;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_u64(v)
        }
    }

    impl HostSwap for i64 {
        type ValueType = i64;
        fn host_swap(v: Self::ValueType) -> Self::ValueType {
            super::swap_big_to_host_i64(v)
        }
    }
}
