pub const CHIP_CONFIG_SHA256_CONTEXT_SIZE: usize = (core::mem::size_of::<u32>() * (8 + 2 + 16 + 2)) + core::mem::size_of::<u64>();
pub const CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE: usize = 32+1;
