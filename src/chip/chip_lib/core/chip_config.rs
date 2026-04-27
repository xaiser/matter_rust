pub const CHIP_CONFIG_SHA256_CONTEXT_SIZE: usize =
    (core::mem::size_of::<u32>() * (8 + 2 + 16 + 2)) + core::mem::size_of::<u64>();
pub const CHIP_CONFIG_HKDF_KEY_HANDLE_CONTEXT_SIZE: usize = 32 + 1;
pub const CHIP_CONFIG_MAX_FABRICS: usize = 10;
pub const CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES: usize = 5;
pub const CHIP_CONFIG_MAX_EXCHANGE_CONTEXTS: usize = 16;
pub const CHIP_CONFIG_MAX_SECURE_SESSION_POOL_SIZE: usize = CHIP_CONFIG_MAX_FABRICS * 3 + 2;
pub const CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE: usize = 32;
