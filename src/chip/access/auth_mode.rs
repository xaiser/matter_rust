#[repr(u8)]
#[derive(Eq, PartialEq, Clone, Copy, Default)]
pub enum AuthMode {
    #[default]
    KNone = 0,
    KInternalDeviceAccess = 1 << 4,
    KPase = 1 << 5,
    KCase = 1 << 6,
    KGroup = 1 << 7,
}
