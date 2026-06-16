#[macro_export]
macro_rules! chip_system_align_size {
    ($value: expr, $alignment: expr) => {
        ($value + $alignment - 1) & !($alignment - 1)
    };
}
