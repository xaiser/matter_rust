#[macro_export]
macro_rules! chip_static_assert {
    ($cond:expr, $msg:expr) => {
        const _: () = {
            if !$cond {
                panic!($msg);
            }
        };
    };
    ($cond:expr) => {
        const _: () = {
            if !$cond {
                panic!("Static assertion failed!");
            }
        };
    };
}
