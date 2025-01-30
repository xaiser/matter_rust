#[macro_export]
macro_rules! verify_or_return_value {
    ($expr:expr, $value:expr $(, $action:stmt)*) => {
        if !$expr {
            $($action)*
            return $value;
        }
    };
}

#[macro_export]
macro_rules! verify_or_return_error {
    ($expr:expr, $code:expr $(, $action:stmt)*) => {
        verify_or_return_value!($expr, $code $(, $action)*);
    };
}

#[macro_export]
macro_rules! verify_or_die {
    ($expr:expr) => {
        if !$expr {
            panic!();
        }
    };
}
