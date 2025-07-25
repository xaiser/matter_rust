#[macro_export]
macro_rules! chip_inet_error {
    ($e: expr) => {
        chip_sdk_error!(crate::chip_error::SdkPart::KInet, ($e))
    };
}

#[macro_export]
macro_rules! inet_error_wrong_address_type {
    () => {
        chip_inet_error!(0x01)
    };
}

#[macro_export]
macro_rules! inet_error_unknown_interface {
    () => {
        chip_inet_error!(0x0e)
    };
}
