use crate::chip_sdk_error;

#[macro_export]
macro_rules! chip_asn1_error {
    ($e:expr) => {
        chip_sdk_error!(
            crate::chip::chip_lib::core::chip_error::SdkPart::KASN1,
            ($e)
        )
    };
}

#[macro_export]
macro_rules! asn1_end {
    () => {
        chip_asn1_error!(0x0)
    };
}

#[macro_export]
macro_rules! asn1_error_overflow {
    () => {
        chip_asn1_error!(0x02)
    };
}

#[macro_export]
macro_rules! asn1_error_unsupported_encoding {
    () => {
        chip_asn1_error!(0x06)
    };
}
