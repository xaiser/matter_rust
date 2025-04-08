#[macro_export]
macro_rules! tlv_estimate_struct_overhead{
    // the basic case
    () => {
        2
    };

    ($first_field_size:expr $(, $other_fileds:expr)*) => {
        $first_field_size + 4 + tlv_estimate_struct_overhead!($($other_fields),*)
    }
}
