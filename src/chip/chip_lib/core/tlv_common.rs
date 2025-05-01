#[macro_export]
macro_rules! tlv_estimate_struct_overhead{
    // the basic case
    () => {
        2
    };

    ($first_field_size:expr $(, $other_fileds:expr)*) => {
        $first_field_size + 4 + tlv_estimate_struct_overhead!($($other_fileds),*)
    }
}

pub const KTLVCONTROL_BYTE_NOT_SPECIFIED: u16 = 0xFFFF;

#[cfg(test)]
mod test {
    use super::*;
    use std::*;
    use crate::tlv_estimate_struct_overhead;

    #[test]
    fn one_size() {
        assert_eq!(7, tlv_estimate_struct_overhead!(1));
    }

    #[test]
    fn two_size() {
        assert_eq!((1+4+2+4+2), tlv_estimate_struct_overhead!(1,2));
    }
}
