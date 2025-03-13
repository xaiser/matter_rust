#[cfg(not(feature = "chip_config_error_source"))]

pub type StorageType = u32;
pub type ValueType = StorageType;
pub type FormatType = StorageType;

#[repr(u8)]
pub enum Range
{
    KSdk        = 0x0, //< CHIP SDK errors.
    KOs         = 0x1, //< Encapsulated OS errors, other than POSIX errno.
    KPosix      = 0x2, //< Encapsulated POSIX errno values.
    KLwIP       = 0x3, //< Encapsulated LwIP errors.
    KOpenThread = 0x4, //< Encapsulated OpenThread errors.
    KPlatform   = 0x5, //< Platform-defined encapsulation.
    KLastRange  = 0x6
}

#[repr(u8)]
pub enum SdkPart
{
    KCore            = 0, //< SDK core errors.
    KInet            = 1, //< Inet layer errors; see <inet/InetError.h>.
    KDevice          = 2, //< Device layer errors; see <platform/CHIPDeviceError.h>.
    KASN1            = 3, //< ASN1 errors; see <asn1/ASN1Error.h>.
    KBLE             = 4, //< BLE layer errors; see <ble/BleError.h>.
    KIMGlobalStatus  = 5, //< Interaction Model global status code.
    KIMClusterStatus = 6, //< Interaction Model cluster-specific status code.
    KApplication     = 7, //< Application-defined errors; see CHIP_APPLICATION_ERROR
}

#[cfg(feature = "chip_config_error_source")]
macro_rules! chip_initialize_error_source {
    ($e:expr, $f:expr, $l:expr) => {
        Self {
            m_error: $e,
            m_file: $f,
            m_line: $l,
        }
    };
}

#[cfg(feature = "chip_config_error_source")]
macro_rules! chip_sdk_error {
    ($part:expr, $code:expr) => {
        crate::chip::chip_lib::core::chip_error::ChipError::new_error_error_source(
            crate::chip::chip_lib::core::chip_error::ChipError::make_integer_with_part_code($part, $code),
            file!(),
            line!())
    };
}

#[cfg(feature = "chip_config_error_source")]
#[macro_export]
macro_rules! chip_no_error {
    () => {
        crate::chip::chip_lib::core::chip_error::ChipError::new_error_error_source(
            0
            file!(),
            line!())
    };
}

#[cfg(not(feature = "chip_config_error_source"))]
macro_rules! chip_initialize_error_source {
    ($e:expr, $_f:expr, $_l:expr) => {
        Self {
            m_error: $e,
        }
    };
}

#[cfg(not(feature = "chip_config_error_source"))]
#[macro_export]
macro_rules! chip_sdk_error {
    ($part:expr, $code:expr) => {
        crate::chip::chip_lib::core::chip_error::ChipError::new_error(
            crate::chip::chip_lib::core::chip_error::ChipError::make_integer_with_part_code($part, $code)
        )
    };
}

#[cfg(not(feature = "chip_config_error_source"))]
#[macro_export]
macro_rules! chip_no_error {
    () => {
        crate::chip::chip_lib::core::chip_error::ChipError::new_error(0)
    };
}

#[macro_export]
macro_rules! chip_core_error{
    ($e:expr) => {
        chip_sdk_error!(crate::chip::chip_lib::core::chip_error::SdkPart::KCore, ($e))
    };
}


#[derive(Debug, Copy, Clone)]
pub struct ChipError 
{
    m_error: StorageType,
#[cfg(feature = "chip_config_error_source")]
    m_file: &'static str,
#[cfg(feature = "chip_config_error_source")]
    m_line: u32,
}

impl PartialEq for ChipError {
    fn eq(&self, other: &Self) -> bool {
        self.m_error == other.m_error
    }
}

impl Eq for ChipError {}

// Currently, Rust cannot use generic template parameter in a const operation.....
// So we just use make_integer directly for now.
/*
pub struct SdkErrorConstant<const PART: u8, const SCODE: StorageType>;

impl<const PART: u8, const SCODE: StorageType> SdkErrorConstant<PART, SCODE>
where
    [(); {
        chip_static_assert!(ChipError::fits_in_field(ChipError::K_SDKPART_LENGTH, PART), "part is too large");
        chip_static_assert!(ChipError::fits_in_field(ChipError::K_SDKCODE_LENGTH, SCODE), "code is too large");
        chip_static_assert!(ChipError::make_integer_with_part_code(PART, SCODE) != 0, "value is zero");
        0
    }]: Sized,
{
    pub const VALUE: u32 = ChipError::make_integer_with_part_code(PART, SCODE);
}

impl<const PART: u8, const SCODE: StorageType> SdkErrorConstant<PART, SCODE>
{
    pub const VALUE: u32 = {
        chip_static_assert!(ChipError::fits_in_field(ChipError::K_SDKPART_LENGTH, PART), "part is too large");
        chip_static_assert!(ChipError::fits_in_field(ChipError::K_SDKCODE_LENGTH, SCODE), "code is too large");
        chip_static_assert!(ChipError::make_integer_with_part_code(PART, SCODE) != 0, "value is zero");

        ChipError::make_integer_with_part_code(PART, SCODE)
    };
}
*/

impl ChipError
{
    const K_RANGE_START: i32 = 24;
    //const K_RANGE_LENGTH: i32 = 8;
    const K_VALUE_START: i32 = 0;
    const K_VALUE_LENGTH: i32 = 24;

    const K_SDKPART_START: i32 = 8;
    pub const K_SDKPART_LENGTH: i32 = 3;
    const K_SDKCODE_START: i32 = 0;
    pub const K_SDKCODE_LENGTH: i32 = 8;

    pub const fn fits_in_field(length: u32, value: StorageType) -> bool {
        return value < (1u32 << length);
    }

    const fn make_mask(start: u32, length: u32) -> StorageType {
        return ((1u32 << length) - 1) << start;
    }

    const fn make_field(start: u32, value: StorageType) -> StorageType {
        return value << start;
    }

    const fn make_integer_with_range_value(range: Range, value: StorageType) -> StorageType {
        return ChipError::make_field(Self::K_RANGE_START as u32, range as StorageType) | 
            ChipError::make_field(Self::K_VALUE_START as u32, value as StorageType);
    }

    pub const fn make_integer_with_part_code(part: SdkPart, code: u8) -> StorageType {
        return Self::make_integer_with_range_value(Range::KSdk, Self::make_field(Self::K_SDKPART_START as u32, part as StorageType)) | 
            Self::make_field(Self::K_SDKCODE_START as u32, code as StorageType);
    }

    pub const fn new_range_value(range: Range, value: ValueType) -> Self {
        return ChipError::new_range_value_error_source(range, value, "", 0);
    }

    #[allow(unused_variables)]
    pub const fn new_range_value_error_source(range: Range, value: ValueType, file: &'static str, line: u32) -> Self {
        chip_initialize_error_source!(Self::make_integer_with_range_value(range, value & Self::make_mask(0, Self::K_VALUE_LENGTH as u32)), 
            file, line)
    }

    pub const fn new_part_code(part: SdkPart, code: u8) -> Self {
        return Self::new_part_code_error_source(part, code, "", 0);
    }

    #[allow(unused_variables)]
    pub const fn new_part_code_error_source(part: SdkPart, code: u8, file: &'static str, line: u32) -> Self {
        chip_initialize_error_source!(Self::make_integer_with_part_code(part, code), file, line)
    }

    pub const fn new_error(error: StorageType) -> Self {
        return Self::new_error_error_source(error, "", 0);
    }

    #[allow(unused_variables)]
    pub const fn new_error_error_source(error: StorageType, file: &'static str, line: u32) -> Self {
        chip_initialize_error_source!(error, file, line)
    }

    pub const fn as_integer(&self) -> StorageType
    {
        return self.m_error;
    }

    pub const fn is_success(&self) -> bool {
        return self.m_error == 0;
    }

    pub const fn format(&self) -> FormatType {
        return self.m_error;
    }

}

// start to create all the error code

#[macro_export]
macro_rules! chip_error_sending_blocked{
    () => {
        chip_core_error!(0x01)
    };
}

#[macro_export]
macro_rules! chip_error_incorrect_state{
    () => {
        chip_core_error!(0x03)
    };
}

#[macro_export]
macro_rules! chip_error_no_message_handler{
    () => {
        chip_core_error!(0x0c)
    };
}

#[macro_export]
macro_rules! chip_error_buffer_too_small{
    () => {
        chip_core_error!(0x19)
    };
}

#[macro_export]
macro_rules! chip_error_end_point_pool_full{
    () => {
        chip_core_error!(0xc1)
    };
}

#[macro_export]
macro_rules! chip_error_inbound_message_too_big{
    () => {
        chip_core_error!(0xc2)
    };
}

#[macro_export]
macro_rules! chip_error_invalid_argument{
    () => {
        chip_core_error!(0x2f)
    };
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod new {
      use super::super::*;
      use std::*;

      fn set_up() {}

      #[test]
      fn new_no_error() {
          set_up();
          let s1 = chip_no_error!();
          let s2 = chip_no_error!();

          assert_eq!(true, s1 == s2);
      }

      #[test]
      fn new_one_error() {
          set_up();
          let s1 = chip_error_sending_blocked!();
          let s2 = chip_error_sending_blocked!();

          assert_eq!(true, s1 == s2);
      }

      #[test]
      fn new_crate_error_type() {
          set_up();
          let s1: crate::ChipError = chip_error_sending_blocked!();
          let s2: crate::ChipError = chip_error_sending_blocked!();

          assert_eq!(true, s1 == s2);
      }
  }
}
