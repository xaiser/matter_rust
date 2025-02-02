pub use super::constants::LogCategory;
pub use super::constants::LogModule;
use crate::chip::platform::log_v;

use core::fmt;

pub type LogRedirectCallback = Option<fn(&str, LogCategory, fmt::Arguments) -> ()>;

#[cfg(feature = "chip_log_filtering")]
static mut LOG_FILTER: LogCategory = LogCategory::KLogCategoryMax;

static mut LOG_REDIRECT_CB: LogRedirectCallback = None;
static MODULENAMES: [&'static str; LogModule::KLogModuleMax as usize] = [
    "-",   // None
    "IN",  // Inet
    "BLE", // BLE
    "ML",  // MessageLayer
    "SM",  // SecurityManager
    "EM",  // ExchangeManager
    "TLV", // TLV
    "ASN", // ASN1
    "CR",  // Crypto
    "CTL", // Controller
    "AL",  // Alarm
    "SC",  // SecureChannel
    "BDX", // BulkDataTransfer
    "DMG", // DataManagement
    "DC",  // DeviceControl
    "DD",  // DeviceDescription
    "ECH", // Echo
    "FP",  // FabricProvisioning
    "NP",  // NetworkProvisioning
    "SD",  // ServiceDirectory
    "SP",  // ServiceProvisioning
    "SWU", // SoftwareUpdate
    "FS",  // FailSafe
    "TS",  // TimeService
    "HB",  // Heartbeat
    "CSL", // chipSystemLayer
    "EVL", // Event Logging
    "SPT", // Support
    "TOO", // chipTool
    "ZCL", // Zcl
    "SH",  // Shell
    "DL",  // DeviceLayer
    "SPL", // SetupPayload
    "SVR", // AppServer
    "DIS", // Discovery
    "IM",  // InteractionModel
    "TST", // Test
    "OSS", // OperationalSessionSetup
    "ATM", // Automation
    "CSM", // CASESessionManager
];

macro_rules! chip_internal_log {
    ($mod:ident, $cat:ident, $msg: expr $(, $args: expr)*) => {
        chip_internal_log_impl!($mod, 
            crate::chip::logging::LogCategory::from_str(concat!(stringify!(KLogCategory), stringify!($cat))).unwrap(), 
            $msg $(, $args)*)
    };
}

#[macro_export]
macro_rules! chip_internal_log_impl {
    ($mod:ident, $cat:expr, $msg: expr $(, $args: expr)*) => {
        if crate::chip::logging::is_category_enabled($cat) {
            crate::chip::logging::log(
                crate::chip::logging::LogModule::from_str(concat!(stringify!(KLogModule), stringify!($mod))).unwrap(), 
                $cat,
                format_args!($msg $(, $args)*));
        }
    };
}

fn get_module_name(module: LogModule) -> &'static str
{
    if module < LogModule::KLogModuleMax {
        return MODULENAMES[module as usize];
    } 
    return MODULENAMES[LogModule::KLogModuleNotSpecified as usize];
}

pub fn set_log_redirect_callback(cb: LogRedirectCallback) {
    unsafe {
        LOG_REDIRECT_CB = cb;
    }
}

#[cfg(not(feature = "chip_log_filtering"))]
pub fn get_log_filter() -> u8 {
    return LogCategory::KLogCategoryMax as u8;
}

#[cfg(feature = "chip_log_filtering")]
pub fn get_log_filter() -> u8 {
    return LOG_FILTER;
}

#[cfg(feature = "chip_log_filtering")]
pub fn set_log_filter(category: u8) {
    LOG_FILTER = category;
}

#[cfg(not(feature = "chip_log_filtering"))]
pub fn set_log_filter(_category: u8) {
}

pub fn log(module: LogModule, category: LogCategory, args: fmt::Arguments) {
    let module_name = get_module_name(module);
    unsafe {
        let redirect = LOG_REDIRECT_CB.clone();

        if redirect.is_none() == true {
            log_v(module_name, category, args);
        } else {
            redirect.unwrap()(module_name, category, args);
        }
    }
}

/*
pub fn log_byte_span(module: u8, category: u8, args: fmt::Arguments) {
}
*/

#[cfg(feature = "chip_log_filtering")]
pub fn is_category_enabled(category: LogCategory) -> bool {
    return category <= gLogFilter;
}

#[cfg(not(feature = "chip_log_filtering"))]
pub fn is_category_enabled(_category: LogCategory) -> bool {
    return true;
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod new {
      use super::super::*;
      use std::*;
      use crate::chip::chip_lib::support::logging::constants::LogModule;
      use crate::chip::chip_lib::support::logging::constants::LogCategory;
      use core::str::FromStr;

      #[test]
      fn test_print() {
          //log(LogModule::KLogModuleInet, 2, format_args!("{}", 123));
          //chip_internal_log_impl!(Inet, Progress, "P {}", 123);
          chip_internal_log!(Inet, Progress, "P {}", 123);
          assert_eq!(1,10);
          //assert_eq!(LogModule::KLogModuleInet,LogModule::from_str("KLogModuleInet").unwrap());
      }
  }
}

