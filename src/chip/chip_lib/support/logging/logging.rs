use super::constants::LogCategory;
use super::constants::LogModule;

use core::fmt;

pub type LogRedirectCallback = Option<fn(&str, u8, fmt::Arguments) -> ()>;

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

pub fn log(module: LogModule, category: u8, args: fmt::Arguments) {
    let module_name = get_module_name(module);
    unsafe {
        let redirect = LOG_REDIRECT_CB.clone();

        if redirect.is_none() == true {
            //platform::logV(module_name, category, args);
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
pub fn is_category_enabled(category: u8) -> bool {
    return category <= gLogFilter;
}

#[cfg(not(feature = "chip_log_filtering"))]
pub fn is_category_enabled(_category: u8) -> bool {
    return true;
}
