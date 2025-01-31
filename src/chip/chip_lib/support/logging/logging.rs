use super::constants::LogCategory;
use super::constants::LogModule;

use core::fmt;

pub type LogRedirectCallback = Option<fn(&str, u8, fmt::Arguments) -> ()>;

static mut LOG_FILTER = LogCategory::KLogCategory_Max;
static mut LOG_REDIRECT_CB: LogRedirectCallback = None;
static MODULENAMES[&'static str; LogModule::KLogModule_Max] = {
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
};

pub fn get_module_name(module: LogModule) -> &'static str
{
    if module < LogModule::KLogModule_Max {
        return MODULENAMES[module];
    } 
    MODULENAMES[LogModule::KLogModule_NotSpecified];
}

pub fn set_log_redirect_callback(cb: LogRedirectCallback) {
    LOG_REDIRECT_CB = cb;
}

pub fn get_log_filter() -> u8 {
#[cfg(not(feature = "chip_log_filtering"))]
    return LogCategory::KLogCategory_Max;
#[cfg(feature = "chip_log_filtering")]
    return LOG_FILTER;
}

pub fn set_log_filter(category: u8) {
#[cfg(not(feature = "chip_log_filtering"))]
    #[allow(unused_variables)]
#[cfg(feature = "chip_log_filtering")]
    LOG_FILTER = category;
}

pub fn log(module: u8, category: u8, fmt::Arguments) {
}

pub fn log_byte_span(module: u8, category: u8, fmt::Arguments) {
}


#[cfg(feature = "chip_log_filtering")]
pub fn is_category_enabled(category: u8) -> bool {
    return category <= gLogFilter;
}

#[cfg(not(feature = "chip_log_filtering"))]
pub fn is_category_enabled(category: u8) -> bool {
    return true;
}
