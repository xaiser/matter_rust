use core::fmt;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogCategory {
    KLogCategoryNone = 0,
    KLogCategoryError = 1,
    KLogCategoryProgress = 2,
    KLogCategoryDetail = 3,
    KLogCategoryAutomation = 4,
    KLogCategoryMax = 5,
}

impl core::str::FromStr for LogCategory {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "KLogCategoryNone" => Ok(LogCategory::KLogCategoryNone),
            "KLogCategoryError" => Ok(LogCategory::KLogCategoryError),
            "KLogCategoryProgress" => Ok(LogCategory::KLogCategoryProgress),
            "KLogCategoryDetail" => Ok(LogCategory::KLogCategoryDetail),
            "KLogCategoryAutomation" => Ok(LogCategory::KLogCategoryAutomation),
            "KLogCategoryMax" => Ok(LogCategory::KLogCategoryMax),
            _ => {
                panic!("invalid enum str {}", s);
            }
        }
    }
}

impl core::fmt::Display for LogCategory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LogCategory::KLogCategoryNone => write!(f, "KLogCategoryNone"),
            LogCategory::KLogCategoryError => write!(f, "KLogCategoryError"),
            LogCategory::KLogCategoryProgress => write!(f, "KLogCategoryProgress"),
            LogCategory::KLogCategoryDetail => write!(f, "KLogCategoryDetail"),
            LogCategory::KLogCategoryAutomation => write!(f, "KLogCategoryAutomation"),
            LogCategory::KLogCategoryMax => write!(f, "KLogCategoryMax"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogModule {
    KLogModuleNotSpecified = 0,

    KLogModuleInet,
    KLogModuleBle,
    KLogModuleMessageLayer,
    KLogModuleSecurityManager,
    KLogModuleExchangeManager,
    KLogModuleTLV,
    KLogModuleASN1,
    KLogModuleCrypto,
    KLogModuleController,
    KLogModuleAlarm,
    KLogModuleSecureChannel,
    KLogModuleBDX,
    KLogModuleDataManagement,
    KLogModuleDeviceControl,
    KLogModuleDeviceDescription,
    KLogModuleEcho,
    KLogModuleFabricProvisioning,
    KLogModuleNetworkProvisioning,
    KLogModuleServiceDirectory,
    KLogModuleServiceProvisioning,
    KLogModuleSoftwareUpdate,
    KLogModuleFailSafe,
    KLogModuleTimeService,
    KLogModuleHeartbeat,
    KLogModulechipSystemLayer,
    KLogModuleEventLogging,
    KLogModuleSupport,
    KLogModulechipTool,
    KLogModuleZcl,
    KLogModuleShell,
    KLogModuleDeviceLayer,
    KLogModuleSetupPayload,
    KLogModuleAppServer,
    KLogModuleDiscovery,
    KLogModuleInteractionModel,
    KLogModuleTest,
    KLogModuleOperationalSessionSetup,
    KLogModuleAutomation,
    KLogModuleCASESessionManager,

    KLogModuleMax,
}

impl core::str::FromStr for LogModule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "KLogModuleNotSpecified" => Ok(LogModule::KLogModuleNotSpecified),
            "KLogModuleInet" => Ok(LogModule::KLogModuleInet),
            "KLogModuleBle" => Ok(LogModule::KLogModuleBle),
            "KLogModuleMessageLayer" => Ok(LogModule::KLogModuleMessageLayer),
            "KLogModuleSecurityManager" => Ok(LogModule::KLogModuleSecurityManager),
            "KLogModuleExchangeManager" => Ok(LogModule::KLogModuleExchangeManager),
            "KLogModuleTLV" => Ok(LogModule::KLogModuleTLV),
            "KLogModuleASN1" => Ok(LogModule::KLogModuleASN1),
            "KLogModuleCrypto" => Ok(LogModule::KLogModuleCrypto),
            "KLogModuleController" => Ok(LogModule::KLogModuleController),
            "KLogModuleAlarm" => Ok(LogModule::KLogModuleAlarm),
            "KLogModuleSecureChannel" => Ok(LogModule::KLogModuleSecureChannel),
            "KLogModuleBDX" => Ok(LogModule::KLogModuleBDX),
            "KLogModuleDataManagement" => Ok(LogModule::KLogModuleDataManagement),
            "KLogModuleDeviceControl" => Ok(LogModule::KLogModuleDeviceControl),
            "KLogModuleDeviceDescription" => Ok(LogModule::KLogModuleDeviceDescription),
            "KLogModuleEcho" => Ok(LogModule::KLogModuleEcho),
            "KLogModuleFabricProvisioning" => Ok(LogModule::KLogModuleFabricProvisioning),
            "KLogModuleNetworkProvisioning" => Ok(LogModule::KLogModuleNetworkProvisioning),
            "KLogModuleServiceDirectory" => Ok(LogModule::KLogModuleServiceDirectory),
            "KLogModuleServiceProvisioning" => Ok(LogModule::KLogModuleServiceProvisioning),
            "KLogModuleSoftwareUpdate" => Ok(LogModule::KLogModuleSoftwareUpdate),
            "KLogModuleFailSafe" => Ok(LogModule::KLogModuleFailSafe),
            "KLogModuleTimeService" => Ok(LogModule::KLogModuleTimeService),
            "KLogModuleHeartbeat" => Ok(LogModule::KLogModuleHeartbeat),
            "KLogModulechipSystemLayer" => Ok(LogModule::KLogModulechipSystemLayer),
            "KLogModuleEventLogging" => Ok(LogModule::KLogModuleEventLogging),
            "KLogModuleSupport" => Ok(LogModule::KLogModuleSupport),
            "KLogModulechipTool" => Ok(LogModule::KLogModulechipTool),
            "KLogModuleZcl" => Ok(LogModule::KLogModuleZcl),
            "KLogModuleShell" => Ok(LogModule::KLogModuleShell),
            "KLogModuleDeviceLayer" => Ok(LogModule::KLogModuleDeviceLayer),
            "KLogModuleSetupPayload" => Ok(LogModule::KLogModuleSetupPayload),
            "KLogModuleAppServer" => Ok(LogModule::KLogModuleAppServer),
            "KLogModuleDiscovery" => Ok(LogModule::KLogModuleDiscovery),
            "KLogModuleInteractionModel" => Ok(LogModule::KLogModuleInteractionModel),
            "KLogModuleTest" => Ok(LogModule::KLogModuleTest),
            "KLogModuleOperationalSessionSetup" => Ok(LogModule::KLogModuleOperationalSessionSetup),
            "KLogModuleAutomation" => Ok(LogModule::KLogModuleAutomation),
            "KLogModuleCASESessionManager" => Ok(LogModule::KLogModuleCASESessionManager),
            "KLogModuleMax" => Ok(LogModule::KLogModuleMax),
            _ => {
                panic!("invalid enum str {}", s);
                //Err(())  // If no match is found, return Err(())
            }
        }
    }
}
