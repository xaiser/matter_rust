#[repr(u8)]
#[derive(PartialEq, PartialOrd)]
pub enum LogCategory
{
    KLogCategoryNone = 0,
    KLogCategoryError = 1,
    KLogCategoryProgress = 2,
    KLogCategoryDetail = 3,
    KLogCategoryAutomation = 4,
    KLogCategoryMax = 5,
}

#[derive(PartialEq, PartialOrd)]
pub enum LogModule
{
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

    KLogModuleMax
}
