pub enum LogCategory
{
    KLogCategory_None = 0,
    KLogCategory_Error = 1,
    KLogCategory_Progress = 2,
    KLogCategory_Detail = 3,
    KLogCategory_Automation = 4,
    KLogCategory_Max = 4,
}

#[derive(PartialEq)]
enum LogModule
{
    KLogModule_NotSpecified = 0,

    KLogModule_Inet,
    KLogModule_Ble,
    KLogModule_MessageLayer,
    KLogModule_SecurityManager,
    KLogModule_ExchangeManager,
    KLogModule_TLV,
    KLogModule_ASN1,
    KLogModule_Crypto,
    KLogModule_Controller,
    KLogModule_Alarm,
    KLogModule_SecureChannel,
    KLogModule_BDX,
    KLogModule_DataManagement,
    KLogModule_DeviceControl,
    KLogModule_DeviceDescription,
    KLogModule_Echo,
    KLogModule_FabricProvisioning,
    KLogModule_NetworkProvisioning,
    KLogModule_ServiceDirectory,
    KLogModule_ServiceProvisioning,
    KLogModule_SoftwareUpdate,
    KLogModule_FailSafe,
    KLogModule_TimeService,
    KLogModule_Heartbeat,
    KLogModule_chipSystemLayer,
    KLogModule_EventLogging,
    KLogModule_Support,
    KLogModule_chipTool,
    KLogModule_Zcl,
    KLogModule_Shell,
    KLogModule_DeviceLayer,
    KLogModule_SetupPayload,
    KLogModule_AppServer,
    KLogModule_Discovery,
    KLogModule_InteractionModel,
    KLogModule_Test,
    KLogModule_OperationalSessionSetup,
    KLogModule_Automation,
    KLogModule_CASESessionManager,

    KLogModule_Max
};
