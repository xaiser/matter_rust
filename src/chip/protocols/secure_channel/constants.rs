#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum MsgType {
    // Message Counter Synchronization Protocol Message Types
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncRsp = 0x01,

    // Reliable Messaging Protocol Message Types
    StandaloneAck = 0x10,

    // Password-based session establishment Message Types
    PbkdfParamRequest  = 0x20,
    PbkdfParamResponse = 0x21,
    PasePake1         = 0x22,
    PasePake2         = 0x23,
    PasePake3         = 0x24,

    // Certificate-based session establishment Message Types
    CaseSigma1       = 0x30,
    CaseSigma2       = 0x31,
    CaseSigma3       = 0x32,
    CaseSigma2Resume = 0x33,

    StatusReport = 0x40,

    IcdCheckIn = 0x50,
}

impl From<MsgType> for u8 {
    fn from(t: MsgType) -> u8 {
        t as u8
    }
}
