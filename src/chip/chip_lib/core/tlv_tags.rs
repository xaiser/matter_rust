pub enum TlvCommonProfiles {
    /**
     * Used to indicate the absence of a profile id in a variable or member.
     * This is essentially the same as kCHIPProfile_NotSpecified defined in CHIPProfiles.h
     */
    KprofileIdNotSpecified = 0xFFFFFFFF,

    KcommonProfileId = 0
}

impl From<u32> for TlvCommonProfiles {
    fn from(value: u32) -> Self {
        match value {
            0x0 => TlvCommonProfiles::KcommonProfileId,
            _ => TlvCommonProfiles::KprofileIdNotSpecified,
        }
    }
}

impl Into<u32> for TlvCommonProfiles {
    fn into(self) -> u32 {
        self as u32
    }
}
