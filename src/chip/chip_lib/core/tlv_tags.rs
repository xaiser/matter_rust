#![allow(dead_code)]

use core::ops::Shr;
pub enum TlvCommonProfiles {
    /*
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


#[repr(u8)]
#[derive(Clone,Copy)]
pub enum TLVTagControl
{
    // IMPORTANT: All values here must have no bits in common with specified
    // values of TLVElementType.
    Anonymous              = 0x00,
    ContextSpecific        = 0x20,
    CommonProfile2Bytes   = 0x40,
    CommonProfile4Bytes   = 0x60,
    ImplicitProfile2Bytes = 0x80,
    ImplicitProfile4Bytes = 0xA0,
    FullyQualified6Bytes  = 0xC0,
    FullyQualified8Bytes  = 0xE0
}

impl Shr<u32> for TLVTagControl {
    type Output = u8;

    fn shr(self, rhs: u32) -> Self::Output {
        (self as u8) >> rhs
    }
}

pub enum TLVTagControlMS
{
    KTLVTagControlMask  = 0xE0,
    KTLVTagControlShift = 5
}

#[repr(u32)]
pub enum SpecialTagNumber {
    KContextTagMaxNum = u8::MAX as u32,
    KAnonymousTagNum,
    KUnknownImplicitTagNum
}

#[derive(Default)]
pub struct Tag {

    // The storage of the tag value uses the following encoding:
    //
    //  63                              47                              31
    // +-------------------------------+-------------------------------+----------------------------------------------+
    // | Vendor id (bitwise-negated)   | Profile num (bitwise-negated) | Tag number                                   |
    // +-------------------------------+-------------------------------+----------------------------------------------+
    //
    // Vendor id and profile number are bitwise-negated in order to optimize the code size when
    // using context tags, the most commonly used tags in the SDK.
    pub(super) m_val: u64,
}

impl Tag {
    pub(super) fn default_with_value(val: u64) -> Self {
        Self {
            m_val: val,
        }
    }
    pub(super) const KPROFILE_ID_SHIFT: u32 = 32;
    pub(super) const KVENDOR_ID_SHIFT: u32 = 48;
    pub(super) const KSPECIAL_TAG_PROFILE_ID: u32 = 0xFFFFFFFF;
}

pub fn profile_tag(profile_id: u32, tag_num: u32) -> Tag {
    return Tag::default_with_value(((!profile_id as u64) << Tag::KPROFILE_ID_SHIFT as u8) | tag_num as u64);
}

pub fn profile_tag_vendor_id(vendor_id: u16, profile_num: u16, tag_num: u32) -> Tag {
    const K_VENDOR_ID_SHIFT: u32 = Tag::KVENDOR_ID_SHIFT - Tag::KPROFILE_ID_SHIFT;

    return profile_tag((vendor_id as u32) << K_VENDOR_ID_SHIFT as u8 | (profile_num as u32), tag_num);
}

pub fn context_tag(tag_num: u8) -> Tag {
    return profile_tag(Tag::KSPECIAL_TAG_PROFILE_ID, tag_num as u32);
}

pub fn common_tag(tag_num: u32) -> Tag {
    return profile_tag(TlvCommonProfiles::KcommonProfileId as u32, tag_num);
}

pub fn anonymous_tag() -> Tag {
    return profile_tag(Tag::KSPECIAL_TAG_PROFILE_ID as u32, SpecialTagNumber::KAnonymousTagNum as u32);
}

pub fn unknown_implicit_tag() -> Tag {
    return profile_tag(Tag::KSPECIAL_TAG_PROFILE_ID as u32, SpecialTagNumber::KUnknownImplicitTagNum as u32);
}

pub fn tag_num_from_tag(tag: &Tag) -> u32 {
    return tag.m_val as u32;
}

pub fn profile_id_from_tag(tag: &Tag) -> u32 {
    return !((tag.m_val >> Tag::KPROFILE_ID_SHIFT) as u32);
}

pub fn is_special_tag(tag: &Tag) -> bool {
    return profile_id_from_tag(tag) == Tag::KSPECIAL_TAG_PROFILE_ID;
}
