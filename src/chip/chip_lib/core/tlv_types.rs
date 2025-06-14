#[derive(Clone,Copy,PartialEq,PartialOrd,Debug)]
pub enum TlvType {
    KtlvTypeNotSpecified     = -1,
    KtlvTypeUnknownContainer = -2,

    KtlvTypeSignedInteger       = 0x00,
    KtlvTypeUnsignedInteger     = 0x04,
    KtlvTypeBoolean             = 0x08,
    KtlvTypeFloatingPointNumber = 0x0A,
    KtlvTypeUTF8String          = 0x0C,
    KtlvTypeByteString          = 0x10,
    // IMPORTANT: Values starting at Null must match the corresponding values of
    // TLVElementType.
    KtlvTypeNull      = 0x14,
    KtlvTypeStructure = 0x15,
    KtlvTypeArray     = 0x16,
    KtlvTypeList      = 0x17
}

impl From<TlvElementType> for TlvType {
    fn from(elem: TlvElementType) -> Self {
        use TlvElementType::*;
        use TlvType::*;

        match elem {
            NotSpecified => KtlvTypeNotSpecified,
            Int8 | Int16 | Int32 | Int64 => KtlvTypeSignedInteger,
            UInt8 | UInt16 | UInt32 | UInt64 => KtlvTypeUnsignedInteger,
            BooleanFalse | BooleanTrue => KtlvTypeBoolean,
            FloatingPointNumber32 | FloatingPointNumber64 => KtlvTypeFloatingPointNumber,
            UTF8String1ByteLength
                | UTF8String2ByteLength
                | UTF8String4ByteLength
                | UTF8String8ByteLength => KtlvTypeUTF8String,
            ByteString1ByteLength
                | ByteString2ByteLength
                | ByteString4ByteLength
                | ByteString8ByteLength => KtlvTypeByteString,
            Null => KtlvTypeNull,
            Structure => KtlvTypeStructure,
            Array => KtlvTypeArray,
            List => KtlvTypeList,
            EndOfContainer => KtlvTypeUnknownContainer,
        }
    }
}

impl From<i16> for TlvType {
    fn from(value: i16) -> Self {
        match value {
            -1 => TlvType::KtlvTypeNotSpecified,
            -2 => TlvType::KtlvTypeUnknownContainer,
            0x00 => TlvType::KtlvTypeSignedInteger,
            0x04 => TlvType::KtlvTypeUnsignedInteger,
            0x08 => TlvType::KtlvTypeBoolean,
            0x0A => TlvType::KtlvTypeFloatingPointNumber,
            0x0C => TlvType::KtlvTypeUTF8String,
            0x10 => TlvType::KtlvTypeByteString,
            0x14 => TlvType::KtlvTypeNull,
            0x15 => TlvType::KtlvTypeStructure,
            0x16 => TlvType::KtlvTypeArray,
            0x17 => TlvType::KtlvTypeList,
            _ => TlvType::KtlvTypeNotSpecified, // fallback for unknown values
        }
    }
}

#[derive(Clone,Copy,PartialEq,PartialOrd)]
#[repr(i8)]
pub enum TlvElementType {
    // IMPORTANT: All values here except NotSpecified must have no bits in
    // common with values of TagControl.
    NotSpecified           = -1,
    Int8                   = 0x00,
    Int16                  = 0x01,
    Int32                  = 0x02,
    Int64                  = 0x03,
    UInt8                  = 0x04,
    UInt16                 = 0x05,
    UInt32                 = 0x06,
    UInt64                 = 0x07,
    BooleanFalse           = 0x08,
    BooleanTrue            = 0x09,
    FloatingPointNumber32  = 0x0A,
    FloatingPointNumber64  = 0x0B,
    UTF8String1ByteLength = 0x0C,
    UTF8String2ByteLength = 0x0D,
    UTF8String4ByteLength = 0x0E,
    UTF8String8ByteLength = 0x0F,
    ByteString1ByteLength = 0x10,
    ByteString2ByteLength = 0x11,
    ByteString4ByteLength = 0x12,
    ByteString8ByteLength = 0x13,
    // IMPORTANT: Values starting at Null must match the corresponding values of
    // TLVType.
    Null           = 0x14,
    Structure      = 0x15,
    Array          = 0x16,
    List           = 0x17,
    EndOfContainer = 0x18
}

impl From<i8> for TlvElementType {
    fn from(v: i8) -> Self {
        match v {
            -1 => TlvElementType::NotSpecified,
            0x00 => TlvElementType::Int8,
            0x01 => TlvElementType::Int16,
            0x02 => TlvElementType::Int32,
            0x03 => TlvElementType::Int64,
            0x04 => TlvElementType::UInt8,
            0x05 => TlvElementType::UInt16,
            0x06 => TlvElementType::UInt32,
            0x07 => TlvElementType::UInt64,
            0x08 => TlvElementType::BooleanFalse,
            0x09 => TlvElementType::BooleanTrue,
            0x0A => TlvElementType::FloatingPointNumber32,
            0x0B => TlvElementType::FloatingPointNumber64,
            0x0C => TlvElementType::UTF8String1ByteLength,
            0x0D => TlvElementType::UTF8String2ByteLength,
            0x0E => TlvElementType::UTF8String4ByteLength,
            0x0F => TlvElementType::UTF8String8ByteLength,
            0x10 => TlvElementType::ByteString1ByteLength,
            0x11 => TlvElementType::ByteString2ByteLength,
            0x12 => TlvElementType::ByteString4ByteLength,
            0x13 => TlvElementType::ByteString8ByteLength,
            0x14 => TlvElementType::Null,
            0x15 => TlvElementType::Structure,
            0x16 => TlvElementType::Array,
            0x17 => TlvElementType::List,
            0x18 => TlvElementType::EndOfContainer,
            _ => TlvElementType::NotSpecified, // fallback for invalid input
        }
    }
}

impl From<u16> for TlvElementType {
    fn from(v: u16) -> Self {
        match v {
            0x00 => TlvElementType::Int8,
            0x01 => TlvElementType::Int16,
            0x02 => TlvElementType::Int32,
            0x03 => TlvElementType::Int64,
            0x04 => TlvElementType::UInt8,
            0x05 => TlvElementType::UInt16,
            0x06 => TlvElementType::UInt32,
            0x07 => TlvElementType::UInt64,
            0x08 => TlvElementType::BooleanFalse,
            0x09 => TlvElementType::BooleanTrue,
            0x0A => TlvElementType::FloatingPointNumber32,
            0x0B => TlvElementType::FloatingPointNumber64,
            0x0C => TlvElementType::UTF8String1ByteLength,
            0x0D => TlvElementType::UTF8String2ByteLength,
            0x0E => TlvElementType::UTF8String4ByteLength,
            0x0F => TlvElementType::UTF8String8ByteLength,
            0x10 => TlvElementType::ByteString1ByteLength,
            0x11 => TlvElementType::ByteString2ByteLength,
            0x12 => TlvElementType::ByteString4ByteLength,
            0x13 => TlvElementType::ByteString8ByteLength,
            0x14 => TlvElementType::Null,
            0x15 => TlvElementType::Structure,
            0x16 => TlvElementType::Array,
            0x17 => TlvElementType::List,
            0x18 => TlvElementType::EndOfContainer,
            _ => TlvElementType::NotSpecified, // fallback for invalid input
        }
    }
}

impl TlvElementType {
    pub fn from_container_type(the_type: TlvType) -> Self {
        match the_type {
            TlvType::KtlvTypeStructure => TlvElementType::Structure,
            TlvType::KtlvTypeArray => TlvElementType::Array,
            TlvType::KtlvTypeList => TlvElementType::List,
            _ => TlvElementType::NotSpecified,
        }
    }
}
                                                                                                                                                                                                                                                                                                                                                                                               

#[derive(Clone,Copy,PartialEq)]
pub enum TLVFieldSize
{
    KTLVFieldSize0Byte = -1,
    KTLVFieldSize1Byte = 0,
    KTLVFieldSize2Byte = 1,
    KTLVFieldSize4Byte = 2,
    KTLVFieldSize8Byte = 3
}

pub enum TLVTypeMask
{
    KTLVTypeMask     = 0x1F,
    KTLVTypeSizeMask = 0x03
}

impl From<u8> for TLVFieldSize {
    fn from(v: u8) -> Self {
        match v {
            0 => TLVFieldSize::KTLVFieldSize1Byte,
            1 => TLVFieldSize::KTLVFieldSize2Byte,
            2 => TLVFieldSize::KTLVFieldSize4Byte,
            3 => TLVFieldSize::KTLVFieldSize8Byte,
            _ => TLVFieldSize::KTLVFieldSize0Byte,
        }
    }
}

pub fn tlv_type_has_value(e_type: TlvElementType) -> bool {
    return (e_type <= TlvElementType::UInt64) || 
        ((e_type >= TlvElementType::FloatingPointNumber32) && (e_type <= TlvElementType::ByteString8ByteLength));
}

#[inline]
pub fn tlv_type_has_length(e_type: TlvElementType) -> bool {
    return e_type >= TlvElementType::UTF8String1ByteLength && e_type <= TlvElementType::ByteString8ByteLength;
}

#[inline]
pub fn tlv_type_is_string(e_type: TlvElementType) -> bool {
    return e_type >= TlvElementType::UTF8String1ByteLength && e_type <= TlvElementType::ByteString8ByteLength;
}

#[inline]
pub fn tlv_type_is_utf8_string(e_type: TlvElementType) -> bool {
    return e_type >= TlvElementType::UTF8String1ByteLength && e_type <= TlvElementType::ByteString8ByteLength;
}

pub fn get_tlv_field_size(e_type: TlvElementType) -> TLVFieldSize {
    if tlv_type_has_value(e_type) {
        return TLVFieldSize::from((e_type as u8) & (TLVTypeMask::KTLVTypeSizeMask as u8));
    }

    return TLVFieldSize::KTLVFieldSize0Byte;
}

pub fn tlv_field_size_to_bytes(size: TLVFieldSize) -> u8 {
    return (if size != TLVFieldSize::KTLVFieldSize0Byte { 1 << (size as u8) } else { 0 }) as u8;
}

#[inline]
pub fn tlv_type_is_container(the_type: TlvType) -> bool {
    return the_type >= TlvType::KtlvTypeStructure && the_type <= TlvType::KtlvTypeList;
}

#[inline]
pub fn tlv_elem_type_is_container(the_type: TlvElementType) -> bool {
    return the_type >= TlvElementType::Structure && the_type <= TlvElementType::List;
}

#[inline]
pub fn is_valid_tlv_type(the_type: TlvElementType) -> bool {
    return the_type <= TlvElementType::EndOfContainer;
}
