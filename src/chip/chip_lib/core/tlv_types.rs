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
