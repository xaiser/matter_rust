pub type Oid = u16;

#[repr(u16)]
#[derive(PartialEq, Eq)]
pub enum Asn1Oid {
    KoidAttributeTypeCommonName = 0x0301,
    KoidAttributeTypeSurname = 0x0302,
    KoidAttributeTypeSerialNumber = 0x0303,
    KoidAttributeTypeCountryName = 0x0304,
    KoidAttributeTypeLocalityName = 0x0305,
    KoidAttributeTypeStateOrProvinceName = 0x0306,
    KoidAttributeTypeOrganizationName = 0x0307,
    KoidAttributeTypeOrganizationalUnitName = 0x0308,
    KoidAttributeTypeTitle = 0x0309,
    KoidAttributeTypeName = 0x030A,
    KoidAttributeTypeGivenName = 0x030B,
    KoidAttributeTypeInitials = 0x030C,
    KoidAttributeTypeGenerationQualifier = 0x030D,
    KoidAttributeTypeDNQualifier = 0x030E,
    KoidAttributeTypePseudonym = 0x030F,
    KoidAttributeTypeDomainComponent = 0x0310,
    KoidAttributeTypeMatterNodeId = 0x0311,
    KoidAttributeTypeMatterFirmwareSigningId = 0x0312,
    KoidAttributeTypeMatterICACId = 0x0313,
    KoidAttributeTypeMatterRCACId = 0x0314,
    KoidAttributeTypeMatterFabricId = 0x0315,
    KoidAttributeTypeMatterCASEAuthTag = 0x0316,
    KoidAttributeTypeMatterVidVerificationSignerId = 0x0317,
    KoidNotSpecified = 0,
    KoidUnknown = 0xFFFF,
}
