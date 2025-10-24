pub type Oid = u16;

#[repr(u16)]
#[derive(PartialEq, Eq)]
pub enum Asn1Oid {
    KoidPubKeyAlgoECPublicKey = 0x0101,

    KoidSigAlgoECDSAWithSHA256 = 0x0201,

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

    KoidEllipticCurvePrime256v1 = 0x0401,

    KoidExtensionBasicConstraints = 0x0501,
    KoidExtensionKeyUsage = 0x0502,
    KoidExtensionExtendedKeyUsage = 0x0503,
    KoidExtensionSubjectKeyIdentifier = 0x0504,
    KoidExtensionAuthorityKeyIdentifier = 0x0505,
    KoidExtensionCSRRequest = 0x0506,

    KoidKeyPurposeServerAuth = 0x0601,
    KoidKeyPurposeClientAuth = 0x0602,
    KoidKeyPurposeCodeSigning = 0x0603,
    KoidKeyPurposeEmailProtection = 0x0604,
    KoidKeyPurposeTimeStamping = 0x0605,
    KoidKeyPurposeOCSPSigning = 0x0606,

    KoidNotSpecified = 0,
    KoidUnknown = 0xFFFF,
    KoidEnumMask = 0x00FF
}

impl From<Asn1Oid> for u16 {
    fn from(oid: Asn1Oid) -> Self {
        oid as u16
    }
}

impl TryFrom<u16> for Asn1Oid {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0101 => Ok(Asn1Oid::KoidPubKeyAlgoECPublicKey),
            0x0201 => Ok(Asn1Oid::KoidSigAlgoECDSAWithSHA256),

            0x0301 => Ok(Asn1Oid::KoidAttributeTypeCommonName),
            0x0302 => Ok(Asn1Oid::KoidAttributeTypeSurname),
            0x0303 => Ok(Asn1Oid::KoidAttributeTypeSerialNumber),
            0x0304 => Ok(Asn1Oid::KoidAttributeTypeCountryName),
            0x0305 => Ok(Asn1Oid::KoidAttributeTypeLocalityName),
            0x0306 => Ok(Asn1Oid::KoidAttributeTypeStateOrProvinceName),
            0x0307 => Ok(Asn1Oid::KoidAttributeTypeOrganizationName),
            0x0308 => Ok(Asn1Oid::KoidAttributeTypeOrganizationalUnitName),
            0x0309 => Ok(Asn1Oid::KoidAttributeTypeTitle),
            0x030A => Ok(Asn1Oid::KoidAttributeTypeName),
            0x030B => Ok(Asn1Oid::KoidAttributeTypeGivenName),
            0x030C => Ok(Asn1Oid::KoidAttributeTypeInitials),
            0x030D => Ok(Asn1Oid::KoidAttributeTypeGenerationQualifier),
            0x030E => Ok(Asn1Oid::KoidAttributeTypeDNQualifier),
            0x030F => Ok(Asn1Oid::KoidAttributeTypePseudonym),
            0x0310 => Ok(Asn1Oid::KoidAttributeTypeDomainComponent),
            0x0311 => Ok(Asn1Oid::KoidAttributeTypeMatterNodeId),
            0x0312 => Ok(Asn1Oid::KoidAttributeTypeMatterFirmwareSigningId),
            0x0313 => Ok(Asn1Oid::KoidAttributeTypeMatterICACId),
            0x0314 => Ok(Asn1Oid::KoidAttributeTypeMatterRCACId),
            0x0315 => Ok(Asn1Oid::KoidAttributeTypeMatterFabricId),
            0x0316 => Ok(Asn1Oid::KoidAttributeTypeMatterCASEAuthTag),
            0x0317 => Ok(Asn1Oid::KoidAttributeTypeMatterVidVerificationSignerId),

            0x0401 => Ok(Asn1Oid::KoidEllipticCurvePrime256v1),

            0x0501 => Ok(Asn1Oid::KoidExtensionBasicConstraints),
            0x0502 => Ok(Asn1Oid::KoidExtensionKeyUsage),
            0x0503 => Ok(Asn1Oid::KoidExtensionExtendedKeyUsage),
            0x0504 => Ok(Asn1Oid::KoidExtensionSubjectKeyIdentifier),
            0x0505 => Ok(Asn1Oid::KoidExtensionAuthorityKeyIdentifier),
            0x0506 => Ok(Asn1Oid::KoidExtensionCSRRequest),

            0x0601 => Ok(Asn1Oid::KoidKeyPurposeServerAuth),
            0x0602 => Ok(Asn1Oid::KoidKeyPurposeClientAuth),
            0x0603 => Ok(Asn1Oid::KoidKeyPurposeCodeSigning),
            0x0604 => Ok(Asn1Oid::KoidKeyPurposeEmailProtection),
            0x0605 => Ok(Asn1Oid::KoidKeyPurposeTimeStamping),
            0x0606 => Ok(Asn1Oid::KoidKeyPurposeOCSPSigning),

            0x0000 => Ok(Asn1Oid::KoidNotSpecified),
            0xFFFF => Ok(Asn1Oid::KoidUnknown),
            0x00FF => Ok(Asn1Oid::KoidEnumMask),

            _ => Err(()),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidCategory {
    KoidCategoryNotSpecified       = 0x0000,
    KoidCategoryPubKeyAlgo         = 0x0100,
    KoidCategorySigAlgo            = 0x0200,
    KoidCategoryAttributeType      = 0x0300,
    KoidCategoryEllipticCurve      = 0x0400,
    KoidCategoryExtension          = 0x0500,
    KoidCategoryKeyPurpose         = 0x0600,
    KoidCategoryUnknown            = 0x0F00,
}

pub const K_OID_CATEGORY_MASK: u16 = 0x0F00;

#[inline]
pub fn get_oid(category: OidCategory, id: u8) -> Oid {
    //let id: u16 = category as u16 | id as u16;
    //id.into();
    (category as u16 | id as u16).into()
}
