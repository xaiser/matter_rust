use crate::chip::{
    FabricId, NodeId,
    asn1::{Oid, Asn1Oid, get_oid, OidCategory},
    chip_lib::{
        core::{
            case_auth_tag::{CaseAuthTag, is_valid_case_auth_tag},
            data_model_types::is_valid_fabric_id,
            node_id::is_operational_node_id,
            tlv_types::TlvType,
            tlv_tags::{is_context_tag, tag_num_from_tag, context_tag, Tag},
            chip_config::CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES,
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
        },
        support::default_string::DefaultString,
    },
    //credentials::chip_cert_to_x509::decode_chip_cert as decode_chip_cert,
    crypto::{P256PublicKey, ECPKey, K_P256_PUBLIC_KEY_LENGTH, P256EcdsaSignature, K_SHA256_HASH_LENGTH},
    system::system_clock::Seconds32,
};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;
use crate::chip_ok;

use crate::chip_error_invalid_argument;
use crate::chip_error_not_implemented;
use crate::chip_error_no_memory;
use crate::chip_error_not_found;
use crate::chip_error_invalid_tlv_tag;
use crate::chip_error_wrong_node_id;
use crate::chip_error_unsupported_signature_type;
use crate::chip_error_wrong_cert_dn;

// re-export
pub use crate::chip::credentials::chip_cert_to_x509::decode_chip_cert as decode_chip_cert;
pub use crate::chip::credentials::chip_cert_to_x509::decode_chip_cert_with_reader as decode_chip_cert_with_reader;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use bitflags::{Flags, bitflags};

// we use this buffer to store the vid verification statement too
// As the development goes, we push more and more data to cert, so we extend 128 bytes first.
pub const K_MAX_CHIP_CERT_LENGTH: usize = crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE + 128;
pub const K_MAX_RDN_STRING_LENGTH: usize = 10;
pub const K_KEY_IDENTIFIER_LENGTH: usize = crate::chip::crypto::K_SUBJECT_KEY_IDENTIFIER_LENGTH;
pub type ChipRDNString = DefaultString<K_MAX_RDN_STRING_LENGTH>;
pub type CertificateKeyId = [u8; K_KEY_IDENTIFIER_LENGTH];

#[derive(Copy, Clone)]
pub enum ChipCertTag
{
    // ---- Context-specific Tags for ChipCertificate Structure ----
    KtagSerialNumber            = 1,  /* [ byte string ] Certificate serial number, in BER integer encoding. */
    KtagSignatureAlgorithm      = 2,  /* [ unsigned int ] Enumerated value identifying the certificate signature algorithm. */
    KtagIssuer                  = 3,  /* [ list ] The issuer distinguished name of the certificate. */
    KtagNotBefore               = 4,  /* [ unsigned int ] Certificate validity period start (certificate date format). */
    KtagNotAfter                = 5,  /* [ unsigned int ] Certificate validity period end (certificate date format). */
    KtagSubject                 = 6,  /* [ list ] The subject distinguished name of the certificate. */
    KtagPublicKeyAlgorithm      = 7,  /* [ unsigned int ] Identifies the algorithm with which the public key can be used. */
    KtagEllipticCurveIdentifier = 8,  /* [ unsigned int ] For EC certs, identifies the elliptic curve used. */
    KtagEllipticCurvePublicKey  = 9,  /* [ byte string ] The elliptic curve public key, in X9.62 encoded format. */
    KtagExtensions              = 10, /* [ list ] Certificate extensions. */
    KtagECDSASignature          = 11, /* [ byte string ] The ECDSA signature for the certificate. */
}

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum CertType {
    KnotSpecified    = 0x00,       /* The certificate's type has not been specified. */
    Kroot            = 0x01,       /* A Matter Root certificate (RCAC). */
    Kica             = 0x02,       /* A Matter Intermediate CA certificate (ICAC). */
    Knode            = 0x03,       /* A Matter node operational certificate (NOC). */
    KfirmwareSigning = 0x04,       /* A Matter firmware signing certificate. Note that Matter doesn't
                                        specify how firmware images are signed and implementation of
                                        firmware image signing is manufacturer-specific. The Matter
                                        certificate format supports encoding of firmware signing
                                        certificates if chosen by the manufacturer to use them. */
    KnetworkIdentity       = 0x05, /* A Matter Network (Client) Identity. */
    KvidVerificationSigner = 0x06  /* A Matter VendorID Verification Signer Certificate. */
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyPurposeFlags: u8 {
        const Knone            = 0x00; /* init */
        const KserverAuth      = 0x01; /* Extended key usage is server authentication. */
        const KclientAuth      = 0x02; /* Extended key usage is client authentication. */
        const KcodeSigning     = 0x04; /* Extended key usage is code signing. */
        const KemailProtection = 0x08; /* Extended key usage is email protection. */
        const KtimeStamping    = 0x10; /* Extended key usage is time stamping. */
        const KoCSPSigning     = 0x20; /* Extended key usage is OCSP signing. */
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyUsageFlags: u16 {
        const Knone             = 0x0000; /* init */
        const KdigitalSignature = 0x0001; /* Key usage is digital signature. */
        const KnonRepudiation   = 0x0002; /* Key usage is non-repudiation. */
        const KkeyEncipherment  = 0x0004; /* Key usage is key encipherment. */
        const KdataEncipherment = 0x0008; /* Key usage is data encipherment. */
        const KkeyAgreement     = 0x0010; /* Key usage is key agreement. */
        const KkeyCertSign      = 0x0020; /* Key usage is key cert signing. */
        const KcRLSign          = 0x0040; /* Key usage is CRL signing. */
        const KencipherOnly     = 0x0080; /* Key usage is encipher only. */
        const KdecipherOnly     = 0x0100; /* Key usage is decipher only. */
    }
}

#[derive(Copy, Clone)]
pub enum ChipCertExtensionTag {
    // ---- Context-specific Tags for certificate extensions ----
    KtagBasicConstraints       = 1, /* [ structure ] Identifies whether the subject of the certificate is a CA. */
    KtagKeyUsage               = 2, /* [ unsigned int ] Bits identifying key usage, per RFC5280. */
    KtagExtendedKeyUsage       = 3, /* [ array ] Enumerated values giving the purposes for which the public key can be used. */
    KtagSubjectKeyIdentifier   = 4, /* [ byte string ] Identifier of the certificate's public key. */
    KtagAuthorityKeyIdentifier = 5, /* [ byte string ] Identifier of the public key used to sign the certificate. */
    KtagFutureExtension        = 6, /* [ byte string ] Arbitrary extension. DER encoded SEQUENCE as in X.509 form. */
}

#[derive(Copy, Clone)]
pub enum ChipCertBasicConstraintTag {

    // ---- Context-specific Tags for BasicConstraints Structure ----
    KtagBasicConstraintsIsCA = 1,              /* [ boolean ] True if the certificate can be used to verify certificate */
    KtagBasicConstraintsPathLenConstraint = 2, /* [ unsigned int ] Maximum number of subordinate intermediate certificates. */
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CertFlags: u16 {
        const Knone                        = 0x0000; /* nothin */
        const KextPresentBasicConstraints = 0x0001; /* Basic constraints extension is present in the certificate. */
        const KextPresentKeyUsage         = 0x0002; /* Key usage extension is present in the certificate. */
        const KextPresentExtendedKeyUsage = 0x0004; /* Extended key usage extension is present in the certificate. */
        const KextPresentSubjectKeyId     = 0x0008; /* Subject key identifier extension is present in the certificate. */
        const KextPresentAuthKeyId        = 0x0010; /* Authority key identifier extension is present in the certificate. */
        const KextPresentFutureIsCritical = 0x0020; /* Future extension marked as critical is present in the certificate. */
        const KpathLenConstraintPresent    = 0x0040; /* Path length constraint is present in the certificate. */
        const KisCA                        = 0x0080; /* Indicates that certificate is a CA certificate. */
        const KisTrustAnchor               = 0x0100; /* Indicates that certificate is a trust anchor. */
        const KtbsHashPresent              = 0x0200; /* Indicates that TBS hash of the certificate was generated and stored. */
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CertDecodeFlags: u8 {
        const Knone            = 0x00; /* nothing */
        const KgenerateTBSHash = 0x01; /* Indicates that to-be-signed (TBS) hash of the certificate should be calculated when certificate is
                                    loaded. The TBS hash is then used to validate certificate signature. Normally, all certificates
                                    (except trust anchor) in the certificate validation chain require TBS hash. */
        const KisTrustAnchor   = 0x02;   /* Indicates that the corresponding certificate is trust anchor. */
    }
}

pub const K_NULL_CERT_TIME: u32 = 0;

#[inline]
const fn default_certificate_key_id() -> CertificateKeyId {
    [0; K_KEY_IDENTIFIER_LENGTH]
}

#[inline]
fn is_chip_64bit_dn_attr(oid: Oid) -> bool {
    return oid == Asn1Oid::KoidAttributeTypeMatterNodeId as Oid ||
        oid == Asn1Oid::KoidAttributeTypeMatterFirmwareSigningId as Oid ||
        oid == Asn1Oid::KoidAttributeTypeMatterICACId as Oid ||
        oid == Asn1Oid::KoidAttributeTypeMatterRCACId as Oid ||
        oid == Asn1Oid::KoidAttributeTypeMatterFabricId as Oid ||
        oid == Asn1Oid::KoidAttributeTypeMatterVidVerificationSignerId as Oid;
}

#[inline]
fn is_chip_32bit_dn_attr(oid: Oid) -> bool {
    return oid == Asn1Oid::KoidAttributeTypeMatterCASEAuthTag as Oid;
}

#[inline]
fn is_chip_dn_attr(oid: Oid) -> bool {
    return is_chip_64bit_dn_attr(oid) || is_chip_32bit_dn_attr(oid);
}

#[inline]
pub(crate) fn tag_not_before() -> Tag {
    context_tag(ChipCertTag::KtagNotBefore as u8)
}

#[inline]
pub(crate) fn tag_not_after() -> Tag {
    context_tag(ChipCertTag::KtagNotAfter as u8)
}

pub(super) mod internal {
    pub const K_NETWORK_IDENTITY_CN: &str = "*";
}

pub fn verify_cert_signature(cert: &ChipCertificateData, signer: &ChipCertificateData) -> ChipErrorResult {
    verify_or_return_error!(cert.m_cert_flags.intersects(CertFlags::KtbsHashPresent), Err(chip_error_invalid_argument!()));
    verify_or_return_error!(cert.m_sig_algo_OID == Asn1Oid::KoidSigAlgoECDSAWithSHA256.into(), Err(chip_error_unsupported_signature_type!()));

    let mut signer_public_key = P256PublicKey::default_with_raw_value(&signer.m_public_key[..]);
    let mut signature = P256EcdsaSignature::default();

    let sig_length = cert.m_signature.length();
    signature.set_length(sig_length)?;
    signature.bytes()[..sig_length].copy_from_slice(&cert.m_signature.const_bytes()[..sig_length]);

    return signer_public_key.ecdsa_validate_hash_signature(&cert.m_tbs_hash[..K_SHA256_HASH_LENGTH], &signature);
}

pub struct CertBuffer {
    pub buf: [u8; K_MAX_CHIP_CERT_LENGTH],
    pub len: usize,
}

impl Default for CertBuffer {
    fn default() -> Self {
        CertBuffer::const_default()
    }
}

impl CertBuffer {
    pub const fn const_default() -> Self {
        Self {
            buf: [0; K_MAX_CHIP_CERT_LENGTH],
            len: 0
        }
    }

    pub fn init(&mut self, cert: &[u8]) -> ChipErrorResult {
        verify_or_return_error!(cert.is_empty() == false && cert.len() <= K_MAX_CHIP_CERT_LENGTH, Err(chip_error_invalid_argument!()));
        let size = cert.len();
        self.buf[0..size].copy_from_slice(cert);

        return self.set_length(size);
    }

    pub fn set_length(&mut self, size: usize) -> ChipErrorResult {
        verify_or_return_error!(size <= K_MAX_CHIP_CERT_LENGTH, Err(chip_error_invalid_argument!()));

        self.len = size;

        chip_ok!()
    }

    pub fn all_bytes(&mut self) -> &mut [u8] {
        return &mut self.buf[..];
    }

    pub fn const_all_bytes(&self) -> &[u8] {
        return &self.buf[..];
    }

    pub fn bytes(&mut self) -> &mut [u8] {
        return &mut self.buf[..self.len];
    }

    pub fn const_bytes(&self) -> &[u8] {
        return &self.buf[..self.len];
    }

    pub fn length(&self) -> usize {
        self.len
    }
}

#[derive(Copy, Clone)]
pub struct ChipRDN {
    m_string: ChipRDNString,
    m_chip_val: u64,
    m_attr_oid: Oid,
    m_attr_is_printable_string: bool,
}

impl ChipRDN {
    pub const fn const_default() -> Self {
        Self {
            m_string: ChipRDNString::const_default(),
            m_chip_val: 0,
            m_attr_oid: Asn1Oid::KoidNotSpecified as Oid,
            m_attr_is_printable_string: false,
        }
    }

    pub fn clear(&mut self) {
        self.m_string.clear();
        self.m_chip_val = 0;
        self.m_attr_oid = Asn1Oid::KoidNotSpecified as Oid;
        self.m_attr_is_printable_string = false;
    }

    pub fn is_empty(&self) -> bool {
        self.m_attr_oid == Asn1Oid::KoidNotSpecified as Oid
    }

    pub fn is_equal(&self, other: &Self) -> bool {
        if self.m_attr_oid == Asn1Oid::KoidUnknown as Oid || self.m_attr_oid == Asn1Oid::KoidNotSpecified as Oid || self.m_attr_oid != other.m_attr_oid ||
            self.m_attr_is_printable_string != other.m_attr_is_printable_string {
                return false;
        }

        if is_chip_dn_attr(self.m_attr_oid) {
            return self.m_chip_val == other.m_chip_val;
        }

        return self.m_string == other.m_string;
    }
}

impl Default for ChipRDN {
    fn default() -> Self {
        ChipRDN::const_default()
    }
}

pub struct ChipDN {
    pub(super) rdn: [ChipRDN; CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES]
}

impl ChipDN {
    pub const fn const_default() -> Self {
        Self {
            rdn: [ChipRDN::const_default(); CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES]
        }
    }

    pub fn add_attribute(&mut self, oid: Oid, val: u64) -> ChipErrorResult {
        let rdn_count = self.rdn_count() as usize;
        verify_or_return_error!(rdn_count < CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES, Err(chip_error_no_memory!()));
        verify_or_return_error!(is_chip_dn_attr(oid), Err(chip_error_invalid_argument!()));

        if is_chip_32bit_dn_attr(oid) {
            let _ = u32::try_from(val).map_err(|_| chip_error_invalid_argument!())?;
        }

        self.rdn[rdn_count].m_attr_oid = oid;
        self.rdn[rdn_count].m_chip_val = val;
        self.rdn[rdn_count].m_attr_is_printable_string = false;

        chip_ok!()
    }

    pub fn add_attribute_string(&mut self, oid: Oid, val: &str, is_printable_string: bool) -> ChipErrorResult {
        let rdn_count = self.rdn_count() as usize;
        verify_or_return_error!(rdn_count < CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES, Err(chip_error_no_memory!()));
        verify_or_return_error!(!is_chip_dn_attr(oid), Err(chip_error_invalid_argument!()));
        verify_or_return_error!(oid != Asn1Oid::KoidNotSpecified.into(), Err(chip_error_invalid_argument!()));
        verify_or_return_error!(val.len() < K_MAX_RDN_STRING_LENGTH, Err(chip_error_invalid_argument!()));

        self.rdn[rdn_count].m_attr_oid = oid;
        self.rdn[rdn_count].m_string = ChipRDNString::from(val);
        self.rdn[rdn_count].m_attr_is_printable_string = is_printable_string;

        chip_ok!()
    }

    pub fn clear(&mut self) {
        for rdn in &mut self.rdn {
            rdn.clear();
        }
    }

    pub fn rdn_count(&self) -> u8 {
        self.rdn.iter().take_while(|r| r.is_empty() == false).count() as u8
    }

    pub fn decode_from_tlv<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
        const KoidAttributeIsPrintableStringFlag: u32 = 0x00000080;
        const KoidAttributeTypeMask: u32 = 0x0000007F;

        verify_or_return_error!(reader.get_type() == TlvType::KtlvTypeList, Err(chip_error_invalid_tlv_tag!()));

        let outer_container = reader.enter_container()?;

        while reader.next().is_ok() {
            let tlv_tag = reader.get_tag();
            verify_or_return_error!(is_context_tag(&tlv_tag), Err(chip_error_invalid_tlv_tag!()));

            let tlv_tag_num = tag_num_from_tag(&tlv_tag);

            let attr_oid = get_oid(OidCategory::KoidCategoryAttributeType, (tlv_tag_num & KoidAttributeTypeMask) as u8);

            let attr_is_printable_string = (tlv_tag_num & KoidAttributeIsPrintableStringFlag) == KoidAttributeIsPrintableStringFlag;

            if is_chip_64bit_dn_attr(attr_oid) {
                // For 64-bit CHIP-defined DN attributes.
                verify_or_return_error!(attr_is_printable_string == false, Err(chip_error_invalid_tlv_tag!()));
                let chip_attr = reader.get_u64()?;
                if attr_oid == crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId.into() {
                    verify_or_return_error!(is_operational_node_id(chip_attr), Err(chip_error_wrong_node_id!()));
                } else if attr_oid == crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId.into() {
                    verify_or_return_error!(is_valid_fabric_id(chip_attr), Err(chip_error_invalid_argument!()));
                }
                self.add_attribute(attr_oid, chip_attr)?;
            } else if is_chip_32bit_dn_attr(attr_oid) {
                // For 32-bit CHIP-defined DN attributes.
                verify_or_return_error!(attr_is_printable_string == false, Err(chip_error_invalid_tlv_tag!()));
                let chip_attr = reader.get_u32()?;
                if attr_oid == crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterCASEAuthTag.into() {
                    verify_or_return_error!(is_valid_case_auth_tag(chip_attr), Err(chip_error_invalid_argument!()));
                }
                self.add_attribute(attr_oid, chip_attr as u64)?;
            } else {
                let chip_attr = reader.get_string()?;
                if chip_attr.is_none() {
                    return Err(chip_error_invalid_argument!());
                }
                self.add_attribute_string(attr_oid, chip_attr.unwrap(), attr_is_printable_string)?;
            }
        }

        reader.exit_container(outer_container)?;

        chip_ok!()
    }

    pub fn is_equal(&self, other: &Self) -> bool {
        let rdn_count = self.rdn_count();

        verify_or_return_value!(rdn_count > 0, false);
        verify_or_return_value!(rdn_count == other.rdn_count(), false);

        for i in 0..(rdn_count as usize) {
            verify_or_return_value!(self.rdn[i].is_equal(&other.rdn[i]), false);
        }

        return true;
    }

    pub fn get_cert_type(&self) -> Result<CertType, ChipError> {
        let rdn_count = self.rdn_count();

        if rdn_count == 1 && self.rdn[0].m_attr_oid == Asn1Oid::KoidAttributeTypeCommonName.into() && !self.rdn[0].m_attr_is_printable_string &&
            self.rdn[0].m_string.const_bytes() == internal::K_NETWORK_IDENTITY_CN.as_bytes() {
                return Ok(CertType::KnetworkIdentity);
        }

        let mut cert_type = CertType::KnotSpecified;
        let mut fabric_id_present = false;
        let mut cats_present = false;

        for i in 0..rdn_count {
            match self.rdn[i as usize].m_attr_oid {
                v if v == Asn1Oid::KoidAttributeTypeMatterRCACId.into() => {
                    verify_or_return_error!(cert_type == CertType::KnotSpecified, Err(chip_error_wrong_cert_dn!()));
                    cert_type = CertType::Kroot;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterICACId.into() => {
                    verify_or_return_error!(cert_type == CertType::KnotSpecified, Err(chip_error_wrong_cert_dn!()));
                    cert_type = CertType::Kica;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterVidVerificationSignerId.into() => {
                    verify_or_return_error!(cert_type == CertType::KnotSpecified, Err(chip_error_wrong_cert_dn!()));
                    cert_type = CertType::KvidVerificationSigner;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterNodeId.into() => {
                    verify_or_return_error!(cert_type == CertType::KnotSpecified, Err(chip_error_wrong_cert_dn!()));
                    verify_or_return_error!(is_operational_node_id(self.rdn[i as usize].m_chip_val), Err(chip_error_wrong_node_id!()));
                    cert_type = CertType::Knode;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterFirmwareSigningId.into() => {
                    verify_or_return_error!(cert_type == CertType::KnotSpecified, Err(chip_error_wrong_cert_dn!()));
                    cert_type = CertType::KfirmwareSigning;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterFabricId.into() => {
                    verify_or_return_error!(!fabric_id_present, Err(chip_error_wrong_cert_dn!()));
                    verify_or_return_error!(is_valid_fabric_id(self.rdn[i as usize].m_chip_val), Err(chip_error_wrong_cert_dn!()));
                    fabric_id_present = true;
                },
                v if v == Asn1Oid::KoidAttributeTypeMatterCASEAuthTag.into() => {
                    if let Ok(val) = CaseAuthTag::try_from(self.rdn[i as usize].m_chip_val) {
                        verify_or_return_error!(is_valid_case_auth_tag(val), Err(chip_error_wrong_cert_dn!()));
                    } else {
                        return Err(chip_error_wrong_cert_dn!());
                    }
                    cats_present = true;
                },
                _ => {
                }
            }
        }

        if cert_type == CertType::Knode {
            verify_or_return_error!(fabric_id_present, Err(chip_error_wrong_cert_dn!()));
        } else {
            verify_or_return_error!(!cats_present, Err(chip_error_wrong_cert_dn!()));
        }

        if cert_type == CertType::KvidVerificationSigner {
            verify_or_return_error!(!fabric_id_present, Err(chip_error_wrong_cert_dn!()));
        }

        return Ok(cert_type);
    }
}

impl Default for ChipDN {
    fn default() -> Self {
        ChipDN::const_default()
    }
}

pub struct ChipCertificateData {
    pub m_subject_dn: ChipDN,
    pub m_issuer_dn: ChipDN,
    pub m_public_key: [u8; K_P256_PUBLIC_KEY_LENGTH],
    pub m_not_before_time: u32,
    pub m_not_after_time: u32,
    pub m_subject_key_id: CertificateKeyId,
    pub m_auth_key_id: CertificateKeyId,
    pub m_cert_flags: CertFlags,
    pub m_key_usage_flags: KeyUsageFlags,
    pub m_key_purpose_flags: KeyPurposeFlags,
    pub m_sig_algo_OID: u16,
    pub m_signature: P256EcdsaSignature,
    pub m_tbs_hash: [u8; K_SHA256_HASH_LENGTH],
    pub m_path_len_constraint: u8,
}

impl ChipCertificateData {
    pub const fn const_default() -> Self {
        Self {
            m_subject_dn: ChipDN::const_default(),
            m_issuer_dn: ChipDN::const_default(),
            m_public_key: [0; K_P256_PUBLIC_KEY_LENGTH],
            m_not_before_time: 0,
            m_not_after_time: 0,
            m_subject_key_id: default_certificate_key_id(),
            m_auth_key_id: default_certificate_key_id(),
            m_cert_flags: CertFlags::Knone,
            m_key_usage_flags: KeyUsageFlags::Knone,
            m_key_purpose_flags: KeyPurposeFlags::Knone,
            // for now, we just level it this way.
            m_sig_algo_OID: Asn1Oid::KoidSigAlgoECDSAWithSHA256 as u16,
            m_signature: P256EcdsaSignature::const_default(),
            m_tbs_hash: [0u8; K_SHA256_HASH_LENGTH],
            m_path_len_constraint: 0,
        }
    }

    pub fn clear(&mut self) {
        self.m_subject_dn = ChipDN::const_default();
        self.m_issuer_dn = ChipDN::const_default();
        self.m_public_key = [0; K_P256_PUBLIC_KEY_LENGTH];
        self.m_not_before_time = 0;
        self.m_not_after_time = 0;
        self.m_subject_key_id = default_certificate_key_id();
        self.m_auth_key_id = default_certificate_key_id();
        self.m_cert_flags.clear();
        self.m_key_usage_flags.clear();
        self.m_key_purpose_flags.clear();
        self.m_sig_algo_OID = 0;
        self.m_signature = P256EcdsaSignature::const_default();
        self.m_tbs_hash = [0u8; K_SHA256_HASH_LENGTH];
        self.m_path_len_constraint = 0;
    }

    pub fn is_equal(&self, other: &Self) -> bool {
        let is_subject_dn = self.m_subject_dn.is_equal(&other.m_subject_dn);
        let is_issuer_dn = self.m_issuer_dn.is_equal(&other.m_issuer_dn);
        let is_public_key = self.m_public_key == other.m_public_key;
        let is_not_before_time = self.m_not_before_time == other.m_not_before_time;
        let is_not_after_time = self.m_not_after_time == other.m_not_after_time;
        let is_subject_key_id = self.m_subject_key_id == other.m_subject_key_id;
        let is_auth_key_id = self.m_auth_key_id == other.m_auth_key_id;
        let is_cert_flags = self.m_cert_flags == other.m_cert_flags;
        let is_key_usage_flags = self.m_key_usage_flags == other.m_key_usage_flags;
        let is_key_purpose_flags = self.m_key_purpose_flags == other.m_key_purpose_flags;
        let is_sig_algo_oid = self.m_sig_algo_OID == other.m_sig_algo_OID;
        let is_signature = self.m_signature.const_bytes() == other.m_signature.const_bytes();
        let is_tbs_hash = self.m_tbs_hash == other.m_tbs_hash;
        let is_path_long_constraint = self.m_path_len_constraint == other.m_path_len_constraint;

        return is_subject_dn && is_issuer_dn && is_public_key && is_not_before_time && is_not_after_time && is_subject_key_id && is_auth_key_id &&
            is_cert_flags && is_key_usage_flags && is_key_purpose_flags && is_sig_algo_oid && is_signature && is_tbs_hash && is_path_long_constraint;
    }
}

impl Default for ChipCertificateData {
    fn default() -> Self {
        ChipCertificateData::const_default()
    }
}

pub fn extract_node_id_fabric_id_from_op_cert(opcert: &ChipCertificateData) -> Result<(NodeId, FabricId), ChipError> {
    // Since we assume the cert is pre-validated, we are going to assume that
    // its subject in fact has both a node id and a fabric id.
    let mut node_id: Option<NodeId> = None;
    let mut fabric_id: Option<FabricId> = None;

    for r in opcert.m_subject_dn.rdn.iter().take_while(|r| r.is_empty() == false) {
        if r.m_attr_oid == Asn1Oid::KoidAttributeTypeMatterNodeId.into() {
            node_id = Some(r.m_chip_val);
        }
        if r.m_attr_oid == Asn1Oid::KoidAttributeTypeMatterFabricId.into() {
            fabric_id = Some(r.m_chip_val);
        }
    }

    if node_id.is_none() || fabric_id.is_none() {
        return Err(chip_error_not_found!());
    }

    return Ok((node_id.unwrap(), fabric_id.unwrap()));
}

pub fn extract_node_id_fabric_id_from_op_cert_byte(opcert: &[u8]) -> Result<(NodeId, FabricId), ChipError> {
    let mut op_cert: ChipCertificateData = ChipCertificateData::default();
    decode_chip_cert(opcert, &mut op_cert, None)?;

    extract_node_id_fabric_id_from_op_cert(&op_cert)
}

pub fn extract_public_key_from_chip_cert(opcert: &ChipCertificateData) -> Result<P256PublicKey, ChipError> {
    Ok(P256PublicKey::default_with_raw_value(&opcert.m_public_key[..]))
}

pub fn extract_public_key_from_chip_cert_byte(opcert: &[u8]) -> Result<P256PublicKey, ChipError> {
    let mut op_cert: ChipCertificateData = ChipCertificateData::default();
    decode_chip_cert(opcert, &mut op_cert, None)?;

    extract_public_key_from_chip_cert(&op_cert)
}

pub fn extract_not_before_from_chip_cert(opcert: &ChipCertificateData) -> Result<Seconds32, ChipError> {
    Ok(Seconds32::from_secs(opcert.m_not_before_time as u64))
}

pub fn extract_not_before_from_chip_cert_byte(opcert: &[u8]) -> Result<Seconds32, ChipError> {
    let mut op_cert: ChipCertificateData = ChipCertificateData::default();
    decode_chip_cert(opcert, &mut op_cert, None)?;

    extract_not_before_from_chip_cert(&op_cert)
}

pub fn extract_not_after_from_chip_cert(opcert: &ChipCertificateData) -> Result<Seconds32, ChipError> {
    Ok(Seconds32::from_secs(opcert.m_not_after_time as u64))
}

pub fn extract_not_after_from_chip_cert_byte(opcert: &[u8]) -> Result<Seconds32, ChipError> {
    let mut op_cert: ChipCertificateData = ChipCertificateData::default();
    decode_chip_cert(opcert, &mut op_cert, None)?;

    extract_not_after_from_chip_cert(&op_cert)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn make_subject_key_id(first: u8, last: u8) -> CertificateKeyId {
        let mut key = [0; crate::chip::credentials::chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = first;
        key[key.len() - 1] = last;

        return key;
    }

    mod rdn {
        use super::super::*;

        #[test]
        fn init_chip_rdn() {
            let rdn = ChipRDN::default();
            assert_eq!(rdn.m_attr_oid, Asn1Oid::KoidNotSpecified as Oid);
            assert_eq!(true, rdn.is_empty());
        }

        #[test]
        fn empty_oid_is_not_same() {
            let rdn1 = ChipRDN::default();
            let rdn2 = ChipRDN::default();
            assert_eq!(false, rdn1.is_equal(&rdn2));
        }

        #[test]
        fn same_oid() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            assert_eq!(true, rdn1.is_equal(&rdn2));
        }

        #[test]
        fn different_oid() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterFabricId as Oid;
            assert_eq!(false, rdn1.is_equal(&rdn2));
        }

        #[test]
        fn not_matter_oid_same_string() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            assert_eq!(true, rdn1.is_equal(&rdn2));
        }

        #[test]
        fn not_matter_oid_not_same_string() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn1.m_string = DefaultString::from("1");
            rdn2.m_string = DefaultString::from("2");
            assert_eq!(false, rdn1.is_equal(&rdn2));
        }
    } // end of rdn
    
    mod dn {
        use super::super::*;
        use crate::chip::chip_lib::core::{
            tlv_types::{self, TlvType},
            tlv_tags::{self, is_context_tag, tag_num_from_tag},
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        };

        #[test]
        fn init() {
            let dn = ChipDN::default();
            assert_eq!(0, dn.rdn_count());
        }

        #[test]
        fn add_one_attr() {
            let mut dn = ChipDN::default();
            
            assert_eq!(true, dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, 1).is_ok());
            assert_eq!(1, dn.rdn_count());
        }

        #[test]
        fn add_non_matter_oid() {
            let mut dn = ChipDN::default();
            
            assert_eq!(false, dn.add_attribute(Asn1Oid::KoidAttributeTypeCommonName as Oid, 1).is_ok());
        }

        #[test]
        fn add_too_much() {
            let mut dn = ChipDN::default();
            for i in 0..CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES {
                assert_eq!(true, dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId.into(), 1).is_ok());
            }
            assert_eq!(false, dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId.into(), 1).is_ok());
        }

        #[test]
        fn add_oid_printable() {
            let mut dn = ChipDN::default();
            
            assert_eq!(true, dn.add_attribute_string(Asn1Oid::KoidAttributeTypeCommonName.into(), "123", true).is_ok());
        }

        #[test]
        fn add_oid_printable_not_specified_oid() {
            let mut dn = ChipDN::default();
            
            assert_eq!(false, dn.add_attribute_string(Asn1Oid::KoidNotSpecified.into(), "123", true).is_ok());
        }

        #[test]
        fn decode_64bit_from_tlv_successfully() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(1, dn.rdn_count());
            assert_eq!(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u16, dn.rdn[0].m_attr_oid);
            assert_eq!(0x01, dn.rdn[0].m_chip_val);
        }

        #[test]
        fn decode_64bit_from_tlv_not_list() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(false, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(0, dn.rdn_count());
        }

        #[test]
        fn decode_64bit_from_tlv_empty_reader() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(false, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(0, dn.rdn_count());
        }

        #[test]
        fn decode_64bit_from_tlv_invalid_tag() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::anonymous_tag(), 0x01u64);
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(false, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(0, dn.rdn_count());
        }

        #[test]
        fn decode_32bit_from_tlv_successfully() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterCASEAuthTag as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a 0x1
            writer.put_u32(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u32);
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(1, dn.rdn_count());
            assert_eq!(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterCASEAuthTag as u16, dn.rdn[0].m_attr_oid);
            assert_eq!(0x01, dn.rdn[0].m_chip_val);
        }

        #[test]
        fn decode_non_matter_from_tlv_successfully() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let name = crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a 0x1
            writer.put_string(tlv_tags::context_tag((is_print_string | name)), "123");
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(1, dn.rdn_count());
            assert_eq!(crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u16, dn.rdn[0].m_attr_oid);
            assert_eq!(DefaultString::from("123"), dn.rdn[0].m_string);
        }

        #[test]
        fn equality() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let name = crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a 0x1
            writer.put_string(tlv_tags::context_tag((is_print_string | name)), "123");
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());
            assert_eq!(true, dn.is_equal(&dn));
        }

        #[test]
        fn zero_compare() {
            let mut dn = ChipDN::default();
            assert_eq!(false, dn.is_equal(&dn));
        }

        #[test]
        fn equality_different_content() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let name = crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            writer.put_string(tlv_tags::context_tag((is_print_string | name)), "123");
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());

            let mut raw_tlv1: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv1.as_mut_ptr(), raw_tlv1.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let name = crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            writer.put_string(tlv_tags::context_tag((is_print_string | name)), "456");
            // end container
            writer.end_container(outer_container);

            let mut dn1 = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv1.as_mut_ptr(), raw_tlv1.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn1.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());

            assert_eq!(false, dn.is_equal(&dn1));
        }

        #[test]
        fn equality_different_count() {
            const RAW_SIZE: usize = 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeList, &mut outer_container);
            // set up a tag number from matter id
            let name = crate::chip::asn1::Asn1Oid::KoidAttributeTypeCommonName as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            writer.put_string(tlv_tags::context_tag((is_print_string | name)), "123");
            // end container
            writer.end_container(outer_container);

            let mut dn = ChipDN::default();

            let mut reader: TlvContiguousBufferReader = TlvContiguousBufferReader::const_default();
            reader.init(raw_tlv.as_mut_ptr(), raw_tlv.len());
            // decode_from_tlv should be called after some outer paring function calls.
            // To simulate that, we just start the reader by next.
            reader.next();

            assert_eq!(true, dn.decode_from_tlv(&mut reader).inspect_err(|e| { println!("{:?}", e) }).is_ok());

            let mut dn1 = ChipDN::default();

            assert_eq!(false, dn.is_equal(&dn1));
        }

        #[test]
        fn get_net_identity_type() {
            let mut dn = ChipDN::default();

            assert!(dn.add_attribute_string(Asn1Oid::KoidAttributeTypeCommonName as Oid, internal::K_NETWORK_IDENTITY_CN, false).is_ok());
            assert!(dn.get_cert_type().is_ok_and(|t| t == CertType::KnetworkIdentity));
        }

        #[test]
        fn get_root_type() {
            let mut dn = ChipDN::default();

            assert!(dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterRCACId as Oid, 1).is_ok());
            assert!(dn.get_cert_type().is_ok_and(|t| t == CertType::Kroot));
        }

        #[test]
        fn get_node_id() {
            let mut dn = ChipDN::default();

            assert!(dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterFabricId as Oid, 1).is_ok());
            assert!(dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, 1).is_ok());
            assert!(dn.get_cert_type().is_ok_and(|t| t == CertType::Knode));
        }

        #[test]
        fn get_node_id_no_fabric_id() {
            let mut dn = ChipDN::default();

            assert!(dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, 1).is_ok());
            assert!(dn.get_cert_type().is_err());
        }

        #[test]
        fn no_type() {
            let dn = ChipDN::default();

            assert_eq!(true, dn.get_cert_type().is_ok_and(|t| t == CertType::KnotSpecified));
        }
    } // end of dn
    
    mod chip_certificate_data {
        use super::super::*;
        use crate::chip::chip_lib::core::{
            tlv_types::{self, TlvType},
            tlv_tags::{self, is_context_tag, tag_num_from_tag},
            //tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        };
        use crate::chip::crypto::{K_P256_PUBLIC_KEY_LENGTH, ECPKey, P256Keypair, ECPKeyTarget};

        #[test]
        fn extract_node_id_fabrid_id() {
            let mut cert = ChipCertificateData::default();
            assert_eq!(true, cert.m_subject_dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterNodeId.into(), 1).is_ok());
            assert_eq!(true, cert.m_subject_dn.add_attribute(Asn1Oid::KoidAttributeTypeMatterFabricId.into(), 2).is_ok());

            if let Ok((node_id, fabric_id)) = extract_node_id_fabric_id_from_op_cert(&cert) {
                assert_eq!(1, node_id);
                assert_eq!(2, fabric_id);
            } else {
                assert!(false);
            }
        }

        #[test]
        fn extract_node_id_fabrid_id_from_bytes() {
            const RAW_SIZE: usize = K_P256_PUBLIC_KEY_LENGTH + 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            assert_eq!(true, writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container).is_ok());

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut issuer_outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            assert_eq!(true, writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e)).is_ok());
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            assert_eq!(true, writer.end_container(outer_container_dn_list).is_ok());

            // make a stub public key
            let fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            // add to cert
            assert_eq!(true, writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), &fake_public_key[..]).inspect_err(|e| println!("{:?}", e)).is_ok());

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            // put a not after
            writer.put_u32(tag_not_after(), 0);

            // put a extension 
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            assert!(writer.start_container(context_tag(ChipCertTag::KtagExtensions as u8), tlv_types::TlvType::KtlvTypeList, &mut extensions_outer_container_list).is_ok());
            writer.end_container(extensions_outer_container_list);

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            if let Ok((node_id, fabric_id)) = extract_node_id_fabric_id_from_op_cert_byte(&raw_tlv[..writer.get_length_written()]).inspect_err(|e| println!("{:?}", e)) {
                assert_eq!(1, node_id);
                assert_eq!(2, fabric_id);
            } else {
                assert!(false);
            }
        }

        #[test]
        fn extract_public_key_from_bytes() {
            const RAW_SIZE: usize = K_P256_PUBLIC_KEY_LENGTH + 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            assert_eq!(true, writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container).is_ok());

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut issuer_outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            assert_eq!(true, writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e)).is_ok());
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            assert_eq!(true, writer.end_container(outer_container_dn_list).is_ok());

            // make a stub public key
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            for i in 0..K_P256_PUBLIC_KEY_LENGTH {
                fake_public_key[i] = i as u8;
            }
            // add to cert
            assert_eq!(true, writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), &fake_public_key[..]).inspect_err(|e| println!("{:?}", e)).is_ok());

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            // put a not after
            writer.put_u32(tag_not_after(), 0);

            // put a extension 
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            assert!(writer.start_container(context_tag(ChipCertTag::KtagExtensions as u8), tlv_types::TlvType::KtlvTypeList, &mut extensions_outer_container_list).is_ok());
            writer.end_container(extensions_outer_container_list);

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            if let Ok(key) = extract_public_key_from_chip_cert_byte(&raw_tlv[..writer.get_length_written()]).inspect_err(|e| println!("{:?}", e)) {
                assert_eq!(&fake_public_key[..], key.const_bytes());
            } else {
                assert!(false);
            }
        }

        #[test]
        fn equality() {
            const RAW_SIZE: usize = K_P256_PUBLIC_KEY_LENGTH + 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            assert_eq!(true, writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container).is_ok());

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut issuer_outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            assert_eq!(true, writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e)).is_ok());
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            assert_eq!(true, writer.end_container(outer_container_dn_list).is_ok());

            // make a stub public key
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            for i in 0..K_P256_PUBLIC_KEY_LENGTH {
                fake_public_key[i] = i as u8;
            }
            // add to cert
            assert_eq!(true, writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), &fake_public_key[..]).inspect_err(|e| println!("{:?}", e)).is_ok());

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            // put a not after
            writer.put_u32(tag_not_after(), 0);

            // put a extension 
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            assert!(writer.start_container(context_tag(ChipCertTag::KtagExtensions as u8), tlv_types::TlvType::KtlvTypeList, &mut extensions_outer_container_list).is_ok());
            writer.end_container(extensions_outer_container_list);

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            let mut cert1 = ChipCertificateData::default();
            let mut cert2 = ChipCertificateData::default();
            assert!(decode_chip_cert(&raw_tlv[..writer.get_length_written()], &mut cert1, None).is_ok());
            assert!(decode_chip_cert(&raw_tlv[..writer.get_length_written()], &mut cert2, None).is_ok());

            assert!(cert1.is_equal(&cert2));
        }

        #[test]
        fn not_same() {
            const RAW_SIZE: usize = K_P256_PUBLIC_KEY_LENGTH + 128;
            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            assert_eq!(true, writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container).is_ok());

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut issuer_outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            assert_eq!(true, writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e)).is_ok());
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            assert_eq!(true, writer.end_container(outer_container_dn_list).is_ok());

            // make a stub public key
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            for i in 0..K_P256_PUBLIC_KEY_LENGTH {
                fake_public_key[i] = i as u8;
            }
            // add to cert
            assert_eq!(true, writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), &fake_public_key[..]).inspect_err(|e| println!("{:?}", e)).is_ok());

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            // put a not after
            writer.put_u32(tag_not_after(), 0);

            // put a extension 
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            assert!(writer.start_container(context_tag(ChipCertTag::KtagExtensions as u8), tlv_types::TlvType::KtlvTypeList, &mut extensions_outer_container_list).is_ok());
            writer.end_container(extensions_outer_container_list);

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            let mut cert1 = ChipCertificateData::default();
            assert!(decode_chip_cert(&raw_tlv[..writer.get_length_written()], &mut cert1, None).is_ok());

            let mut raw_tlv: [u8; RAW_SIZE] = [0; RAW_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            assert_eq!(true, writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container).is_ok());

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut issuer_outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x01u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            assert_eq!(true, writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e)).is_ok());
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            // NOT SAME
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), 0x02u64);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), 0x02u64);
            // end of list conatiner
            assert_eq!(true, writer.end_container(outer_container_dn_list).is_ok());

            // make a stub public key
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            for i in 0..K_P256_PUBLIC_KEY_LENGTH {
                fake_public_key[i] = i as u8;
            }
            // add to cert
            assert_eq!(true, writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), &fake_public_key[..]).inspect_err(|e| println!("{:?}", e)).is_ok());

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            // put a not after
            writer.put_u32(tag_not_after(), 0);

            // put a extension 
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            assert!(writer.start_container(context_tag(ChipCertTag::KtagExtensions as u8), tlv_types::TlvType::KtlvTypeList, &mut extensions_outer_container_list).is_ok());
            writer.end_container(extensions_outer_container_list);

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            let mut cert2 = ChipCertificateData::default();
            assert!(decode_chip_cert(&raw_tlv[..writer.get_length_written()], &mut cert2, None).is_ok());

            assert_eq!(false, cert1.is_equal(&cert2));
        }
    } // end of chip_certificate_data

} // end of tests
