use crate::chip::{
    FabricId, NodeId,
    asn1::{Oid, Asn1Oid, get_oid, OidCategory},
    chip_lib::{
        core::{
            case_auth_tag::is_valid_case_auth_tag,
            data_model_types::is_valid_fabric_id,
            node_id::is_operational_node_id,
            tlv_types::TlvType,
            tlv_tags::{is_context_tag, tag_num_from_tag},
            chip_config::CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES,
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
        },
        support::default_string::DefaultString,
    },
    credentials::chip_cert_to_x509::decode_chip_cert as decode_chip_cert,
    crypto::{P256PublicKey, K_P256_PUBLIC_KEY_LENGTH}
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

/*
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;
*/

use crate::verify_or_return_error;
use crate::verify_or_return_value;

// we use this buffer to store the vid verification statement too
pub const K_MAX_CHIP_CERT_LENGTH: usize = crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE;
pub const K_MAX_RDN_STRING_LENGTH: usize = 10;
pub type ChipRDNString = DefaultString<K_MAX_RDN_STRING_LENGTH>;

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

// Not using now, just give it a type
#[derive(Copy, Clone, Default)]
pub enum CertDecodeFlags {
    #[default]
    KNone,
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
}

impl Default for ChipRDN {
    fn default() -> Self {
        ChipRDN::const_default()
    }
}

impl PartialEq for ChipRDN {
    fn eq(&self, other: &Self) -> bool {
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

impl Eq for ChipRDN {}

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
}

impl Default for ChipDN {
    fn default() -> Self {
        ChipDN::const_default()
    }
}

pub struct ChipCertificateData {
    pub m_subject_dn: ChipDN,
    pub m_public_key: [u8; K_P256_PUBLIC_KEY_LENGTH],
}

impl ChipCertificateData {
    pub const fn const_default() -> Self {
        Self {
            m_subject_dn: ChipDN::const_default(),
            m_public_key: [0; K_P256_PUBLIC_KEY_LENGTH],
        }
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
    decode_chip_cert(opcert, &mut op_cert, CertDecodeFlags::default())?;

    extract_node_id_fabric_id_from_op_cert(&op_cert)
}

pub fn extract_public_key_from_chip_cert(opcert: &ChipCertificateData) -> Result<P256PublicKey, ChipError> {
    Ok(P256PublicKey::default_with_raw_value(&opcert.m_public_key[..]))
}

pub fn extract_public_key_from_chip_cert_byte(opcert: &[u8]) -> Result<P256PublicKey, ChipError> {
    let mut op_cert: ChipCertificateData = ChipCertificateData::default();
    decode_chip_cert(opcert, &mut op_cert, CertDecodeFlags::default())?;

    extract_public_key_from_chip_cert(&op_cert)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(false, rdn1 == rdn2);
        }

        #[test]
        fn same_oid() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            assert_eq!(true, rdn1 == rdn2);
        }

        #[test]
        fn different_oid() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterNodeId as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeMatterFabricId as Oid;
            assert_eq!(false, rdn1 == rdn2);
        }

        #[test]
        fn not_matter_oid_same_string() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            assert_eq!(true, rdn1 == rdn2);
        }

        #[test]
        fn not_matter_oid_not_same_string() {
            let mut rdn1 = ChipRDN::default();
            let mut rdn2 = ChipRDN::default();
            rdn1.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn2.m_attr_oid = Asn1Oid::KoidAttributeTypeCommonName as Oid;
            rdn1.m_string = DefaultString::from("1");
            rdn2.m_string = DefaultString::from("2");
            assert_eq!(false, rdn1 == rdn2);
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
    } // end of dn
    
    mod chip_certificate_data {
        use super::super::*;
        use crate::chip::chip_lib::core::{
            tlv_types::{self, TlvType},
            tlv_tags::{self, is_context_tag, tag_num_from_tag},
            //tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        };
        use crate::chip::crypto::{K_P256_PUBLIC_KEY_LENGTH, ECPKey};

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

            // end struct container
            assert_eq!(true, writer.end_container(outer_container).is_ok());

            if let Ok(key) = extract_public_key_from_chip_cert_byte(&raw_tlv[..writer.get_length_written()]).inspect_err(|e| println!("{:?}", e)) {
                assert_eq!(&fake_public_key[..], key.const_bytes());
            } else {
                assert!(false);
            }
        }
    } // end of other

} // end of tests
