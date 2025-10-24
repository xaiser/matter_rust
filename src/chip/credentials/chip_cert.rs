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

use crate::verify_or_return_error;
use crate::verify_or_return_value;

// we use this buffer to store the vid verification statement too
pub const K_MAX_CHIP_CERT_LENGTH: usize = crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE;
pub const K_MAX_RDN_STRING_LENGTH: usize = 10;
pub type ChipRDNString = DefaultString<K_MAX_RDN_STRING_LENGTH>;

// Not using now, just give it a type
#[derive(Copy, Clone)]
pub enum CertDecodeFlags {}

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

    pub fn decode_from_tlv<Reader: TlvReader>(&mut self, reader: &mut Reader) -> ChipErrorResult {
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
            }

        }

        Err(chip_error_invalid_argument!())
    }
}

impl Default for ChipDN {
    fn default() -> Self {
        ChipDN::const_default()
    }
}

pub struct ChipCertificateData {
    pub m_subject_dn: ChipDN,
}

impl ChipCertificateData {
    pub const fn const_default() -> Self {
        Self {
            m_subject_dn: ChipDN::const_default(),
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
            assert_eq!(false, rdn1 == rdn2);
        }
    } // end of rdn
    
    mod dn {
        use super::super::*;

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
    } // end of dn
    
    mod chip_certificate_data {
        use super::super::*;

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
    } // end of other

} // end of tests
