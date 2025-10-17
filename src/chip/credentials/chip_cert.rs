use crate::chip::{
    asn1::{Oid, Asn1Oid},
    chip_lib::core::chip_config::CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES,
};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;
use crate::chip_ok;

use crate::chip_error_invalid_argument;
use crate::chip_error_not_implemented;
use crate::chip_error_no_memory;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

// we use this buffer to store the vid verification statement too
pub const K_MAX_CHIP_CERT_LENGTH: usize = crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE;
pub const K_MAX_RDN_STRING_LENGTH: usize = 10;

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
    m_string: [u8; K_MAX_RDN_STRING_LENGTH],
    m_chip_val: u64,
    m_attr_oid: Oid,
    m_attr_is_printable_string: bool,
}

impl ChipRDN {
    pub const fn const_default() -> Self {
        Self {
            m_string: [0; K_MAX_RDN_STRING_LENGTH],
            m_chip_val: 0,
            m_attr_oid: Asn1Oid::KoidNotSpecified as Oid,
            m_attr_is_printable_string: false,
        }
    }

    pub fn clear(&mut self) {
        self.m_string = [0; K_MAX_RDN_STRING_LENGTH];
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

    pub fn add_attribute_printable(&mut self, oid: Oid, val: u64, is_printable_string: bool) -> ChipErrorResult {
        let rdn_count = self.rdn_count() as usize;
        verify_or_return_error!(rdn_count < CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES, Err(chip_error_no_memory!()));
        verify_or_return_error!(!is_chip_dn_attr(oid), Err(chip_error_invalid_argument!()));
        verify_or_return_error!(oid != Asn1Oid::KoidNotSpecified.into(), Err(chip_error_invalid_argument!()));

        self.rdn[rdn_count].m_attr_oid = oid;
        self.rdn[rdn_count].m_chip_val = val;
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
}

impl Default for ChipDN {
    fn default() -> Self {
        ChipDN::const_default()
    }
}

pub struct ChipCertificateData {
    m_subject_dn: ChipDN,
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
            rdn1.m_string[0] = 0;
            rdn1.m_string[0] = 1;
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
            
            assert_eq!(true, dn.add_attribute_printable(Asn1Oid::KoidAttributeTypeCommonName.into(), 1, true).is_ok());
        }

        #[test]
        fn add_oid_printable_not_specified_oid() {
            let mut dn = ChipDN::default();
            
            assert_eq!(false, dn.add_attribute_printable(Asn1Oid::KoidNotSpecified.into(), 1, true).is_ok());
        }
    } // end of dn

} // end of tests
