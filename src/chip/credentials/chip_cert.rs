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

use crate::verify_or_return_error;
use crate::verify_or_return_value;

// we use this buffer to store the vid verification statement too
pub const K_MAX_CHIP_CERT_LENGTH: usize = crate::chip::crypto::K_VENDOR_ID_VERIFICATION_STATEMENT_V1_SIZE;
pub const K_MAX_RDN_STRING_LENGTH: usize = 10;

#[inline]
fn is_chip_64bit_dn_attr(oid: Oid) -> bool {
    return oid == Asn1Oid::KoidAttributeTypeMatterNodeId as u16 ||
        oid == Asn1Oid::KoidAttributeTypeMatterFirmwareSigningId as u16 ||
        oid == Asn1Oid::KoidAttributeTypeMatterICACId as u16 ||
        oid == Asn1Oid::KoidAttributeTypeMatterRCACId as u16 ||
        oid == Asn1Oid::KoidAttributeTypeMatterFabricId as u16 ||
        oid == Asn1Oid::KoidAttributeTypeMatterVidVerificationSignerId as u16;
}

#[inline]
fn is_chip_32bit_dn_attr(oid: Oid) -> bool {
    return oid == Asn1Oid::KoidAttributeTypeMatterCASEAuthTag as u16;
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
            m_attr_oid: Asn1Oid::KoidNotSpecified as u16,
            m_attr_is_printable_string: false,
        }
    }

    pub fn clear(&mut self) {
        self.m_string = [0; K_MAX_RDN_STRING_LENGTH];
        self.m_chip_val = 0;
        self.m_attr_oid = Asn1Oid::KoidNotSpecified as u16;
        self.m_attr_is_printable_string = false;
    }

    pub fn is_empty(&self) -> bool {
        self.m_attr_oid == Asn1Oid::KoidNotSpecified as u16
    }
}

impl Default for ChipRDN {
    fn default() -> Self {
        ChipRDN::const_default()
    }
}

impl PartialEq for ChipRDN {
    fn eq(&self, other: &Self) -> bool {
        if self.m_attr_oid == Asn1Oid::KoidUnknown as u16 || self.m_attr_oid == Asn1Oid::KoidNotSpecified as u16 || self.m_attr_oid != other.m_attr_oid ||
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
        Err(chip_error_not_implemented!())
    }

    pub fn add_attribute_printable(&mut self, oid: Oid, val: u64, is_printable_string: bool) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
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
