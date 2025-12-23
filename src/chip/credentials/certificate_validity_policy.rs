pub mod certificate_validity_policy {
    use crate::{
        chip_core_error,
        chip_sdk_error,
        ChipError,
        ChipErrorResult,
        chip::{
            credentials::chip_cert::ChipCertificateData,
        },
    };
    pub enum CertificateValidityResult {
        Kvalid                         = 0, // current time is known and is within the validity period bounded by [notBefore, notAfter]
        KnotYetValid                   = 1, // current time is known and falls before the validity period bounded by notBefore
        Kexpired                       = 2, // current time is known and falls after the validity period bounded by notAfter
        KnotExpiredAtLastKnownGoodTime = 3, // Last Known Good Time is known and notAfter occurs at or after this
        KexpiredAtLastKnownGoodTime    = 4, // Last Known Good Time is known and notAfter occurs before this
        KtimeUnknown                   = 5, // No time source is available
    }

    //pub struct CertificateValidityPolicy(u8);

    pub trait CertificateValidityPolicy { 
        fn apply_certificate_validity_policy(&self, cert: &ChipCertificateData, depth: u8) -> Result<CertificateValidityResult, ChipError>;
    }

    pub struct IgnoreCertificateValidityPeriodPolicy;

    impl CertificateValidityPolicy for IgnoreCertificateValidityPeriodPolicy {
        fn apply_certificate_validity_policy(&self, _cert: &ChipCertificateData, _depth: u8) -> Result<CertificateValidityResult, ChipError> {
            Ok(CertificateValidityResult::Kvalid)
        }
    }


    pub fn apply_default_policy(_cert: &ChipCertificateData, _depth: u8) -> Result<CertificateValidityResult, ChipError> {
        Ok(CertificateValidityResult::Kvalid)
    }
} // certificate_validity_policy

pub use certificate_validity_policy::*;
