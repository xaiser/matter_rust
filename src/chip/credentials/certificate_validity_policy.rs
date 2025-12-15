// just mock it now
pub struct CertificateValidityPolicy(u8);

pub trait TheCertificateValidityPolicy { }

impl TheCertificateValidityPolicy for CertificateValidityPolicy {}
