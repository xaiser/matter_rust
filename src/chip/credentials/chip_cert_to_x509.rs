use crate::chip::{
    credentials::chip_cert::{ChipCertificateData, CertDecodeFlags},
    chip_lib::core::tlv_reader::{TlvContiguousBufferReader, TlvReader},
};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;
use crate::chip_ok;

use crate::chip_error_not_implemented;

// Just make up a X509 format to make life easier, here is the format:
// SbujectDNs

pub fn decode_chip_cert(cert: &[u8], cert_data: &mut ChipCertificateData, decode_flag: CertDecodeFlags) -> ChipErrorResult {
    let mut reader = TlvContiguousBufferReader::const_default();

    reader.init(cert.as_ptr(), cert.len());

    return decode_chip_cert_with_reader(&mut reader, cert_data, decode_flag);
}

pub fn decode_chip_cert_with_reader<Reader: TlvReader>(reader: &mut Reader, cert_data: &mut ChipCertificateData, decode_flag: CertDecodeFlags) -> ChipErrorResult {
    return cert_data.m_subject_dn.decode_from_tlv(reader);
}
