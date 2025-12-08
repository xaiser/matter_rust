use crate::chip::{
    credentials::chip_cert::{ChipCertificateData, CertDecodeFlags, ChipCertTag, tag_not_before, tag_not_after},
    chip_lib::core::{
        tlv_types::TlvType,
        tlv_tags::{anonymous_tag, context_tag, Tag},
        tlv_reader::{TlvContiguousBufferReader, TlvReader},
    },
};

use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;
use crate::chip_ok;

use crate::chip_error_not_implemented;
use crate::chip_error_no_memory;

/*
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;
*/

use crate::verify_or_return_error;
use crate::verify_or_return_value;

// Just make up a X509 format to make life easier, here is the format:
// struct {
//     SbujectDNs: [..]
//     ECPublicKey
//     NotBeforeTime
//     NotAfterTime
// }

pub fn decode_chip_cert(cert: &[u8], cert_data: &mut ChipCertificateData, decode_flag: CertDecodeFlags) -> ChipErrorResult {
    let mut reader = TlvContiguousBufferReader::const_default();

    reader.init(cert.as_ptr(), cert.len());

    return decode_chip_cert_with_reader(&mut reader, cert_data, decode_flag);
}

pub fn decode_subject_public_key_info<'a, Reader: TlvReader<'a>>(reader: &mut Reader, cert_data: &mut ChipCertificateData) -> ChipErrorResult {
    reader.next_type_tag(TlvType::KtlvTypeByteString, context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8))?;
    let raw_bytes = reader.get_bytes()?;
    verify_or_return_error!(raw_bytes.len() == cert_data.m_public_key.len(), Err(chip_error_no_memory!()));

    cert_data.m_public_key.copy_from_slice(raw_bytes);

    chip_ok!()
}

pub fn decode_chip_cert_with_reader<'a, Reader: TlvReader<'a>>(reader: &mut Reader, cert_data: &mut ChipCertificateData, decode_flag: CertDecodeFlags) -> ChipErrorResult {
    if reader.get_type() == TlvType::KtlvTypeNotSpecified {
        reader.next()?;
    }

    reader.expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
    let container_type = reader.enter_container()?;

    // start reading
    reader.next()?;

    // get subject DNs
    cert_data.m_subject_dn.decode_from_tlv(reader)?;
    
    // get public key
    decode_subject_public_key_info(reader, cert_data);

    // get validity
    // not before time
    reader.next_tag(tag_not_before())?;
    cert_data.m_not_before_time= reader.get_u32()?;
    // not after time
    reader.next_tag(tag_not_after())?;
    cert_data.m_not_after_time = reader.get_u32()?;

    reader.verify_end_of_container()?;

    reader.exit_container(container_type)
}
