use crate::chip::{
    asn1::Oid,
    chip_lib::{
        core::{
            tlv_reader::{TlvContiguousBufferReader, TlvReader},
            tlv_tags::{anonymous_tag, context_tag, is_context_tag, tag_num_from_tag, Tag},
            tlv_types::TlvType,
        },
        asn1::asn1_writer::{Asn1Writer, NullAsn1Writer},
    },
    credentials::chip_cert::{
        tag_not_after, tag_not_before, CertDecodeFlags, CertFlags, ChipCertExtensionTag,
        ChipCertTag, ChipCertificateData, KeyPurposeFlags, KeyUsageFlags,
    },
};

use crate::chip_core_error;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_error_end_of_tlv;
use crate::chip_error_invalid_tlv_tag;
use crate::chip_error_no_memory;
use crate::chip_error_not_implemented;
use crate::chip_error_unsupported_cert_format;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use core::str::FromStr;

use crate::verify_or_return_error;
use crate::verify_or_return_value;

use bitflags::Flags;

pub fn decode_chip_cert(
    cert: &[u8],
    cert_data: &mut ChipCertificateData,
    decode_flag: Option<CertDecodeFlags>,
) -> ChipErrorResult {
    let mut reader = TlvContiguousBufferReader::const_default();

    reader.init(cert.as_ptr(), cert.len());

    let mut writer = NullAsn1Writer::default();

    return decode_chip_cert_with_reader(&mut reader, &mut writer, cert_data, decode_flag);
}

pub fn decode_subject_public_key_info<'a, Reader: TlvReader<'a>, Writer: Asn1Writer>(
    reader: &mut Reader,
    writer: &mut Writer,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    reader.next_type_tag(
        TlvType::KtlvTypeByteString,
        context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8),
    )?;
    let raw_bytes = reader.get_bytes()?;
    verify_or_return_error!(
        raw_bytes.len() == cert_data.m_public_key.len(),
        Err(chip_error_no_memory!())
    );

    // TODO: use the public key algo oid
    writer.put_object_id(cert_data.m_sig_algo_OID as Oid)?;

    cert_data.m_public_key.copy_from_slice(raw_bytes);

    writer.put_bit_string(0, &cert_data.m_public_key[..])?;

    chip_ok!()
}

pub fn decode_convert_authority_key_identifier_extension<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    cert_data
        .m_cert_flags
        .insert(CertFlags::KextPresentAuthKeyId);

    reader.expect_type_tag(
        TlvType::KtlvTypeByteString,
        context_tag(ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8),
    )?;
    let key = reader.get_bytes()?;

    if key.len() != cert_data.m_auth_key_id.len() {
        return Err(chip_error_invalid_tlv_tag!());
    }

    cert_data.m_auth_key_id.copy_from_slice(key);

    chip_ok!()
}

pub fn decode_convert_subject_key_identifier_extension<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    cert_data
        .m_cert_flags
        .insert(CertFlags::KextPresentSubjectKeyId);

    reader.expect_type_tag(
        TlvType::KtlvTypeByteString,
        context_tag(ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8),
    )?;
    let key = reader.get_bytes()?;

    if key.len() != cert_data.m_subject_key_id.len() {
        return Err(chip_error_invalid_tlv_tag!());
    }

    cert_data.m_subject_key_id.copy_from_slice(key);

    chip_ok!()
}

pub fn decode_convert_key_usage_extension<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    cert_data
        .m_cert_flags
        .insert(CertFlags::KextPresentKeyUsage);

    reader.expect(context_tag(ChipCertExtensionTag::KtagKeyUsage as u8))?;
    let key_usage_bits = reader.get_u16()?;

    {
        if let Some(key_usage_flags) = KeyUsageFlags::from_bits(key_usage_bits) {
            cert_data.m_key_usage_flags = key_usage_flags;
        } else {
            return Err(chip_error_unsupported_cert_format!());
        }
    }

    chip_ok!()
}

pub fn decode_convert_extended_key_usage_extension<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    cert_data
        .m_cert_flags
        .insert(CertFlags::KextPresentExtendedKeyUsage);

    reader.expect_type_tag(
        TlvType::KtlvTypeArray,
        context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
    )?;

    let container_type = reader.enter_container()?;

    let mut err = chip_error_end_of_tlv!();

    while reader
        .next_tag(anonymous_tag())
        .inspect_err(|e| err = *e)
        .is_ok()
    {
        let key_purpose_id = reader.get_u8()?;

        if let Some(key_purpose_flags) = KeyPurposeFlags::from_bits(key_purpose_id) {
            cert_data.m_key_purpose_flags.insert(key_purpose_flags);
        } else {
            return Err(chip_error_unsupported_cert_format!());
        }
    }

    verify_or_return_error!(err == chip_error_end_of_tlv!(), Err(err));

    reader.exit_container(container_type)?;

    chip_ok!()
}

pub fn decode_extension<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    let tlv_tag = reader.get_tag();

    verify_or_return_error!(is_context_tag(&tlv_tag), Err(chip_error_invalid_tlv_tag!()));

    let extension_tag_num = tag_num_from_tag(&tlv_tag);

    if extension_tag_num == ChipCertExtensionTag::KtagFutureExtension as u32 {
        return Err(chip_error_not_implemented!());
    } else {
        match extension_tag_num {
            v if v == ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u32 => {
                decode_convert_authority_key_identifier_extension(reader, cert_data)?;
            }
            v if v == ChipCertExtensionTag::KtagSubjectKeyIdentifier as u32 => {
                decode_convert_subject_key_identifier_extension(reader, cert_data)?;
            }
            v if v == ChipCertExtensionTag::KtagKeyUsage as u32 => {
                decode_convert_key_usage_extension(reader, cert_data)?;
            }
            v if v == ChipCertExtensionTag::KtagBasicConstraints as u32 => {
                return Err(chip_error_not_implemented!());
            }
            v if v == ChipCertExtensionTag::KtagExtendedKeyUsage as u32 => {
                decode_convert_extended_key_usage_extension(reader, cert_data)?;
            }
            _ => {
                return Err(chip_error_unsupported_cert_format!());
            }
        }
    }

    chip_ok!()
}

pub fn decode_extensions<'a, Reader: TlvReader<'a>>(
    reader: &mut Reader,
    cert_data: &mut ChipCertificateData,
) -> ChipErrorResult {
    reader.next_type_tag(
        TlvType::KtlvTypeList,
        context_tag(ChipCertTag::KtagExtensions as u8),
    )?;
    let container_type = reader.enter_container()?;

    let mut err = chip_error_end_of_tlv!();

    while reader.next().inspect_err(|e| err = *e).is_ok() {
        decode_extension(reader, cert_data)?;
    }

    verify_or_return_error!(err == chip_error_end_of_tlv!(), Err(err));

    reader.exit_container(container_type)?;

    chip_ok!()
}

pub fn decode_chip_cert_with_reader<'a, Reader: TlvReader<'a>, Writer: Asn1Writer>(
    reader: &mut Reader,
    writer: &mut Writer,
    cert_data: &mut ChipCertificateData,
    decode_flag: Option<CertDecodeFlags>,
) -> ChipErrorResult {
    if reader.get_type() == TlvType::KtlvTypeNotSpecified {
        reader.next()?;
    }

    reader.expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
    let container_type = reader.enter_container()?;

    // start reading
    reader.next()?;

    // get issuer DNs
    cert_data.m_issuer_dn.decode_from_tlv(reader)?;

    reader.next()?;
    // get subject DNs
    cert_data.m_subject_dn.decode_from_tlv(reader)?;

    // get public key
    decode_subject_public_key_info(reader, writer, cert_data)?;

    // get validity
    // not before time
    reader.next_tag(tag_not_before())?;
    cert_data.m_not_before_time = reader.get_u32()?;
    // not after time
    reader.next_tag(tag_not_after())?;
    cert_data.m_not_after_time = reader.get_u32()?;

    // get extensions
    decode_extensions(reader, cert_data)?;

    reader.verify_end_of_container()?;

    reader.exit_container(container_type)?;

    if let Some(flags) = decode_flag {
        if flags.contains(CertDecodeFlags::KisTrustAnchor) {
            cert_data.m_cert_flags.insert(CertFlags::KisTrustAnchor);
        }
    }

    chip_ok!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::{
        chip_lib::core::{
            tlv_tags::{self, anonymous_tag},
            tlv_types::{self, TlvType},
            tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        },
        credentials::chip_cert,
    };

    const TEST_BUT_SIZE: usize = 512;

    #[test]
    fn decode_auth_key_id_correctly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_bytes(
                context_tag(ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8),
                &key
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert_eq!(1, cert.m_auth_key_id[0]);
        assert_eq!(
            2,
            cert.m_auth_key_id[chip_cert::K_KEY_IDENTIFIER_LENGTH - 1]
        );
        assert!(cert.m_cert_flags.contains(CertFlags::KextPresentAuthKeyId));
    }

    #[test]
    fn decode_auth_key_id_with_wrong_length() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_bytes(
                context_tag(ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8),
                &key[0..1]
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_err());
        // still setup
        assert!(cert.m_cert_flags.contains(CertFlags::KextPresentAuthKeyId));
    }

    #[test]
    fn decode_subject_key_id_correctly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_bytes(
                context_tag(ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8),
                &key
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert_eq!(1, cert.m_subject_key_id[0]);
        assert_eq!(
            2,
            cert.m_subject_key_id[chip_cert::K_KEY_IDENTIFIER_LENGTH - 1]
        );
        assert!(cert
            .m_cert_flags
            .contains(CertFlags::KextPresentSubjectKeyId));
    }

    #[test]
    fn decode_key_usage_correctlly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        let expected_usage = KeyUsageFlags::KdigitalSignature.bits() as u16;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_u16(
                context_tag(ChipCertExtensionTag::KtagKeyUsage as u8),
                expected_usage
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert_eq!(KeyUsageFlags::KdigitalSignature, cert.m_key_usage_flags);
    }

    #[test]
    fn decode_incorrect_key_usage() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        let incorrect_key_usage = 0x8000u16;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_u16(
                context_tag(ChipCertExtensionTag::KtagKeyUsage as u8),
                incorrect_key_usage
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(!decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
    }

    #[test]
    fn decode_extended_key_usage_correctlly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());

        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());

        let mut outer_container_array = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start an array
        assert!(writer
            .start_container(
                context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
                tlv_types::TlvType::KtlvTypeArray,
                &mut outer_container_array
            )
            .is_ok());

        let expected_key_usage = KeyPurposeFlags::KserverAuth.bits();
        assert!(writer
            .put_u8(anonymous_tag(), expected_key_usage)
            .inspect_err(|e| println!("{}", e))
            .is_ok());

        writer.end_container(outer_container_array);

        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert_eq!(KeyPurposeFlags::KserverAuth, cert.m_key_purpose_flags);
    }

    #[test]
    fn decode_two_extended_key_usage_correctlly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());

        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());

        let mut outer_container_array = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start an array
        assert!(writer
            .start_container(
                context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
                tlv_types::TlvType::KtlvTypeArray,
                &mut outer_container_array
            )
            .is_ok());

        let expected_key_usage = KeyPurposeFlags::KserverAuth.bits();
        let expected_key_usage2 = KeyPurposeFlags::KclientAuth.bits();
        assert!(writer
            .put_u8(anonymous_tag(), expected_key_usage)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert!(writer
            .put_u8(anonymous_tag(), expected_key_usage2)
            .inspect_err(|e| println!("{}", e))
            .is_ok());

        writer.end_container(outer_container_array);

        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert!(cert
            .m_key_purpose_flags
            .contains(KeyPurposeFlags::KserverAuth | KeyPurposeFlags::KclientAuth));
    }

    #[test]
    fn decode_incorrect_extended_key_usage() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());

        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());

        let mut outer_container_array = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start an array
        assert!(writer
            .start_container(
                context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
                tlv_types::TlvType::KtlvTypeArray,
                &mut outer_container_array
            )
            .is_ok());

        let expected_key_usage = 0x80u8;
        assert!(writer
            .put_u8(anonymous_tag(), expected_key_usage)
            .inspect_err(|e| println!("{}", e))
            .is_ok());

        writer.end_container(outer_container_array);

        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(!decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
    }

    #[test]
    fn decode_auth_key_id_and_subject_key_id_correctly() {
        // first, build up a fake extensions
        let mut raw_tlv = [0; TEST_BUT_SIZE];
        let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
        writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

        let mut key = [0; chip_cert::K_KEY_IDENTIFIER_LENGTH];
        key[0] = 1;
        key[key.len() - 1] = 2;

        let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
        // start a struct
        assert!(writer
            .start_container(
                anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container
            )
            .is_ok());
        let mut outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;

        // start a list
        assert!(writer
            .start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut outer_container_list
            )
            .is_ok());
        assert!(writer
            .put_bytes(
                context_tag(ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8),
                &key
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        key[0] = 3;
        key[key.len() - 1] = 4;
        assert!(writer
            .put_bytes(
                context_tag(ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8),
                &key
            )
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        writer.end_container(outer_container_list);

        writer.end_container(outer_container);

        let tlv_buffer = &raw_tlv[..writer.get_length_written()];

        // create the reader
        let mut reader = TlvContiguousBufferReader::const_default();
        reader.init(tlv_buffer.as_ptr(), tlv_buffer.len());

        let mut cert = ChipCertificateData::default();

        reader.next();
        // enter the struct to simulate what we do in decode_chip_cert
        assert!(reader
            .expect_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())
            .is_ok());
        let container_type = reader.enter_container();

        assert!(decode_extensions(&mut reader, &mut cert)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
        assert_eq!(1, cert.m_auth_key_id[0]);
        assert_eq!(
            2,
            cert.m_auth_key_id[chip_cert::K_KEY_IDENTIFIER_LENGTH - 1]
        );
        assert!(cert.m_cert_flags.contains(CertFlags::KextPresentAuthKeyId));
        assert_eq!(3, cert.m_subject_key_id[0]);
        assert_eq!(
            4,
            cert.m_subject_key_id[chip_cert::K_KEY_IDENTIFIER_LENGTH - 1]
        );
        assert!(cert
            .m_cert_flags
            .contains(CertFlags::KextPresentSubjectKeyId));
    }
} // end of mod tests
