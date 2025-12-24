pub use chip_certificate_set::*;

mod chip_certificate_set {
    /*
    use crate::chip::{
        CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
        system::system_clock::Seconds32,
        chip_lib::{
            core::{
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                case_auth_tag::CatValues,
                tlv_types::TlvType,
                tlv_tags::{self, anonymous_tag},
                data_model_types::{
                    KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX, is_valid_fabric_index,
                    KMIN_VALID_FABRIC_INDEX, KMAX_VALID_FABRIC_INDEX, FabricIndex,
                },
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                chip_encoding,
            },
            support::{
                default_string::DefaultString,
                default_storage_key_allocator::DefaultStorageKeyAllocator,
            }
        },
        credentials::{
            self, last_known_good_time::LastKnownGoodTime, chip_certificate_set::ValidationContext,
            certificate_validity_policy::CertificateValidityPolicy, operational_certificate_store::{CertChainElement, OperationalCertificateStore},
            chip_cert::{CertBuffer, K_MAX_CHIP_CERT_LENGTH, extract_public_key_from_chip_cert_byte, extract_node_id_fabric_id_from_op_cert_byte},
        },
        crypto::{
            self,
            generate_compressed_fabric_id,
            crypto_pal::{P256EcdsaSignature, P256Keypair, P256PublicKey, ECPKey, ECPKeypair, P256KeypairBase, P256SerializedKeypair},
        },
    };
    use crate::chip_core_error;
    use crate::chip_error_invalid_argument;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_key_not_found;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipErrorResult;
    use crate::ChipError;

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use crate::chip_log_progress;

    use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES};
    use core::{ptr, str::{self, FromStr}};
    */
    use crate::chip::{
        asn1::Asn1Oid,
        system::system_clock::Seconds32,
        chip_lib::{
            core::{
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
            },
        },
        credentials::{
            certificate_validity_policy::CertificateValidityPolicy,
            chip_cert::{CertFlags, KeyUsageFlags, KeyPurposeFlags, ChipCertificateData, CertType, CertDecodeFlags, decode_chip_cert_with_reader, CertificateKeyId},
        },
        crypto::{P256PublicKey, ECPKey, P256EcdsaSignature, K_SHA256_HASH_LENGTH},
    };

    use crate::chip_core_error;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipErrorResult;
    use crate::ChipError;
    use crate::{chip_error_unsupported_cert_format, chip_error_unsupported_signature_type, chip_error_no_memory, chip_error_internal,
       chip_error_invalid_argument};

    enum EffectiveTime {
        CurrentChipEpochTime(Seconds32),
        LastKnownGoodChipEpochTime(Seconds32),
    }

    pub struct ValidationContext<'a, ValidityPolicy> 
        where
            ValidityPolicy: CertificateValidityPolicy,
    {
        pub m_effective_time: EffectiveTime,
        pub m_trust_anchor: Option<&'a ChipCertificateData>,
        pub m_required_key_usages: KeyUsageFlags,
        pub m_required_key_purpose: KeyPurposeFlags,
        pub m_required_cert_type: CertType,
        pub m_validity_policy: Option<&'a ValidityPolicy>,
    }

    impl<'a, ValidityPolicy> ValidationContext<'a, ValidityPolicy>
        where
            ValidityPolicy: CertificateValidityPolicy,
    {
        pub const fn new() -> Self {
            Self {
                m_effective_time: EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(0)),
                m_trust_anchor: None,
                m_required_key_usages: KeyUsageFlags::KdigitalSignature,
                m_required_key_purpose: KeyPurposeFlags::KserverAuth,
                m_required_cert_type: CertType::KnotSpecified,
                m_validity_policy: None,
            }
        }

        pub fn set_effective_time(&mut self, chip_time: EffectiveTime) {
            self.m_effective_time = chip_time;
        }
    }

    const K_MAX_ARRAY_SIZE: usize = 3usize;

    // TODO: add an option to use storage from caller.
    // Check cre/credentials/CHIPCert.cpp: Init(certsArray, certsArraySize)
    pub struct ChipCertificateSet {
        //m_certs_internal_storage: [ChipCertificateData; K_MAX_ARRAY_SIZE],
        m_certs_internal_storage: [Option<ChipCertificateData>; K_MAX_ARRAY_SIZE],
        m_cert_count: u8,
    }

    impl ChipCertificateSet {
        pub const fn new() -> Self {
            /*
            use core::mem::MaybeUninit;
            let mut certs: [MaybeUninit<ChipCertificateData>; K_MAX_ARRAY_SIZE] = [ const { MaybeUninit::uninit() }; K_MAX_ARRAY_SIZE];
            let mut index: usize = 0;

            while index < K_MAX_ARRAY_SIZE {
                certs[index].write(ChipCertificateData::const_default());
                index += 1;
            }

            unsafe {
                Self {
                    m_certs_internal_storage: core::mem::transmute::<_, [ChipCertificateData; K_MAX_ARRAY_SIZE]>(certs),
                    m_cert_count: 0,
                }
            }
            */
            Self {
                m_certs_internal_storage: [const { None }; K_MAX_ARRAY_SIZE],
                m_cert_count: 0,
            }
        }

        fn release(&mut self) {
            self.clear();
        }

        fn clear(&mut self) {
            for cert in self.m_certs_internal_storage.iter_mut() {
                //cert.clear();
                if let Some(ref mut c) = cert {
                    c.clear();
                }
                *cert = None;
            }
            self.m_cert_count = 0;
        }

        pub fn load_cert(&mut self, chip_cert: &[u8], decode_flags: CertDecodeFlags) -> ChipErrorResult {
            let mut reader = TlvContiguousBufferReader::default();

            reader.init(chip_cert.as_ptr(), chip_cert.len());

            return self.load_cert_reader(&mut reader, decode_flags, chip_cert);
        }

        pub fn load_cert_reader<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader, decode_flags: CertDecodeFlags, chip_cert: &[u8]) -> ChipErrorResult {
            let mut cert = ChipCertificateData::default();
            decode_chip_cert_with_reader(reader, &mut cert, Some(decode_flags))?;

            // Verify the cert has both the Subject Key Id and Authority Key Id extensions present.
            // Only certs with both these extensions are supported for the purposes of certificate validation.
            verify_or_return_error!(cert.m_cert_flags.contains(CertFlags::KextPresentSubjectKeyId | CertFlags::KextPresentAuthKeyId),
                                Err(chip_error_unsupported_cert_format!()));

            // Verify the cert was signed with ECDSA-SHA256. This is the only signature algorithm currently supported.
            verify_or_return_error!(cert.m_sig_algo_OID == Asn1Oid::KoidSigAlgoECDSAWithSHA256.into(), Err(chip_error_unsupported_signature_type!()));

            for internal_cert in self.m_certs_internal_storage.iter() {
                if internal_cert.as_ref().is_some_and(|c| c.is_equal(&cert)) {
                    return chip_ok!();
                }
            }

            verify_or_return_error!((self.m_cert_count as usize) < K_MAX_ARRAY_SIZE, Err(chip_error_no_memory!()));

            self.m_certs_internal_storage[self.m_cert_count as usize] = Some(cert);

            self.m_cert_count += 1;

            chip_ok!()
        }

        pub fn release_last_cert(&mut self) -> ChipErrorResult {
            if self.m_cert_count > 0 {
                self.m_certs_internal_storage[(self.m_cert_count - 1) as usize] = None;
                self.m_cert_count -= 1;

                chip_ok!()
            } else {
                Err(chip_error_internal!())
            }
        }

        pub fn find_cert(&self, subject_key_id: &CertificateKeyId) -> Option<&ChipCertificateData> {
            for i in 0..self.m_cert_count as usize {
                if let Some(ref cert) = self.m_certs_internal_storage[i] {
                    if cert.m_subject_key_id == *subject_key_id {
                        return Some(cert);
                    }
                }
            }

            None
        }

        pub fn is_cert_in_the_set(&self, cert: &ChipCertificateData) -> bool {
            for i in 0..self.m_cert_count as usize {
                if let Some(ref current_cert) = self.m_certs_internal_storage[i] {
                    if core::ptr::eq(cert, current_cert) {
                        return true;
                    }
                }
            }

            false
        }

        pub fn validate_cert<Policy: CertificateValidityPolicy>(&self, cert: &ChipCertificateData, context: &mut ValidationContext<Policy>) -> ChipErrorResult {
            verify_or_return_error!(self.is_cert_in_the_set(cert), Err(chip_error_invalid_argument!()));

            context.m_trust_anchor = None;

            return self.validate_cert_depth(cert, context, 0);
        }

        pub fn validate_cert_depth<Policy: CertificateValidityPolicy>(&self, cert: &ChipCertificateData, context: &mut ValidationContext<Policy>, depth: u8) -> ChipErrorResult {
            chip_ok!()
        }


        pub fn get_cert_count(&self) -> u8 {
            self.m_cert_count
        }

        pub fn get_cert_sets(&self) -> &[Option<ChipCertificateData>] {
            &self.m_certs_internal_storage
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        use crate::chip::{
            credentials::{
                chip_cert::tests::make_subject_key_id,
                fabric_table::fabric_info::tests::{stub_public_key, make_chip_cert},
            },
        };

        #[test]
        fn new() {
            let sets = ChipCertificateSet::new();
            assert_eq!(0, sets.get_cert_count());
        }

        #[test]
        fn load_one_cert_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert_eq!(1, sets.get_cert_count());
        }

        #[test]
        fn load_two_cert_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            let cert2 = make_chip_cert(3, 4, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(sets.load_cert(cert2.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert_eq!(2, sets.get_cert_count());
        }

        #[test]
        fn load_one_cert_twice_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert_eq!(1, sets.get_cert_count());
        }

        #[test]
        fn release_last_cert_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(sets.release_last_cert().is_ok());
        }

        #[test]
        fn find_cert() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());

            // this is the key in make_chip_cert
            let key = make_subject_key_id(3, 4);
            assert!(sets.find_cert(&key).is_some());
        }

        #[test]
        fn is_cert_in_the_sets() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets.load_cert(cert.const_bytes(), CertDecodeFlags::Knone).inspect_err(|e| println!("{}", e)).is_ok());

            // this is the key in make_chip_cert
            let key = make_subject_key_id(3, 4);
            let found_cert = sets.find_cert(&key);

            assert!(found_cert.is_some());
            assert!(sets.is_cert_in_the_set(found_cert.unwrap()));
        }
    } // end of tests
}
