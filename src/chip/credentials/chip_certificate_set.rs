pub use chip_certificate_set::*;

mod chip_certificate_set {
    use crate::chip::{
        asn1::Asn1Oid,
        chip_lib::{
            core::tlv_reader::{TlvContiguousBufferReader, TlvReader},
            asn1::asn1_writer::{Asn1Writer, NullAsn1Writer},
        },
        credentials::{
            certificate_validity_policy::{
                apply_default_policy, CertificateValidityPolicy, CertificateValidityResult,
            },
            chip_cert::{
                decode_chip_cert_with_reader, verify_cert_signature, CertDecodeFlags, CertFlags,
                CertType, CertificateKeyId, ChipCertificateData, ChipDN, KeyPurposeFlags,
                KeyUsageFlags, K_NULL_CERT_TIME,
            },
        },
        crypto::{ECPKey, P256EcdsaSignature, P256PublicKey, K_SHA256_HASH_LENGTH},
        system::system_clock::Seconds32,
    };

    use crate::chip_core_error;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipError;
    use crate::ChipErrorResult;
    use crate::{
        chip_error_ca_cert_not_found, chip_error_cert_not_found, chip_error_cert_not_trusted,
        chip_error_cert_path_len_constraint_exceeded, chip_error_cert_path_too_long,
        chip_error_cert_usage_not_allowed, chip_error_internal, chip_error_invalid_argument,
        chip_error_no_memory, chip_error_unsupported_cert_format,
        chip_error_unsupported_signature_type, chip_error_wrong_cert_type,
    };

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_detail;
    use crate::chip_log_error;
    use core::str::FromStr;

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
                m_required_key_usages: KeyUsageFlags::empty(),
                m_required_key_purpose: KeyPurposeFlags::empty(),
                m_required_cert_type: CertType::KnotSpecified,
                m_validity_policy: None,
            }
        }

        pub fn set_effective_time(&mut self, chip_time: EffectiveTime) {
            self.m_effective_time = chip_time;
        }

        pub fn reset(&mut self) {
            self.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(0));
            self.m_trust_anchor = None;
            self.m_required_key_usages = KeyUsageFlags::empty();
            self.m_required_key_purpose = KeyPurposeFlags::empty();
            self.m_required_cert_type = CertType::KnotSpecified;
        }
    }

    impl<'a, ValidityPolicy> Default for ValidationContext<'a, ValidityPolicy>
    where
        ValidityPolicy: CertificateValidityPolicy,
    {
        fn default() -> Self {
            ValidationContext::<ValidityPolicy>::new()
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

    impl Default for ChipCertificateSet {
        fn default() -> Self {
            ChipCertificateSet::new()
        }
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

        pub fn load_cert(
            &mut self,
            chip_cert: &[u8],
            decode_flags: CertDecodeFlags,
        ) -> ChipErrorResult {
            let mut reader = TlvContiguousBufferReader::default();

            reader.init(chip_cert.as_ptr(), chip_cert.len());

            return self.load_cert_reader(&mut reader, decode_flags, chip_cert);
        }

        pub fn load_cert_reader<'a, Reader: TlvReader<'a>>(
            &mut self,
            reader: &mut Reader,
            decode_flags: CertDecodeFlags,
            chip_cert: &[u8],
        ) -> ChipErrorResult {
            let mut cert = ChipCertificateData::default();
            decode_chip_cert_with_reader(reader, &mut cert, Some(decode_flags))?;

            // Verify the cert has both the Subject Key Id and Authority Key Id extensions present.
            // Only certs with both these extensions are supported for the purposes of certificate validation.
            verify_or_return_error!(
                cert.m_cert_flags
                    .contains(CertFlags::KextPresentSubjectKeyId | CertFlags::KextPresentAuthKeyId),
                Err(chip_error_unsupported_cert_format!())
            );

            // Verify the cert was signed with ECDSA-SHA256. This is the only signature algorithm currently supported.
            verify_or_return_error!(
                cert.m_sig_algo_OID == Asn1Oid::KoidSigAlgoECDSAWithSHA256.into(),
                Err(chip_error_unsupported_signature_type!())
            );

            for internal_cert in self.m_certs_internal_storage.iter() {
                if internal_cert.as_ref().is_some_and(|c| c.is_equal(&cert)) {
                    return chip_ok!();
                }
            }

            verify_or_return_error!(
                (self.m_cert_count as usize) < K_MAX_ARRAY_SIZE,
                Err(chip_error_no_memory!())
            );

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

        pub fn validate_cert<'a, Policy: CertificateValidityPolicy>(
            &'a self,
            cert: &'a ChipCertificateData,
            context: &mut ValidationContext<'a, Policy>,
        ) -> ChipErrorResult {
            verify_or_return_error!(
                self.is_cert_in_the_set(cert),
                Err(chip_error_invalid_argument!())
            );

            context.m_trust_anchor = None;

            return self.validate_cert_depth(cert, context, 0);
        }

        pub fn validate_cert_depth<'a, Policy: CertificateValidityPolicy>(
            &'a self,
            cert: &'a ChipCertificateData,
            context: &mut ValidationContext<'a, Policy>,
            depth: u8,
        ) -> ChipErrorResult {
            let cert_type = cert.m_subject_dn.get_cert_type()?;

            verify_or_return_error!(
                !cert
                    .m_cert_flags
                    .contains(CertFlags::KextPresentFutureIsCritical),
                Err(chip_error_cert_usage_not_allowed!())
            );

            if depth > 0 {
                // If the depth is greater than 0 then the certificate is required to be a CA certificate...

                // Verify the isCA flag is present.
                verify_or_return_value!(
                    cert.m_cert_flags.contains(CertFlags::KisCA),
                    Err(chip_error_cert_usage_not_allowed!())
                );

                // Verify the key usage extension is present and contains the 'keyCertSign' flag.
                verify_or_return_value!(
                    cert.m_cert_flags.contains(CertFlags::KextPresentKeyUsage)
                        && cert.m_key_usage_flags.contains(KeyUsageFlags::KkeyCertSign),
                    Err(chip_error_cert_usage_not_allowed!())
                );

                // Verify that the certificate type is set to Root or ICA.
                verify_or_return_error!(
                    cert_type == CertType::Kica || cert_type == CertType::Kroot,
                    Err(chip_error_wrong_cert_type!())
                );

                // If a path length constraint was included, verify the cert depth vs. the specified constraint.
                //
                // From the RFC, the path length constraint "gives the maximum number of non-self-issued
                // intermediate certificates that may follow this certificate in a valid certification path.
                // (Note: The last certificate in the certification path is not an intermediate certificate,
                // and is not included in this limit...)"
                //
                if cert
                    .m_cert_flags
                    .contains(CertFlags::KpathLenConstraintPresent)
                {
                    verify_or_return_error!(
                        (depth - 1) <= cert.m_path_len_constraint,
                        Err(chip_error_cert_path_len_constraint_exceeded!())
                    );
                }
            } else {
                // Otherwise verify the desired certificate usages/purposes/type given in the validation context...

                // If a set of desired key usages has been specified, verify that the key usage extension exists
                // in the certificate and that the corresponding usages are supported.
                if !context.m_required_key_usages.is_empty() {
                    verify_or_return_error!(
                        cert.m_cert_flags.contains(CertFlags::KextPresentKeyUsage)
                            && cert
                                .m_key_usage_flags
                                .contains(context.m_required_key_usages.clone()),
                        Err(chip_error_cert_usage_not_allowed!())
                    );
                }

                if !context.m_required_key_purpose.is_empty() {
                    verify_or_return_error!(
                        cert.m_cert_flags
                            .contains(CertFlags::KextPresentExtendedKeyUsage)
                            && cert
                                .m_key_purpose_flags
                                .contains(context.m_required_key_purpose.clone()),
                        Err(chip_error_cert_usage_not_allowed!())
                    );
                }

                // If a required certificate type has been specified, verify it against the current certificate's type.
                if context.m_required_cert_type != CertType::KnotSpecified {
                    verify_or_return_error!(
                        cert_type == context.m_required_cert_type,
                        Err(chip_error_wrong_cert_type!())
                    );
                }
            }

            // Verify NotBefore and NotAfter validity of the certificates.
            //
            // See also ASN1ToChipEpochTime().
            //
            // X.509/RFC5280 defines the special time 99991231235959Z to mean 'no
            // well-defined expiration date'.  In CHIP TLV-encoded certificates, this
            // special value is represented as a CHIP Epoch time value of 0 sec
            // (2000-01-01 00:00:00 UTC).
            let mut validity_result = CertificateValidityResult::Kvalid;
            match context.m_effective_time {
                EffectiveTime::CurrentChipEpochTime(time) => {
                    let time_secs = time.as_secs() as u32;
                    if time_secs < cert.m_not_before_time {
                        chip_log_detail!(
                            SecureChannel,
                            "Certificate's m_not_before_time {} is after curren time {}",
                            cert.m_not_before_time,
                            time_secs
                        );
                        validity_result = CertificateValidityResult::KnotYetValid;
                    } else if cert.m_not_after_time != K_NULL_CERT_TIME
                        && time_secs > cert.m_not_after_time
                    {
                        chip_log_detail!(
                            SecureChannel,
                            "Certificate's m_not_after_time {} is before curren time {}",
                            cert.m_not_after_time,
                            time_secs
                        );
                        validity_result = CertificateValidityResult::Kexpired;
                    } else {
                        // do nothing
                    }
                }
                EffectiveTime::LastKnownGoodChipEpochTime(time) => {
                    let time_secs = time.as_secs() as u32;
                    // Last Known Good Time may not be moved forward except at the time of
                    // commissioning or firmware update, so we can't use it to validate
                    // NotBefore.  However, so long as firmware build times are properly
                    // recorded and certificates loaded during commissioning are in fact
                    // valid at the time of commissioning, observing a NotAfter that falls
                    // before Last Known Good Time is a reliable indicator that the
                    // certificate in question is expired.  Check for this.
                    if cert.m_not_after_time != K_NULL_CERT_TIME
                        && time_secs > cert.m_not_after_time
                    {
                        chip_log_detail!(
                            SecureChannel,
                            "Certificate's m_not_after_time {} is before curren time {}",
                            cert.m_not_after_time,
                            time_secs
                        );
                        validity_result = CertificateValidityResult::KexpiredAtLastKnownGoodTime;
                    } else {
                        validity_result = CertificateValidityResult::KnotExpiredAtLastKnownGoodTime;
                    }
                }
            }

            if let Some(policy) = context.m_validity_policy {
                policy.apply_certificate_validity_policy(cert, depth, validity_result)?;
            } else {
                apply_default_policy(cert, depth, validity_result)?;
            }

            // If the certificate itself is trusted, then it is implicitly valid.  Record this certificate as the trust
            // anchor and return success.
            if cert.m_cert_flags.contains(CertFlags::KisTrustAnchor) {
                context.m_trust_anchor = Some(cert);
                return chip_ok!();
            }

            // Otherwise we must validate the certificate by looking for a chain of valid certificates up to a trusted
            // certificate known as the 'trust anchor'.

            // Fail validation if the certificate is self-signed. Since we don't trust this certificate (see the check above) and
            // it has no path we can follow to a trust anchor, it can't be considered valid.
            if cert.m_issuer_dn.is_equal(&cert.m_subject_dn)
                && cert.m_auth_key_id == cert.m_subject_key_id
            {
                return Err(chip_error_cert_not_trusted!());
            }

            // Verify that the certificate depth is less than the total number of certificates. It is technically possible to create
            // a circular chain of certificates.  Limiting the maximum depth of the certificate path prevents infinite
            // recursion in such a case.
            verify_or_return_error!(
                depth < self.m_cert_count,
                Err(chip_error_cert_path_too_long!())
            );

            // Search for a valid CA certificate that matches the Issuer DN and Authority Key Id of the current certificate.
            // Fail if no acceptable certificate is found.
            let ca_cert = self
                .find_valid_cert(
                    &cert.m_issuer_dn,
                    &cert.m_auth_key_id,
                    context,
                    (depth + 1) as u8,
                )
                .map_err(|e| {
                    chip_log_error!(
                        SecureChannel,
                        "Failed to find valid cert druing chain traversal: {}",
                        e
                    );
                    chip_error_ca_cert_not_found!()
                })?;

            // Verify signature of the current certificate against public key of the CA certificate. If signature verification
            // succeeds, the current certificate is valid.
            return verify_cert_signature(cert, ca_cert);
        }

        pub fn find_valid_cert<'a, Policy: CertificateValidityPolicy>(
            &'a self,
            subject_dn: &ChipDN,
            subject_key_id: &CertificateKeyId,
            context: &mut ValidationContext<'a, Policy>,
            depth: u8,
        ) -> Result<&'a ChipCertificateData, ChipError> {
            let mut err = if depth > 0 {
                chip_error_ca_cert_not_found!()
            } else {
                chip_error_cert_not_found!()
            };

            for i in 0..self.m_cert_count {
                let candidate_cert = &self.m_certs_internal_storage[i as usize];

                if candidate_cert.is_none() {
                    continue;
                }
                let candidate_cert = candidate_cert.as_ref().unwrap();

                if !candidate_cert.m_subject_dn.is_equal(subject_dn) {
                    continue;
                }

                if &candidate_cert.m_subject_key_id[..] != subject_key_id {
                    continue;
                }

                // Attempt to validate the cert.  If the cert is valid, return it to the caller. Otherwise,
                // save the returned error and continue searching.  If there are no other matching certs this
                // will be the error returned to the caller.
                if self
                    .validate_cert_depth(candidate_cert, context, depth)
                    .inspect_err(|e| err = *e)
                    .is_ok()
                {
                    return Ok(candidate_cert);
                }
            }

            return Err(err);
        }

        pub fn get_cert_count(&self) -> u8 {
            self.m_cert_count
        }

        pub fn get_cert_sets(&self) -> &[Option<ChipCertificateData>] {
            &self.m_certs_internal_storage
        }

        pub fn get_last_cert(&self) -> Option<&ChipCertificateData> {
            if self.m_cert_count > 0 {
                if let Some(cert) = self.m_certs_internal_storage[(self.m_cert_count - 1) as usize].as_ref() {
                    return Some(cert);
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        use crate::chip::{
            credentials::{
                certificate_validity_policy::{
                    CertificateValidityPolicy, IgnoreCertificateValidityPeriodPolicy,
                },
                chip_cert::{tests::make_subject_key_id, K_KEY_IDENTIFIER_LENGTH},
                fabric_table::fabric_info::tests::{make_ca_cert, make_chip_cert, stub_public_key},
            },
            crypto::{
                ECPKeyTarget, ECPKeypair, P256EcdsaSignature, P256Keypair, P256KeypairBase,
                K_P256_PUBLIC_KEY_LENGTH,
            },
        };

        use sha2::{Digest, Sha256};

        type IgorePolicyValidate<'a> = ValidationContext<'a, IgnoreCertificateValidityPeriodPolicy>;

        #[derive(Default)]
        struct CheckResultPolicy;

        impl CertificateValidityPolicy for CheckResultPolicy {
            fn apply_certificate_validity_policy(
                &self,
                _cert: &ChipCertificateData,
                _depth: u8,
                result: CertificateValidityResult,
            ) -> ChipErrorResult {
                println!("here??");
                if CertificateValidityResult::Kvalid == result {
                    return chip_ok!();
                }
                if CertificateValidityResult::KnotExpiredAtLastKnownGoodTime == result {
                    return chip_ok!();
                }

                Err(chip_error_internal!())
            }
        }

        type CheckResultValidate<'a> = ValidationContext<'a, CheckResultPolicy>;

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
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert_eq!(1, sets.get_cert_count());
        }

        #[test]
        fn load_two_cert_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            let cert2 = make_chip_cert(3, 4, &key[..]).unwrap();
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets
                .load_cert(cert2.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert_eq!(2, sets.get_cert_count());
        }

        #[test]
        fn load_one_cert_twice_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert_eq!(1, sets.get_cert_count());
        }

        #[test]
        fn release_last_cert_correctlly() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets.release_last_cert().is_ok());
        }

        #[test]
        fn find_cert() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());

            // this is the key in make_chip_cert
            let key = make_subject_key_id(3, 4);
            assert!(sets.find_cert(&key).is_some());
        }

        #[test]
        fn is_cert_in_the_sets() {
            let mut sets = ChipCertificateSet::new();
            let key = stub_public_key();
            let cert = make_chip_cert(1, 2, &key[..]).unwrap();
            assert!(sets
                .load_cert(cert.const_bytes(), CertDecodeFlags::Knone)
                .inspect_err(|e| println!("{}", e))
                .is_ok());

            // this is the key in make_chip_cert
            let key = make_subject_key_id(3, 4);
            let found_cert = sets.find_cert(&key);

            assert!(found_cert.is_some());
            assert!(sets.is_cert_in_the_set(found_cert.unwrap()));
        }

        #[test]
        fn valid_one_noc_and_one_root_successfully() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let noc = {
                let key = stub_public_key();
                let root_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[1].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(root_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // copy subject dn from root to issue dn from noc
                    noc.m_issuer_dn.clear();
                    for (index, value) in root_dn.rdn.iter().enumerate() {
                        noc.m_issuer_dn.rdn[index] = value.clone();
                    }
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let key = make_subject_key_id(3, 4);
                let noc_ref = sets.find_cert(&key);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
        }

        #[test]
        fn valid_one_noc_and_one_icac_and_one_root_successfully() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_key_id = make_subject_key_id(1, 2);
            let icac_key_id = make_subject_key_id(3, 4);
            let node_key_id = make_subject_key_id(5, 6);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                    root.m_subject_key_id = root_key_id.clone();
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let mut icac_keypair = P256Keypair::default();
            icac_keypair.initialize(ECPKeyTarget::Ecdh);
            let icac_dn = {
                let icac_buffer = make_ca_cert(1, icac_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(icac_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(icac) = sets.m_certs_internal_storage[1].as_mut() {
                    icac.m_not_before_time = expected_not_before;
                    icac.m_not_after_time = expected_not_after;
                    icac.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    icac.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                    // replace RCAC id with ICAC id
                    icac.m_subject_dn.clear();
                    icac.m_subject_dn.add_attribute(
                        crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterICACId.into(),
                        2,
                    );
                    icac.m_subject_key_id = icac_key_id.clone();
                    icac.m_auth_key_id = root_key_id.clone();

                    // copy subject dn from root to issue dn from noc
                    icac.m_issuer_dn.clear();
                    for (index, value) in root_dn.rdn.iter().enumerate() {
                        icac.m_issuer_dn.rdn[index] = value.clone();
                    }

                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&icac.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&icac.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    icac.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(root_keypair
                        .ecdsa_sign_msg(&buf[..], &mut icac.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    icac.m_cert_flags.insert(CertFlags::KtbsHashPresent);
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let icac_ref = sets.find_cert(&icac_key_id);
                assert!(icac_ref.is_some());
                let icac_ref = icac_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(icac_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());

                let mut icac_dn = ChipDN::default();
                for (index, value) in icac_ref.m_subject_dn.rdn.iter().enumerate() {
                    icac_dn.rdn[index] = value.clone();
                }

                icac_dn
            };

            let noc = {
                let key = stub_public_key();
                let node_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(node_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[2].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[2].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // update key id
                    noc.m_subject_key_id = node_key_id.clone();
                    noc.m_auth_key_id = icac_key_id.clone();

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(icac_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // copy subject dn from root to issue dn from noc
                    noc.m_issuer_dn.clear();
                    for (index, value) in icac_dn.rdn.iter().enumerate() {
                        noc.m_issuer_dn.rdn[index] = value.clone();
                    }
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let noc_ref = sets.find_cert(&node_key_id);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
        }

        #[test]
        fn valid_one_noc_and_one_root_no_CA_flag() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags.insert(CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let noc = {
                let key = stub_public_key();
                let root_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[1].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(root_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // copy subject dn from root to issue dn from noc
                    noc.m_issuer_dn.clear();
                    for (index, value) in root_dn.rdn.iter().enumerate() {
                        noc.m_issuer_dn.rdn[index] = value.clone();
                    }
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let key = make_subject_key_id(3, 4);
                let noc_ref = sets.find_cert(&key);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_one_noc_and_one_root_no_CA_type() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                    // clear subject dn so the type is WRONG
                    root.m_subject_dn.clear();
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let noc = {
                let key = stub_public_key();
                let root_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[1].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(root_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // copy subject dn from root to issue dn from noc
                    noc.m_issuer_dn.clear();
                    for (index, value) in root_dn.rdn.iter().enumerate() {
                        noc.m_issuer_dn.rdn[index] = value.clone();
                    }
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let key = make_subject_key_id(3, 4);
                let noc_ref = sets.find_cert(&key);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_one_noc_and_one_root_no_CA_existed() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let noc = {
                let key = stub_public_key();
                let root_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[1].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    // sign the buf: pubkey + sub key id
                    assert!(root_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // NOT copying issuer DN
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let key = make_subject_key_id(3, 4);
                let noc_ref = sets.find_cert(&key);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_one_noc_and_one_root_cannot_verify_sign() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_dn = {
                let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[0].is_some());
                if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                    root.m_not_before_time = expected_not_before;
                    root.m_not_after_time = expected_not_after;
                    root.m_cert_flags
                        .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                    root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
                } else {
                    assert!(false);
                }

                let mut context = IgorePolicyValidate::default();
                context.m_effective_time = EffectiveTime::CurrentChipEpochTime(
                    Seconds32::from_secs((expected_not_before + 1).into()),
                );

                // this is the key in make_chip_cert
                let key = make_subject_key_id(1, 2);
                let root_ref = sets.find_cert(&key);
                assert!(root_ref.is_some());
                let root_ref = root_ref.unwrap();

                // validate the root cert first
                assert!(sets
                    .validate_cert(root_ref, &mut context)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(context
                    .m_trust_anchor
                    .is_some_and(|c| core::ptr::eq(c, root_ref)));

                let mut root_dn = ChipDN::default();
                for (index, value) in root_ref.m_subject_dn.rdn.iter().enumerate() {
                    root_dn.rdn[index] = value.clone();
                }

                root_dn
            };

            let noc = {
                let key = stub_public_key();
                let root_buffer = make_chip_cert(1, 2, &key[..]).unwrap();
                // load as trust anchor
                assert!(sets
                    .load_cert(root_buffer.const_bytes(), CertDecodeFlags::Knone)
                    .inspect_err(|e| println!("{}", e))
                    .is_ok());
                assert!(sets.m_certs_internal_storage[1].is_some());
                if let Some(noc) = sets.m_certs_internal_storage[1].as_mut() {
                    // update the effec time
                    noc.m_not_before_time = expected_not_before;
                    noc.m_not_after_time = expected_not_after;
                    /* for test, just sign pubkey and sub key id */
                    let mut buf = [0u8; K_P256_PUBLIC_KEY_LENGTH + K_KEY_IDENTIFIER_LENGTH];
                    buf[..K_P256_PUBLIC_KEY_LENGTH].copy_from_slice(&noc.m_public_key[..]);
                    buf[K_P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&noc.m_subject_key_id[..]);

                    // get the hash result first
                    let mut hasher = Sha256::new();
                    hasher.update(&buf[..]);
                    let result = hasher.finalize();

                    assert!(result.as_slice().len() == K_SHA256_HASH_LENGTH);
                    noc.m_tbs_hash[..K_SHA256_HASH_LENGTH].copy_from_slice(result.as_slice());

                    let mut rand_keypair = P256Keypair::default();
                    rand_keypair.initialize(ECPKeyTarget::Ecdh);

                    // use DIFFERENT key to sign
                    assert!(rand_keypair
                        .ecdsa_sign_msg(&buf[..], &mut noc.m_signature)
                        .inspect_err(|e| println!("{}", e))
                        .is_ok());
                    // set up hash present flag
                    noc.m_cert_flags.insert(CertFlags::KtbsHashPresent);

                    // copy subject dn from root to issue dn from noc
                    noc.m_issuer_dn.clear();
                    for (index, value) in root_dn.rdn.iter().enumerate() {
                        noc.m_issuer_dn.rdn[index] = value.clone();
                    }
                } else {
                    assert!(false);
                }

                // this is the key in make_chip_cert
                let key = make_subject_key_id(3, 4);
                let noc_ref = sets.find_cert(&key);
                assert!(noc_ref.is_some());
                let noc_ref = noc_ref.unwrap();

                noc_ref
            };

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before + 1).into(),
            ));
            context.m_required_key_usages = noc.m_key_usage_flags.clone();
            context.m_required_cert_type = CertType::Knode;
            assert!(sets
                .validate_cert(noc, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_cert_wrong_before() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
            // load as trust anchor
            assert!(sets
                .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets.m_certs_internal_storage[0].is_some());
            if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                root.m_not_before_time = expected_not_before;
                root.m_not_after_time = expected_not_after;
                root.m_cert_flags
                    .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
            } else {
                assert!(false);
            }

            // use policy checking the result
            let mut context = CheckResultValidate::default();
            let policy = CheckResultPolicy::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_before - 1).into(),
            ));
            context.m_validity_policy = Some(&policy);

            // this is the key in make_chip_cert
            let key = make_subject_key_id(1, 2);
            let root_ref = sets.find_cert(&key);
            assert!(root_ref.is_some());
            let root_ref = root_ref.unwrap();

            // validate the root cert first
            assert!(sets
                .validate_cert(root_ref, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_cert_wrong_after() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
            // load as trust anchor
            assert!(sets
                .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets.m_certs_internal_storage[0].is_some());
            if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                root.m_not_before_time = expected_not_before;
                root.m_not_after_time = expected_not_after;
                root.m_cert_flags
                    .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
            } else {
                assert!(false);
            }

            // use policy checking the result
            let mut context = CheckResultValidate::default();
            let policy = CheckResultPolicy::default();
            context.m_effective_time = EffectiveTime::CurrentChipEpochTime(Seconds32::from_secs(
                (expected_not_after + 1).into(),
            ));
            context.m_validity_policy = Some(&policy);

            // this is the key in make_chip_cert
            let key = make_subject_key_id(1, 2);
            let root_ref = sets.find_cert(&key);
            assert!(root_ref.is_some());
            let root_ref = root_ref.unwrap();

            // validate the root cert first
            assert!(sets
                .validate_cert(root_ref, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_cert_wrong_after_last_know_time() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
            // load as trust anchor
            assert!(sets
                .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets.m_certs_internal_storage[0].is_some());
            if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                root.m_not_before_time = expected_not_before;
                root.m_not_after_time = expected_not_after;
                root.m_cert_flags
                    .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
            } else {
                assert!(false);
            }

            // use policy checking the result
            let mut context = CheckResultValidate::default();
            let policy = CheckResultPolicy::default();
            context.m_effective_time = EffectiveTime::LastKnownGoodChipEpochTime(
                Seconds32::from_secs((expected_not_after + 1).into()),
            );
            context.m_validity_policy = Some(&policy);

            // this is the key in make_chip_cert
            let key = make_subject_key_id(1, 2);
            let root_ref = sets.find_cert(&key);
            assert!(root_ref.is_some());
            let root_ref = root_ref.unwrap();

            // validate the root cert first
            assert!(sets
                .validate_cert(root_ref, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_err());
        }

        #[test]
        fn valid_cert_good_after_last_know_time() {
            let expected_not_before: u32 = 1;
            let expected_not_after: u32 = 100;
            let mut sets = ChipCertificateSet::new();
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_buffer = make_ca_cert(1, root_keypair.public_key().const_bytes()).unwrap();
            // load as trust anchor
            assert!(sets
                .load_cert(root_buffer.const_bytes(), CertDecodeFlags::KisTrustAnchor)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
            assert!(sets.m_certs_internal_storage[0].is_some());
            if let Some(root) = sets.m_certs_internal_storage[0].as_mut() {
                root.m_not_before_time = expected_not_before;
                root.m_not_after_time = expected_not_after;
                root.m_cert_flags
                    .insert(CertFlags::KisCA | CertFlags::KextPresentKeyUsage);
                root.m_key_usage_flags.insert(KeyUsageFlags::KkeyCertSign);
            } else {
                assert!(false);
            }

            // use policy checking the result
            let mut context = CheckResultValidate::default();
            let policy = CheckResultPolicy::default();
            context.m_effective_time = EffectiveTime::LastKnownGoodChipEpochTime(
                Seconds32::from_secs((expected_not_after - 1).into()),
            );
            context.m_validity_policy = Some(&policy);

            // this is the key in make_chip_cert
            let key = make_subject_key_id(1, 2);
            let root_ref = sets.find_cert(&key);
            assert!(root_ref.is_some());
            let root_ref = root_ref.unwrap();

            // validate the root cert first
            assert!(sets
                .validate_cert(root_ref, &mut context)
                .inspect_err(|e| println!("{}", e))
                .is_ok());
        }
    } // end of tests
}
