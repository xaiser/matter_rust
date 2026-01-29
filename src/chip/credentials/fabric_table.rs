const KFABRIC_LABEL_MAX_LENGTH_IN_BYTES: usize = 32;
pub type FabricLabelString = crate::chip::chip_lib::support::default_string::DefaultString<
    KFABRIC_LABEL_MAX_LENGTH_IN_BYTES,
>;

pub mod fabric_info {
    use crate::chip::{
        chip_lib::{
            core::{
                case_auth_tag::CatValues,
                chip_encoding,
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::{
                    is_valid_fabric_index, FabricIndex, KMAX_VALID_FABRIC_INDEX,
                    KMIN_VALID_FABRIC_INDEX, KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID,
                    KUNDEFINED_FABRIC_INDEX,
                },
                node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
                tlv_tags::{self, anonymous_tag, context_tag},
                tlv_types::TlvType,
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
            },
            support::{
                default_storage_key_allocator::DefaultStorageKeyAllocator,
                default_string::DefaultString,
            },
        },
        credentials::{
            self,
            certificate_validity_policy::IgnoreCertificateValidityPeriodPolicy,
            chip_cert::{
                extract_node_id_fabric_id_from_op_cert_byte,
                extract_public_key_from_chip_cert_byte, CertBuffer, K_MAX_CHIP_CERT_LENGTH,
                ChipCertificateData, ChipCertExtensionTag,
            },
            last_known_good_time::LastKnownGoodTime,
            operational_certificate_store::{CertChainElement, OperationalCertificateStore},
        },
        crypto::{
            self,
            crypto_pal::{
                ECPKey, ECPKeypair, P256EcdsaSignature, P256Keypair, P256KeypairBase,
                P256PublicKey, P256SerializedKeypair,
            },
            generate_compressed_fabric_id,
        },
        system::system_clock::Seconds32,
        CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
    };
    use crate::chip_core_error;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_internal;
    use crate::chip_error_invalid_argument;
    use crate::chip_error_key_not_found;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipError;
    use crate::ChipErrorResult;

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use crate::chip_log_progress;

    use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES};
    use core::{
        ptr,
        str::{self, FromStr},
    };
    #[cfg(test)]
    use mockall::*;
    //#[cfg(test)]
    //use mockall_derive::*;

    const K_FABRIC_LABEL_MAX_LENGTH_IN_BYTES: u8 = 32;

    fn vendor_id_tag() -> tlv_tags::Tag {
        tlv_tags::context_tag(0)
    }

    fn fabric_label_tag() -> tlv_tags::Tag {
        tlv_tags::context_tag(1)
    }

    /*
    const fn metadata_tlv_max_size() -> usize {
        tlv_estimate_struct_overhead!(core::mem::size_of::<u16>(), K_FABRIC_LABEL_MAX_LENGTH_IN_BYTES as usize)
    }
    */

    pub(super) struct InitParams {
        pub m_node_id: NodeId,
        pub m_fabric_id: FabricId,
        pub m_compressed_fabric_id: CompressedFabricId,
        pub m_root_publick_key: P256PublicKey,
        pub m_fabric_index: FabricIndex,
        pub m_vendor_id: VendorId,
        pub m_has_externally_owned_operation_key: bool,
        pub m_should_advertise_identity: bool,
        pub m_operation_key: *mut P256Keypair,
    }

    impl InitParams {
        pub(super) const fn const_default() -> Self {
            Self {
                m_node_id: KUNDEFINED_NODE_ID,
                m_fabric_id: KUNDEFINED_FABRIC_ID,
                m_compressed_fabric_id: KUNDEFINED_COMPRESSED_FABRIC_ID,
                m_root_publick_key: P256PublicKey::const_default(),
                m_fabric_index: KUNDEFINED_FABRIC_INDEX,
                m_vendor_id: VendorId::NotSpecified,
                m_has_externally_owned_operation_key: false,
                m_should_advertise_identity: true,
                m_operation_key: ptr::null_mut(),
            }
        }

        pub(super) fn are_valid(&self) -> ChipErrorResult {
            verify_or_return_error!(
                (self.m_fabric_id != KUNDEFINED_FABRIC_ID)
                    && (self.m_fabric_index != KUNDEFINED_FABRIC_INDEX),
                Err(chip_error_invalid_argument!())
            );
            verify_or_return_error!(
                is_operational_node_id(self.m_node_id),
                Err(chip_error_invalid_argument!())
            );

            chip_ok!()
        }
    }

    impl Default for InitParams {
        fn default() -> Self {
            InitParams::const_default()
        }
    }

    pub struct FabricInfo {
        m_node_id: NodeId,
        m_fabric_id: FabricId,
        m_compressed_fabric_id: CompressedFabricId,
        m_root_publick_key: P256PublicKey,
        m_fabric_label: FabricLabelString,
        m_fabric_index: FabricIndex,
        m_vendor_id: VendorId,
        m_has_externally_owned_operation_key: bool,
        m_should_advertise_identity: bool,
        // until we implement dynamic allocate, we just use a static allocation
        m_internal_op_key_storage: Option<P256Keypair>,
        m_operation_key: *mut P256Keypair,
    }

    #[cfg(test)]
    mock! {
        pub FabricInfo {
            fn set_fabric_label(&mut self, label: &str) -> ChipErrorResult;
            fn get_fabric_label<'a>(&'a self) -> Option<&'a str>;
            pub fn get_node_id(&self) -> NodeId;
            pub fn get_scoped_node_id(&self) -> ScopedNodeId;
            pub fn get_scoped_node_id_for_node(&self, node: NodeId) -> ScopedNodeId;
            pub fn get_fabric_id(&self) -> FabricId;
            pub fn get_fabric_index(&self) -> FabricIndex;
            pub fn get_compressed_fabric_id(&self) -> CompressedFabricId;
            pub fn get_compressed_fabric_id_bytes(
                &self,
                compressed_fabric_id: &mut [u8],
            ) -> ChipErrorResult;
            pub fn fetch_root_pubkey(&self) -> Result<P256PublicKey, ChipError>;
            pub fn get_vendor_id(&self) -> VendorId;
            pub fn is_initialized(&self) -> bool;
            pub fn has_operational_key(&self) -> bool;
            pub fn should_advertise_identity(&self) -> bool;
            pub(super) fn init(&mut self, init_params: &super::fabric_info::InitParams) -> ChipErrorResult;
            pub(super) fn set_operational_keypair(
                &mut self,
                keypair: *const P256Keypair,
            ) -> ChipErrorResult;
            pub(super) fn set_externally_owned_operational_keypair(
                &mut self,
                keypair: *mut P256Keypair,
            ) -> ChipErrorResult;
            pub(super) fn sign_with_op_keypair(
                &self,
                message: &[u8],
                out_signature: &mut P256EcdsaSignature,
            ) -> ChipErrorResult;
            pub(super) fn reset(&mut self);
            pub(super) fn set_should_advertise_identity(&mut self, advertise_identity: bool);
            pub(super) fn commit_to_storge<Storage: PersistentStorageDelegate + 'static>(
                &self,
                storage: &'static mut Storage,
            ) -> ChipErrorResult;
            pub(super) fn load_from_storage<Storage: PersistentStorageDelegate + 'static>(
                &mut self,
                storage: &'static mut Storage,
                new_fabric_index: FabricIndex,
                rcac: &[u8],
                noc: &[u8],
            ) -> ChipErrorResult;
        } // end of FabricInfo declear

        /*
        impl Drop for FabricInfo {
            fn drop(&mut self);
        }
        */
    } // end of FabricInfo mock

    impl Default for FabricInfo {
        fn default() -> Self {
            fabric_info_const_default()
        }
    }

    pub const fn fabric_info_const_default() -> FabricInfo {
        FabricInfo {
            m_node_id: KUNDEFINED_NODE_ID,
            m_fabric_id: KUNDEFINED_FABRIC_ID,
            m_compressed_fabric_id: KUNDEFINED_COMPRESSED_FABRIC_ID,
            m_root_publick_key: P256PublicKey::const_default(),
            m_fabric_label: FabricLabelString::const_default(),
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_vendor_id: VendorId::NotSpecified,
            m_has_externally_owned_operation_key: false,
            m_should_advertise_identity: true,
            m_internal_op_key_storage: None,
            m_operation_key: ptr::null_mut(),
        }
    }

    pub(super) const fn metadata_tlv_max_size() -> usize {
        tlv_estimate_struct_overhead!(
            core::mem::size_of::<u16>(),
            KFABRIC_LABEL_MAX_LENGTH_IN_BYTES
        )
    }

    pub(super) const fn op_key_tlv_max_size() -> usize {
        tlv_estimate_struct_overhead!(
            core::mem::size_of::<u16>(),
            P256SerializedKeypair::capacity()
        )
    }

    impl FabricInfo {
        pub fn set_fabric_label(&mut self, label: &str) -> ChipErrorResult {
            self.m_fabric_label = FabricLabelString::from(label);

            chip_ok!()
        }

        pub fn get_fabric_label<'a>(&'a self) -> Option<&'a str> {
            self.m_fabric_label.str()
        }

        pub fn get_node_id(&self) -> NodeId {
            self.m_node_id
        }

        pub fn get_scoped_node_id(&self) -> ScopedNodeId {
            ScopedNodeId::default_with_ids(self.m_node_id, self.m_fabric_index)
        }

        pub fn get_scoped_node_id_for_node(&self, node: NodeId) -> ScopedNodeId {
            ScopedNodeId::default_with_ids(node, self.m_fabric_index)
        }

        pub fn get_fabric_id(&self) -> FabricId {
            self.m_fabric_id
        }

        pub fn get_fabric_index(&self) -> FabricIndex {
            self.m_fabric_index
        }

        pub fn get_compressed_fabric_id(&self) -> CompressedFabricId {
            self.m_compressed_fabric_id
        }

        pub fn get_compressed_fabric_id_bytes(
            &self,
            compressed_fabric_id: &mut [u8],
        ) -> ChipErrorResult {
            verify_or_return_error!(
                compressed_fabric_id.len() == (core::mem::size_of::<u64>()),
                Err(chip_error_invalid_argument!())
            );
            chip_encoding::big_endian::put_u64(
                compressed_fabric_id,
                self.get_compressed_fabric_id(),
            );
            chip_ok!()
        }

        pub fn fetch_root_pubkey(&self) -> Result<P256PublicKey, ChipError> {
            verify_or_return_error!(self.is_initialized(), Err(chip_error_key_not_found!()));

            return Ok(self.m_root_publick_key.clone());
        }

        pub fn get_vendor_id(&self) -> VendorId {
            self.m_vendor_id
        }

        pub fn is_initialized(&self) -> bool {
            return (self.m_fabric_index != KUNDEFINED_FABRIC_INDEX)
                && is_operational_node_id(self.m_node_id);
        }

        pub fn has_operational_key(&self) -> bool {
            //unsafe { (*self.m_operation_key.get()).is_null() == false }
            self.m_operation_key.is_null() == false
        }

        pub fn should_advertise_identity(&self) -> bool {
            self.m_should_advertise_identity
        }

        pub(super) fn init(&mut self, init_params: &InitParams) -> ChipErrorResult {
            init_params.are_valid()?;

            self.reset();

            self.m_node_id = init_params.m_node_id;
            self.m_fabric_id = init_params.m_fabric_id;
            self.m_fabric_index = init_params.m_fabric_index;
            self.m_compressed_fabric_id = init_params.m_compressed_fabric_id;
            self.m_root_publick_key =
                P256PublicKey::default_with_raw_value(init_params.m_root_publick_key.const_bytes());
            self.m_vendor_id = init_params.m_vendor_id;
            self.m_should_advertise_identity = init_params.m_should_advertise_identity;

            if init_params.m_operation_key.is_null() == false {
                if init_params.m_has_externally_owned_operation_key == true {
                    self.set_externally_owned_operational_keypair(init_params.m_operation_key)?;
                } else {
                    self.set_operational_keypair(init_params.m_operation_key)?;
                }
            }

            chip_ok!()
        }

        pub(super) fn set_operational_keypair(
            &mut self,
            keypair: *const P256Keypair,
        ) -> ChipErrorResult {
            verify_or_return_error!(!keypair.is_null(), Err(chip_error_invalid_argument!()));

            let mut serialized = P256SerializedKeypair::default();

            unsafe {
                keypair.as_ref().unwrap().serialize(&mut serialized)?;
            }

            if self.m_has_externally_owned_operation_key == true {
                // Drop it, so we will allocate an internally owned one.
                self.m_operation_key = ptr::null_mut();
                self.m_has_externally_owned_operation_key = false;
            }

            let mut internal_keypair = P256Keypair::default();
            internal_keypair.deserialize(&serialized)?;
            self.m_operation_key = ptr::addr_of_mut!(internal_keypair);
            self.m_internal_op_key_storage = Some(internal_keypair);

            chip_ok!()
        }

        pub(super) fn set_externally_owned_operational_keypair(
            &mut self,
            keypair: *mut P256Keypair,
        ) -> ChipErrorResult {
            verify_or_return_error!(!keypair.is_null(), Err(chip_error_invalid_argument!()));

            if self.m_has_externally_owned_operation_key == false
                && self.m_operation_key.is_null() == false
                && self.m_internal_op_key_storage.is_some()
            {
                let mut internal_keypair = self.m_internal_op_key_storage.take().unwrap();
                internal_keypair.clear();
                self.m_operation_key = ptr::null_mut();
            }

            self.m_has_externally_owned_operation_key = true;
            self.m_operation_key = keypair;

            chip_ok!()
        }

        pub(super) fn sign_with_op_keypair(
            &self,
            message: &[u8],
            out_signature: &mut P256EcdsaSignature,
        ) -> ChipErrorResult {
            verify_or_return_error!(
                !self.m_operation_key.is_null(),
                Err(chip_error_key_not_found!())
            );

            unsafe {
                return self
                    .m_operation_key
                    .as_ref()
                    .unwrap()
                    .ecdsa_sign_msg(message, out_signature);
            }
        }

        pub(super) fn reset(&mut self) {
            self.m_node_id = KUNDEFINED_NODE_ID;
            self.m_fabric_id = KUNDEFINED_FABRIC_ID;
            self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
            self.m_compressed_fabric_id = KUNDEFINED_COMPRESSED_FABRIC_ID;

            self.m_vendor_id = VendorId::NotSpecified;
            self.m_fabric_label = FabricLabelString::default();

            if !self.m_has_externally_owned_operation_key
                && self.m_operation_key.is_null() == false
                && self.m_internal_op_key_storage.is_some()
            {
                // force to drop the internal op key
                let mut to_drop = self.m_internal_op_key_storage.take().unwrap();
                to_drop.clear();
            }

            // TODO: Also, make sure the correct when we have a = b

            self.m_operation_key = ptr::null_mut();

            self.m_has_externally_owned_operation_key = false;
            self.m_should_advertise_identity = true;

            self.m_node_id = KUNDEFINED_NODE_ID;
            self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
        }

        pub(super) fn set_should_advertise_identity(&mut self, advertise_identity: bool) {
            self.m_should_advertise_identity = advertise_identity;
        }

        pub(super) fn commit_to_storge<'a, Storage: PersistentStorageDelegate>(
            &'a self,
            storage: &'a mut Storage,
        ) -> ChipErrorResult {
            let mut buf: [u8; metadata_tlv_max_size()] = [0; { metadata_tlv_max_size() }];
            let mut writer = TlvContiguousBufferWriter::const_default();

            writer.init(buf.as_mut_ptr(), metadata_tlv_max_size() as u32);

            let mut outer_type = TlvType::KtlvTypeNotSpecified;

            writer.start_container(
                tlv_tags::anonymous_tag(),
                TlvType::KtlvTypeStructure,
                &mut outer_type,
            )?;

            writer.put_u16(vendor_id_tag(), self.m_vendor_id as u16)?;
            let label = self.m_fabric_label.str().ok_or(chip_error_internal!())?;
            writer.put_string(fabric_label_tag(), label)?;

            writer.end_container(outer_type)?;

            let meta_data_len = u16::try_from(writer.get_length_written())
                .map_err(|_| chip_error_buffer_too_small!())?;
            return storage.sync_set_key_value(
                DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(),
                &buf[..meta_data_len as usize],
            );
        }

        pub(super) fn load_from_storage<'a, Storage: PersistentStorageDelegate>(
            &'a mut self,
            storage: &'a mut Storage,
            new_fabric_index: FabricIndex,
            rcac: &'a [u8],
            noc: &'a [u8],
        ) -> ChipErrorResult {
            self.m_fabric_index = new_fabric_index;
            {
                (self.m_node_id, self.m_fabric_id) =
                    extract_node_id_fabric_id_from_op_cert_byte(noc)?;
                self.m_root_publick_key = extract_public_key_from_chip_cert_byte(rcac)?;
                self.m_compressed_fabric_id =
                    generate_compressed_fabric_id(&self.m_root_publick_key, self.m_fabric_id)?;
            }
            // Load other storable metadata (label, vendorId, etc)
            {
                const size: usize = metadata_tlv_max_size();
                let mut buffer: [u8; size] = [0; size];
                /*
                unsafe {
                    storage.as_ref().unwrap().sync_get_key_value(DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(), &mut buffer[..])?;
                }
                */
                let data_size = storage.sync_get_key_value(
                    DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(),
                    &mut buffer[..],
                )?;
                let mut reader = TlvContiguousBufferReader::const_default();
                reader.init(buffer.as_ptr(), data_size);
                reader.next_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
                let container_type = reader.enter_container()?;

                reader.next_tag(vendor_id_tag())?;
                self.m_vendor_id = reader.get_u16()?.into();

                // this will return Ok(None) when the label is empty str
                reader.next_tag(fabric_label_tag())?;
                let label_string = reader.get_string()?;

                if let Some(label) = label_string {
                    verify_or_return_error!(
                        label.len() <= KFABRIC_LABEL_MAX_LENGTH_IN_BYTES,
                        Err(chip_error_buffer_too_small!())
                    );
                    self.m_fabric_label = FabricLabelString::from(label);
                }

                reader.exit_container(container_type)?;
                reader.verify_end_of_container()?;
            }
            chip_ok!()
        }
    }

    impl Drop for FabricInfo {
        fn drop(&mut self) {
            self.reset();
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;
        use crate::chip::{
            asn1::{Oid, Asn1Oid, Asn1TagClasses, Class},
            chip_lib::{
                asn1::asn1_writer::{Asn1Writer, TestAsn1Writer},
                core::{
                    tlv_tags::{self, context_tag, is_context_tag, tag_num_from_tag},
                    tlv_types::{self, TlvType},
                    tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                },
                support::test_persistent_storage::TestPersistentStorage,
            },
            credentials::{
                chip_cert::{
                    tag_not_after, tag_not_before, tests::make_subject_key_id, ChipCertTag, KeyPurposeFlags, decode_chip_cert, CertDecodeFlags,
                    CertFlags, ChipCertBasicConstraintTag, chip_epoch_to_asn1_time, CertificateKeyId, ChipDN,
                    internal::K_MAX_CHIP_CERT_DECODE_BUF_LENGTH, CertType, KeyUsageFlags
                },
                persistent_storage_op_cert_store::PersistentStorageOpCertStore,
            },
            crypto::{
                crypto_pal::hash_sha256,
                K_SHA256_HASH_LENGTH,
                persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
                ECPKeyTarget, ECPKeypair, P256Keypair, P256KeypairBase, K_P256_PUBLIC_KEY_LENGTH,
                *,
            },
        };
        use core::ptr;
        use sha2::{Digest, Sha256};

        type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
        type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;
        //type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;
        const CHIP_CERT_SIZE: usize = 512 + K_P256_PUBLIC_KEY_LENGTH;

        pub fn stub_public_key() -> [u8; K_P256_PUBLIC_KEY_LENGTH] {
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] =
                [0; K_P256_PUBLIC_KEY_LENGTH];
            let mut keypair = P256Keypair::default();
            let _ = keypair.initialize(ECPKeyTarget::Ecdh);
            fake_public_key.copy_from_slice(keypair.public_key().const_bytes());
            return fake_public_key;
        }

        pub fn stub_keypair() -> P256Keypair {
            let mut keypair = P256Keypair::default();
            let _ = keypair.initialize(ECPKeyTarget::Ecdh);
            return keypair;
        }

        pub fn make_chip_cert_with_time(
            matter_id_value: u64,
            fabric_id_value: u64,
            public_key: &[u8],
            not_before: Seconds32,
            not_after: Seconds32,
            key_pair: Option<&P256Keypair>,
        ) -> Result<CertBuffer, ()> {
            let mut raw_tlv: [u8; CHIP_CERT_SIZE] = [0; CHIP_CERT_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut asn1_writer = TestAsn1Writer::default();
            let mut asn1_buf = [0u8; K_MAX_CHIP_CERT_DECODE_BUF_LENGTH];
            asn1_writer.init(&mut asn1_buf);

            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer
                .start_container(
                    tlv_tags::context_tag(ChipCertTag::KtagSubject as u8),
                    tlv_types::TlvType::KtlvTypeList,
                    &mut issuer_outer_container_dn_list,
                )
                .inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | matter_id)),
                matter_id_value,
            );
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | fabric_id)),
                fabric_id_value,
            );
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            let mut subject_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a subject_dn list
            writer
                .start_container(
                    tlv_tags::context_tag(ChipCertTag::KtagSubject as u8),
                    tlv_types::TlvType::KtlvTypeList,
                    &mut subject_outer_container_dn_list,
                )
                .inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | matter_id)),
                matter_id_value,
            );
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | fabric_id)),
                fabric_id_value,
            );
            // end of list conatiner
            writer.end_container(subject_outer_container_dn_list);

            // add public key to cert
            writer
                .put_bytes(
                    tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8),
                    public_key,
                )
                .inspect_err(|e| println!("{:?}", e));
            asn1_writer.put_object_id(Asn1Oid::KoidSigAlgoECDSAWithSHA256 as Oid);
            asn1_writer.put_bit_string(0, public_key);

            // put a not before
            writer.put_u32(tag_not_before(), not_before.as_secs() as u32);
            let asn1_not_before = chip_epoch_to_asn1_time(not_before.as_secs() as u32).unwrap();
            asn1_writer.put_time(&asn1_not_before);
            // put a not after
            writer.put_u32(tag_not_after(), not_after.as_secs() as u32);
            let asn1_not_after = chip_epoch_to_asn1_time(not_after.as_secs() as u32).unwrap();
            asn1_writer.put_time(&asn1_not_after);

            // make empty extensions
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut extensions_outer_container_list,
            );
            writer.end_container(extensions_outer_container_list);

            if let Some(sign_key) = key_pair {
                let mut sig = P256EcdsaSignature::default();
                let asn1_written = asn1_writer.const_raw_bytes().unwrap();
                sign_key.ecdsa_sign_msg(&asn1_written[..writer.get_length_written()], &mut sig);
                writer
                    .put_bytes(
                        tlv_tags::context_tag(ChipCertTag::KtagECDSASignature as u8),
                        &sig.const_bytes()[..sig.length()],
                    )
                    .inspect_err(|e| println!("{:?}", e));
            }

            // end struct container
            writer.end_container(outer_container);

            let mut cert = CertBuffer::default();
            cert.init(&raw_tlv[..writer.get_length_written()]);

            return Ok(cert);
        }

        pub fn make_chip_cert(
            matter_id_value: u64,
            fabric_id_value: u64,
            public_key: &[u8],
            key_pair: Option<&P256Keypair>,
        ) -> Result<CertBuffer, ()> {
            /*
            let mut raw_tlv: [u8; CHIP_CERT_SIZE] = [0; CHIP_CERT_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut asn1_writer = TestAsn1Writer::default();
            let mut asn1_buf = [0u8; K_MAX_CHIP_CERT_DECODE_BUF_LENGTH];
            asn1_writer.init(&mut asn1_buf);

            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            let mut issuer_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a issuer_dn list
            writer
                .start_container(
                    tlv_tags::context_tag(ChipCertTag::KtagSubject as u8),
                    tlv_types::TlvType::KtlvTypeList,
                    &mut issuer_outer_container_dn_list,
                )
                .inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | matter_id)),
                matter_id_value,
            );
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | fabric_id)),
                fabric_id_value,
            );
            // end of list conatiner
            writer.end_container(issuer_outer_container_dn_list);

            // start a subject dn list
            let mut subject_outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            writer
                .start_container(
                    tlv_tags::context_tag(ChipCertTag::KtagSubject as u8),
                    tlv_types::TlvType::KtlvTypeList,
                    &mut subject_outer_container_dn_list,
                )
                .inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | matter_id)),
                matter_id_value,
            );
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(
                tlv_tags::context_tag((is_print_string | fabric_id)),
                fabric_id_value,
            );
            // end of list conatiner
            writer.end_container(subject_outer_container_dn_list);

            // add to cert
            writer
                .put_bytes(
                    tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8),
                    public_key,
                )
                .inspect_err(|e| println!("{:?}", e));
            asn1_writer.put_object_id(Asn1Oid::KoidSigAlgoECDSAWithSHA256 as Oid);
            asn1_writer.put_bit_string(0, public_key);

            // put a not before
            writer.put_u32(tag_not_before(), 0);
            let asn1_not_before = chip_epoch_to_asn1_time(0u32).unwrap();
            asn1_writer.put_time(&asn1_not_before);

            // put a not after
            writer.put_u32(tag_not_after(), 0);
            let asn1_not_after = chip_epoch_to_asn1_time(0u32).unwrap();
            asn1_writer.put_time(&asn1_not_after);

            // make empty extensions
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut extensions_outer_container_list,
            );

            let key = make_subject_key_id(1, 2);
            assert!(writer.put_bytes(context_tag(crate::chip::credentials::chip_cert::ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8), &key).inspect_err(|e| println!("{}", e)).is_ok());
            asn1_writer.put_octet_string_cls_tag(Asn1TagClasses::Kasn1TagClassContextSpecific as Class, 0, &key);

            let key = make_subject_key_id(3, 4);
            assert!(writer.put_bytes(context_tag(crate::chip::credentials::chip_cert::ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8), &key).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(asn1_writer.put_octet_string(&key[..]).is_ok());

            writer.end_container(extensions_outer_container_list);

            if let Some(sign_key) = key_pair {
                let mut sig = P256EcdsaSignature::default();
                let asn1_written = asn1_writer.const_raw_bytes().unwrap();
                assert!(sign_key.ecdsa_sign_msg(&asn1_written[..asn1_writer.get_length_written()], &mut sig).is_ok());
                writer
                    .put_bytes(
                        tlv_tags::context_tag(ChipCertTag::KtagECDSASignature as u8),
                        &sig.const_bytes()[..sig.length()],
                    )
                    .inspect_err(|e| println!("{:?}", e));
            }

            // end struct container
            writer.end_container(outer_container);

            let mut cert = CertBuffer::default();
            cert.init(&raw_tlv[..writer.get_length_written()]);

            return Ok(cert);
            */

            let auth_id = make_subject_key_id(1, 2);
            let subject_id = make_subject_key_id(3, 4);
            let mut subject_dn = ChipDN::default();
            subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, matter_id_value as u64);
            subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as Oid, fabric_id_value as u64);
            let mut issuer_dn = ChipDN::default();
            issuer_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, matter_id_value as u64);
            issuer_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as Oid, fabric_id_value as u64);
            return make_chip_cert_with_ids(&subject_dn, &issuer_dn, public_key, &subject_id, &auth_id, key_pair, CertType::Knode);
        }

        pub fn make_chip_cert_with_ids(
            subject_dn: &ChipDN,
            auth_dn: &ChipDN,
            public_key: &[u8],
            subject_id: &CertificateKeyId,
            auth_id: &CertificateKeyId,
            key_pair: Option<&P256Keypair>,
            cert_type: CertType,
        ) -> Result<CertBuffer, ()> {
            return make_chip_cert_with_ids_and_times(subject_dn, auth_dn, public_key, subject_id, auth_id, 0u32, 0u32, key_pair, cert_type);
        }

        pub fn make_chip_cert_with_ids_and_times(
            subject_dn: &ChipDN,
            auth_dn: &ChipDN,
            public_key: &[u8],
            subject_id: &CertificateKeyId,
            auth_id: &CertificateKeyId,
            not_before: u32,
            not_after: u32,
            key_pair: Option<&P256Keypair>,
            cert_type: CertType,
        ) -> Result<CertBuffer, ()> {
            let mut raw_tlv: [u8; CHIP_CERT_SIZE] = [0; CHIP_CERT_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut asn1_writer = TestAsn1Writer::default();
            let mut asn1_buf = [0u8; K_MAX_CHIP_CERT_DECODE_BUF_LENGTH];
            asn1_writer.init(&mut asn1_buf);

            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            auth_dn.encode_to_tlv(&mut writer, tlv_tags::context_tag(ChipCertTag::KtagSubject as u8));

            // start a issuer_dn list

            subject_dn.encode_to_tlv(&mut writer, tlv_tags::context_tag(ChipCertTag::KtagSubject as u8));
            // start a subject dn list

            // add to cert
            writer
                .put_bytes(
                    tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8),
                    public_key,
                )
                .inspect_err(|e| println!("{:?}", e));
            asn1_writer.put_object_id(Asn1Oid::KoidSigAlgoECDSAWithSHA256 as Oid);
            asn1_writer.put_bit_string(0, public_key);

            // put a not before
            writer.put_u32(tag_not_before(), not_before);
            let asn1_not_before = chip_epoch_to_asn1_time(not_before).unwrap();
            asn1_writer.put_time(&asn1_not_before);

            // put a not after
            writer.put_u32(tag_not_after(), not_after);
            let asn1_not_after = chip_epoch_to_asn1_time(not_after).unwrap();
            asn1_writer.put_time(&asn1_not_after);

            // make empty extensions
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a list
            writer.start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut extensions_outer_container_list,
            );

            assert!(writer.put_bytes(context_tag(crate::chip::credentials::chip_cert::ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8), auth_id).inspect_err(|e| println!("{}", e)).is_ok());
            asn1_writer.put_octet_string_cls_tag(Asn1TagClasses::Kasn1TagClassContextSpecific as Class, 0, auth_id);

            assert!(writer.put_bytes(context_tag(crate::chip::credentials::chip_cert::ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8), subject_id).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(asn1_writer.put_octet_string(&subject_id[..]).is_ok());

            let mut key_usage_flag = KeyUsageFlags::empty();

            match cert_type {
                CertType::Kroot => {
                    key_usage_flag.insert(KeyUsageFlags::KkeyCertSign);
                },
                _ => {}
            }

            assert!(writer.put_u16(context_tag(crate::chip::credentials::chip_cert::ChipCertExtensionTag::KtagKeyUsage as u8), key_usage_flag.bits()).inspect_err(|e| println!("{}", e)).is_ok());
            assert!(asn1_writer.put_bit_string_with_value(key_usage_flag.bits().into()).is_ok());

            match cert_type {
                CertType::Kroot => {
                    // basic constraint
                    let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
                    writer.start_container(
                        context_tag(ChipCertExtensionTag::KtagBasicConstraints as u8),
                        tlv_types::TlvType::KtlvTypeStructure,
                        &mut outer_container,
                    );
                    assert!(asn1_writer.put_boolean(true).is_ok());
                    writer.put_boolean(context_tag(ChipCertBasicConstraintTag::KtagBasicConstraintsIsCA as u8), true);

                    // end basic constraint
                    writer.end_container(outer_container);
                },
                _ => {}
            }

            // empty extended key usage
            {
                // start extended key usage extensions list
                let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
                writer.start_container(
                    context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
                    tlv_types::TlvType::KtlvTypeArray,
                    &mut extensions_outer_container_list,
                );

                // end entensions list
                writer.end_container(extensions_outer_container_list);
            }

            writer.end_container(extensions_outer_container_list);

            if let Some(sign_key) = key_pair {
                let mut sig = P256EcdsaSignature::default();
                let asn1_written = asn1_writer.const_raw_bytes().unwrap();
                let msg =  &asn1_written[..asn1_writer.get_length_written()];
                let mut hasher = Sha256::new();
                hasher.update(&msg[..]);
                let hash_result = hasher.finalize();
                //println!("the sig hash is {:?}", hash_result.as_slice());
                assert!(sign_key.ecdsa_sign_msg(&asn1_written[..asn1_writer.get_length_written()], &mut sig).is_ok());
                writer
                    .put_bytes(
                        tlv_tags::context_tag(ChipCertTag::KtagECDSASignature as u8),
                        &sig.const_bytes()[..sig.length()],
                    )
                    .inspect_err(|e| println!("{:?}", e));
            }

            // end struct container
            writer.end_container(outer_container);

            let mut cert = CertBuffer::default();
            cert.init(&raw_tlv[..writer.get_length_written()]);

            return Ok(cert);
        }

        pub fn make_ca_cert(rcac_id_value: u64, public_key: &[u8]) -> Result<CertBuffer, ()> {
            let subject_id = make_subject_key_id(1, 2);
            let auth_id = make_subject_key_id(1, 2);
            let mut subject_dn = ChipDN::default();
            subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterRCACId as Oid, rcac_id_value as u64);
            let mut issuer_dn = ChipDN::default();
            let keypair = stub_keypair();

            return make_chip_cert_with_ids(&subject_dn, &issuer_dn, public_key, &subject_id, &auth_id, Some(&keypair), CertType::Kroot);
        }

        pub fn make_chip_cert_by_data(
            cert_data: &ChipCertificateData
        ) -> Result<CertBuffer, ()> {
            let mut raw_tlv: [u8; CHIP_CERT_SIZE] = [0; CHIP_CERT_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                tlv_types::TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            // start a issuer_dn list
            //cert_data.m_issuer_dn.encode_to_tlv(&mut writer, context_tag(ChipCertTag::KtagIssuer as u8));
            cert_data.m_issuer_dn.encode_to_tlv(&mut writer, context_tag(ChipCertTag::KtagSubject as u8));

            // start a subject dn list
            cert_data.m_subject_dn.encode_to_tlv(&mut writer, context_tag(ChipCertTag::KtagSubject as u8));

            // add public key
            writer
                .put_bytes(
                    tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8),
                    &cert_data.m_public_key,
                )
                .inspect_err(|e| println!("{:?}", e));

            // put a not before
            writer.put_u32(tag_not_before(), cert_data.m_not_before_time);
            // put a not after
            writer.put_u32(tag_not_after(), cert_data.m_not_after_time);

            // start extensions list
            let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            writer.start_container(
                context_tag(ChipCertTag::KtagExtensions as u8),
                tlv_types::TlvType::KtlvTypeList,
                &mut extensions_outer_container_list,
            );

            writer.put_bytes(context_tag(ChipCertExtensionTag::KtagAuthorityKeyIdentifier as u8), &cert_data.m_auth_key_id);
            writer.put_bytes(context_tag(ChipCertExtensionTag::KtagSubjectKeyIdentifier as u8), &cert_data.m_subject_key_id);
            //writer.put_u32(context_tag(ChipCertExtensionTag::KtagKeyUsage as u8), cert_data.m_key_usage_flags.bits() as u32);
            writer.put_u16(context_tag(ChipCertExtensionTag::KtagKeyUsage as u8), cert_data.m_key_usage_flags.bits() as u16);

            if cert_data.m_cert_flags.intersects(CertFlags::KisCA) {
                // basic constraint
                let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
                writer.start_container(
                    context_tag(ChipCertExtensionTag::KtagBasicConstraints as u8),
                    tlv_types::TlvType::KtlvTypeStructure,
                    &mut outer_container,
                );
                writer.put_boolean(context_tag(ChipCertBasicConstraintTag::KtagBasicConstraintsIsCA as u8), true);

                // end basic constraint
                writer.end_container(outer_container);
            }

            // extended key usage
            {
                // start extended key usage extensions list
                let mut extensions_outer_container_list = tlv_types::TlvType::KtlvTypeNotSpecified;
                writer.start_container(
                    context_tag(ChipCertExtensionTag::KtagExtendedKeyUsage as u8),
                    tlv_types::TlvType::KtlvTypeArray,
                    &mut extensions_outer_container_list,
                );

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KserverAuth) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KserverAuth.bits() as u8);
                }

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KclientAuth) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KclientAuth.bits() as u8);
                }

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KcodeSigning) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KcodeSigning.bits() as u8);
                }

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KemailProtection) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KemailProtection.bits() as u8);
                }

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KtimeStamping) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KtimeStamping.bits() as u8);
                }

                if cert_data.m_key_purpose_flags.intersects(KeyPurposeFlags::KoCSPSigning) {
                    writer.put_u8(anonymous_tag(), KeyPurposeFlags::KoCSPSigning.bits() as u8);
                }

                // end entensions list
                writer.end_container(extensions_outer_container_list);
            }

            // end entensions list
            writer.end_container(extensions_outer_container_list);

            // signature
            writer.put_bytes(context_tag(ChipCertTag::KtagECDSASignature as u8), cert_data.m_signature.const_bytes());

            // end struct container
            writer.end_container(outer_container);

            let mut cert = CertBuffer::default();
            assert!(cert.init(&raw_tlv[..writer.get_length_written()]).is_ok());

            return Ok(cert);
        }

        #[test]
        fn default_init() {
            let info = fabric_info_const_default();
            assert_eq!(false, info.has_operational_key());
        }

        #[test]
        fn commit() {
            let mut pa = TestPersistentStorage::default();
            let info = fabric_info_const_default();
            assert_eq!(true, info.commit_to_storge(&mut pa).is_ok());
            assert_eq!(
                true,
                pa.has_key(DefaultStorageKeyAllocator::fabric_metadata(0).key_name_str())
            );
        }

        #[test]
        fn load() {
            let mut pa = TestPersistentStorage::default();
            let mut info = fabric_info_const_default();
            info.m_vendor_id = VendorId::Common;
            let label = "abc";
            info.m_fabric_label = FabricLabelString::from(label);
            // commit first
            assert_eq!(true, info.commit_to_storge(&mut pa).is_ok());

            //let pub_key = stub_public_key();
            let keypair = stub_keypair();
            let rcac = make_chip_cert(1, 2, keypair.public_key().const_bytes(), Some(&keypair)).unwrap();
            let noc = make_chip_cert(3, 4, keypair.public_key().const_bytes(), Some(&keypair)).unwrap();

            let mut info_out = fabric_info_const_default();
            assert_eq!(
                true,
                info_out
                    .load_from_storage(&mut pa, 0, rcac.const_bytes(), noc.const_bytes())
                    .inspect_err(|e| println!("{:?}", e))
                    .is_ok()
            );
            assert_eq!(3, info_out.m_node_id);
            assert_eq!(4, info_out.m_fabric_id);
            assert_eq!(VendorId::Common, info_out.m_vendor_id);
            assert_eq!("abc", info_out.m_fabric_label.str().unwrap_or(&""));
        }

        #[test]
        fn set_op_keypair() {
            let mut info = fabric_info_const_default();
            let keypair = P256Keypair::default();

            assert_eq!(
                true,
                info.set_operational_keypair(ptr::addr_of!(keypair)).is_ok()
            );
            assert_eq!(true, info.m_internal_op_key_storage.is_some());
            assert_eq!(
                keypair.public_key().const_bytes(),
                info.m_internal_op_key_storage
                    .as_ref()
                    .unwrap()
                    .public_key()
                    .const_bytes()
            );
        }

        #[test]
        fn test_chip_data_to_tlv() {
            let pub_key = stub_public_key();
            let rcac = make_chip_cert(1, 2, &pub_key[..], None).unwrap();
            let mut cert_data = ChipCertificateData::default();

            assert!(decode_chip_cert(rcac.const_bytes(), &mut cert_data, Some(CertDecodeFlags::KgenerateTBSHash)).is_ok());
            let hash1 = cert_data.m_tbs_hash.clone();

            let output_cert_buffer = make_chip_cert_by_data(&cert_data);
            assert!(output_cert_buffer.is_ok());
            let output_cert_buffer = output_cert_buffer.unwrap();
            assert!(decode_chip_cert(rcac.const_bytes(), &mut cert_data, Some(CertDecodeFlags::KgenerateTBSHash)).is_ok());

            assert_eq!(&hash1, &cert_data.m_tbs_hash);
        }
    } // end of mod tests
} // end of mod fabric_info

mod fabric_table {
    use crate::chip::{
        chip_lib::{
            core::{
                case_auth_tag::CatValues,
                chip_config::CHIP_CONFIG_MAX_FABRICS,
                chip_encoding,
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::{
                    is_valid_fabric_index, FabricIndex, KMAX_VALID_FABRIC_INDEX,
                    KMIN_VALID_FABRIC_INDEX, KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID,
                    KUNDEFINED_FABRIC_INDEX,
                },
                node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
                tlv_tags::{self, anonymous_tag, context_tag, Tag},
                tlv_types::TlvType,
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
            },
            support::{
                default_storage_key_allocator::DefaultStorageKeyAllocator,
                default_string::DefaultString,
            },
        },
        credentials::{
            self,
            certificate_validity_policy::{
                CertificateValidityPolicy, IgnoreCertificateValidityPeriodPolicy,
            },
            chip_cert::{
                extract_node_id_fabric_id_from_op_cert,
                extract_fabric_id_from_cert,
                extract_node_id_fabric_id_from_op_cert_byte,
                extract_not_before_from_chip_cert_byte, extract_public_key_from_chip_cert_byte,
                CertBuffer, K_MAX_CHIP_CERT_LENGTH,
                CertDecodeFlags, ChipCertificateData,
            },
            chip_certificate_set::ChipCertificateSet,
            last_known_good_time::LastKnownGoodTime,
            operational_certificate_store::{CertChainElement, OperationalCertificateStore},
        },
        crypto::{
            self,
            crypto_pal::{
                ECPKey, ECPKeypair, P256EcdsaSignature, P256Keypair, P256KeypairBase,
                P256PublicKey, P256SerializedKeypair, K_MIN_CSR_BUFFER_SIZE,
            },
            generate_compressed_fabric_id,
        },
        system::system_clock::Seconds32,
        CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
    };
    use crate::chip_core_error;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_end_of_tlv;
    use crate::chip_error_incorrect_state;
    use crate::chip_error_internal;
    use crate::chip_error_invalid_argument;
    use crate::chip_error_invalid_fabric_index;
    use crate::chip_error_key_not_found;
    use crate::chip_error_no_memory;
    use crate::chip_error_not_found;
    use crate::chip_error_not_implemented;
    use crate::chip_error_persisted_storage_value_not_found;
    use crate::chip_error_fabric_mismatch_on_ica;
    use crate::chip_error_wrong_cert_dn;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::chip_static_assert;
    use crate::matter_trace_scope;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipError;
    use crate::ChipErrorResult;

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_detail;
    use crate::chip_log_error;
    use crate::chip_log_progress;

    use bitflags::{bitflags, Flags};
    //use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES, fabric_info::{self, FabricInfo, fabric_info_const_default}};
    use super::{
        fabric_info::{self, fabric_info_const_default},
        FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES,
    };
    use core::{
        ptr,
        str::{self, FromStr},
    };

    #[cfg(test)]
    use mockall::*;
    use mockall_double::double;

    //#[double]
    use super::fabric_info::FabricInfo;

    type ValidationContext<'a> = crate::chip::credentials::chip_certificate_set::ValidationContext<
        'a,
        IgnoreCertificateValidityPeriodPolicy,
    >;

    bitflags! {
        #[derive(Clone, Copy)]
        struct StateFlags: u16 {
            // If true, we are in the process of a fail-safe and there was at least one
            // operation that caused partial data in the fabric table.
            const KisPendingFabricDataPresent = (1u16 << 0);
            const KisTrustedRootPending = (1u16 << 1);
            const KisUpdatePending = (1u16 << 2);
            const KisAddPending = (1u16 << 3);

            // Only true when `AllocatePendingOperationalKey` has been called
            const KisOperationalKeyPending = (1u16 << 4);
            // True if `AllocatePendingOperationalKey` was for an existing fabric
            const KisPendingKeyForUpdateNoc = (1u16 << 5);

            // True if we allow more than one fabric with same root and fabricId in the fabric table
            // for test purposes. This disables a collision check.
            const KareCollidingFabricsIgnored = (1u16 << 6);

            // If set to true (only possible on test builds), will cause `CommitPendingFabricData()` to early
            // return during commit, skipping clean-ups, so that we can validate commit marker fabric removal.
            const KabortCommitForTest = (1u16 << 7);
        }
    }

    fn next_available_fabric_index_tag() -> Tag {
        context_tag(0)
    }

    fn fabric_indices_tag() -> Tag {
        context_tag(1)
    }

    const fn commit_marker_context_tlv_max_size() -> usize {
        use core::mem;

        tlv_estimate_struct_overhead!(
            size_of::<FabricIndex>(),
            size_of::<bool>(),
            size_of::<u64>(),
            size_of::<u64>()
        )
    }

    const fn index_info_tlv_max_size() -> usize {
        use core::mem;
        // We have a single next-available index and an array of anonymous-tagged
        // fabric indices.
        //
        // The max size of the list is (1 byte control + bytes for actual value)
        // times max number of list items, plus one byte for the list terminator.

        tlv_estimate_struct_overhead!(
            size_of::<FabricIndex>(),
            CHIP_CONFIG_MAX_FABRICS * (1 + size_of::<FabricIndex>()) + 1
        )
    }

    fn marker_fabric_index_tag() -> Tag {
        context_tag(0)
    }

    fn marker_is_addition_tag() -> Tag {
        context_tag(1)
    }

    struct CommitMarker {
        pub fabric_index: FabricIndex,
        pub is_addition: bool,
    }

    impl CommitMarker {
        pub fn new(fabric_index: FabricIndex, is_addition: bool) -> Self {
            Self {
                fabric_index,
                is_addition,
            }
        }
    }

    impl Default for CommitMarker {
        fn default() -> Self {
            Self {
                fabric_index: KUNDEFINED_FABRIC_INDEX,
                is_addition: false,
            }
        }
    }

    pub trait Delegate<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        fn fabric_will_be_removed(
            &mut self,
            fabric_table: &FabricTable<PSD, OK, OCS>,
            fabric_index: FabricIndex,
        );
        fn on_fabric_removed(
            &mut self,
            fabric_table: &FabricTable<PSD, OK, OCS>,
            fabric_index: FabricIndex,
        );
        fn next(&self) -> Option<*mut dyn Delegate<PSD, OK, OCS>>;
        fn remove_next(&mut self);
        fn set_next(&mut self, next: Option<*mut dyn Delegate<PSD, OK, OCS>>);
    }

    #[repr(u8)]
    #[derive(Copy, Clone, PartialEq)]
    pub enum AdvertiseIdentity {
        Yes,
        No,
    }

    // Increment a fabric index in a way that ensures that it stays in the valid
    // range [kMinValidFabricIndex, kMaxValidFabricIndex].
    fn next_fabric_index(fabric_index: FabricIndex) -> FabricIndex {
        if fabric_index == KMAX_VALID_FABRIC_INDEX {
            return KMIN_VALID_FABRIC_INDEX;
        }

        return (fabric_index + 1) as FabricIndex;
    }

    pub struct FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        m_states: [FabricInfo; CHIP_CONFIG_MAX_FABRICS],
        // Used for UpdateNOC pending fabric updates
        m_pending_fabric: FabricInfo,
        m_storage: *mut PSD,
        m_operational_keystore: *mut OK,
        m_op_cert_store: *mut OCS,
        // FabricTable::Delegate link to first node, since FabricTable::Delegate is a form
        // of intrusive linked-list item.
        m_delegate_list_root: Option<*mut dyn Delegate<PSD, OK, OCS>>,
        //m_delegate_list_root: * mut dyn Delegate<PSD, OK, OCS>,

        // When mStateFlags.Has(kIsPendingFabricDataPresent) is true, this holds the index of the fabric
        // for which there is currently pending data.
        m_fabric_index_with_pending_state: FabricIndex,

        // For when a revert occurs during init, so that more clean-up can be scheduled by caller.
        m_deleted_fabric_index_from_init: FabricIndex,

        //create the last known good time
        m_last_known_good_time: LastKnownGoodTime<PSD>,

        // We may not have an mNextAvailableFabricIndex if our table is as large as
        // it can go and is full.
        m_next_available_fabric_index: Option<FabricIndex>,

        m_fabric_count: u8,

        m_state_flag: StateFlags,
    }

    pub struct InitParams<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        pub storage: *mut PSD,
        pub operational_keystore: *mut OK,
        pub op_certs_store: *mut OCS,
    }

    impl<PSD, OK, OCS> Default for InitParams<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        fn default() -> Self {
            Self {
                storage: ptr::null_mut(),
                operational_keystore: ptr::null_mut(),
                op_certs_store: ptr::null_mut(),
            }
        }
    }

    pub struct SignVidVerificationResponseData {
        pub fabric_index: FabricIndex,
        pub fabric_binding_version: u8,
        //TODO; chech the type
        pub signature: [u8; 1],
    }

    #[cfg(test)]
    pub fn fabric_table_const_default<PSD, OK, OCS>() -> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        FabricTable {
            //m_states: [const {FabricInfo::default()}; CHIP_CONFIG_MAX_FABRICS],
            m_states: core::array::from_fn(|_| FabricInfo::default()),
            m_pending_fabric: FabricInfo::default(),
            m_storage: ptr::null_mut(),
            m_operational_keystore: ptr::null_mut(),
            m_op_cert_store: ptr::null_mut(),
            //m_delegate_list_root: ptr::null_mut(),
            m_delegate_list_root: None,
            m_fabric_index_with_pending_state: KUNDEFINED_FABRIC_INDEX,
            m_deleted_fabric_index_from_init: KUNDEFINED_FABRIC_INDEX,
            m_last_known_good_time: LastKnownGoodTime::<PSD>::const_default(),
            m_next_available_fabric_index: None,
            m_fabric_count: 0,
            // TODO check the init value
            m_state_flag: StateFlags::KabortCommitForTest,
        }
    }

    #[cfg(not(test))]
    pub const fn fabric_table_const_default<PSD, OK, OCS>() -> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        FabricTable {
            m_states: [const { fabric_info_const_default() }; CHIP_CONFIG_MAX_FABRICS],
            m_pending_fabric: fabric_info_const_default(),
            m_storage: ptr::null_mut(),
            m_operational_keystore: ptr::null_mut(),
            m_op_cert_store: ptr::null_mut(),
            //m_delegate_list_root: ptr::null_mut(),
            m_delegate_list_root: None,
            m_fabric_index_with_pending_state: KUNDEFINED_FABRIC_INDEX,
            m_deleted_fabric_index_from_init: KUNDEFINED_FABRIC_INDEX,
            m_last_known_good_time: LastKnownGoodTime::<PSD>::const_default(),
            m_next_available_fabric_index: None,
            m_fabric_count: 0,
            // TODO check the init value
            m_state_flag: StateFlags::KabortCommitForTest,
        }
    }

    impl<PSD, OK, OCS> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        fn load_from_storage(
            &mut self,
            fabric_index: FabricIndex,
            index: usize,
        ) -> ChipErrorResult {
            verify_or_return_error!(
                !self.m_storage.is_null(),
                Err(chip_error_invalid_argument!())
            );
            verify_or_return_error!(
                !self.m_states[index].is_initialized(),
                Err(chip_error_incorrect_state!())
            );

            let mut noc_buf = CertBuffer::default();
            let mut rcac_buf = CertBuffer::default();

            let err = self
                .fetch_noc_cert(fabric_index, &mut noc_buf)
                .and_then(|_| {
                    self.fetch_root_cert(fabric_index, &mut rcac_buf)
                        .and_then(|_| unsafe {
                            self.m_states[index].load_from_storage(
                                self.m_storage.as_mut().unwrap(),
                                fabric_index,
                                rcac_buf.const_bytes(),
                                noc_buf.const_bytes(),
                            )
                        })
                });

            if err.is_err() {
                chip_log_error!(
                    FabricProvisioning,
                    "Failed to load fabric {:#x}: {}",
                    fabric_index,
                    err.err().unwrap()
                );
                self.m_states[index].reset();
                return err;
            }

            chip_log_progress!(FabricProvisioning, "fabric index {:#x} was retrieved from storage. Compressed Fabric Id {:#x}, FabricId {:#x}, NodeId {:#x}, VendorId {:#x}",
                self.m_states[index].get_fabric_index(), self.m_states[index].get_compressed_fabric_id(), self.m_states[index].get_fabric_id(), self.m_states[index].get_node_id(), self.m_states[index].get_vendor_id() as u16);

            chip_ok!()
        }

        fn read_fabric_info<'a, Reader: TlvReader<'a>>(
            &mut self,
            reader: &mut Reader,
        ) -> ChipErrorResult {
            reader.next_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
            let container_type = reader.enter_container()?;
            reader.next_tag(next_available_fabric_index_tag())?;

            if reader.get_type() == TlvType::KtlvTypeNull {
                self.m_next_available_fabric_index = None;
            } else {
                self.m_next_available_fabric_index = Some(reader.get_u8()?);
            }

            reader.next_type_tag(TlvType::KtlvTypeArray, fabric_indices_tag())?;
            let array_type = reader.enter_container()?;
            let mut err: ChipError = chip_error_internal!();
            while reader.next().inspect_err(|e| err = *e).is_ok() {
                if (self.m_fabric_count as usize) >= self.m_states.len() {
                    return Err(chip_error_no_memory!());
                }

                let current_fabric_index = reader.get_u8()?;

                //if self.load_from_storage(current_fabric_index, &mut self.m_states[self.m_fabric_count as usize]).is_ok() {
                if self
                    .load_from_storage(current_fabric_index, self.m_fabric_count as usize)
                    .is_ok()
                {
                    self.m_fabric_count += 1;
                } else {
                    // This could happen if we failed to store our fabric index info
                    // after we deleted the fabric from storage.  Just ignore this
                    // fabric index and keep going.
                }
            }

            if err != chip_error_end_of_tlv!() {
                return Err(err);
            }

            reader.exit_container(array_type)?;

            reader.exit_container(container_type)?;

            reader.verify_end_of_container()?;

            self.ensure_next_available_fabric_index_updated();

            chip_ok!()
        }

        pub fn init(&mut self, init_params: &InitParams<PSD, OK, OCS>) -> ChipErrorResult {
            verify_or_return_error!(
                !init_params.storage.is_null(),
                Err(chip_error_invalid_argument!())
            );
            verify_or_return_error!(
                !init_params.op_certs_store.is_null(),
                Err(chip_error_invalid_argument!())
            );

            self.m_storage = init_params.storage;
            self.m_operational_keystore = init_params.operational_keystore;
            self.m_op_cert_store = init_params.op_certs_store;

            chip_log_detail!(
                FabricProvisioning,
                "Initializing FabricTable from persistent storage"
            );

            chip_static_assert!(KMAX_VALID_FABRIC_INDEX <= u8::MAX);

            self.m_fabric_count = 0;
            for f in &mut self.m_states {
                f.reset();
            }
            self.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);
            // Init failure of Last Known Good Time is non-fatal.  If Last Known Good
            // Time is unknown during incoming certificate validation for CASE and
            // current time is also unknown, the certificate validity policy will see
            // this condition and can act appropriately.
            self.m_last_known_good_time.init(self.m_storage);

            const SIZE: usize = index_info_tlv_max_size();
            let mut buf: [u8; SIZE] = [0; SIZE];

            unsafe {
                match self.m_storage.as_mut().unwrap().sync_get_key_value(
                    DefaultStorageKeyAllocator::fabric_index_info().key_name_str(),
                    &mut buf,
                ) {
                    Ok(data_size) => {
                        let mut reader = TlvContiguousBufferReader::default();
                        reader.init(buf.as_ptr(), data_size);

                        self.read_fabric_info(&mut reader).inspect_err(|e| {
                            chip_log_error!(
                                FabricProvisioning,
                                "Error loading fabric table {}, we are in a bad state!",
                                e
                            );
                        })?;
                    }
                    Err(e) => {
                        if e == chip_error_persisted_storage_value_not_found!() {
                            // No fabrics yet.  Nothing to be done here.
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

            match self.get_commit_marker() {
                Ok(commit_marker) => {
                    // Found a commit marker! We need to possibly delete a loaded fabric
                    chip_log_error!(FabricProvisioning, "Found a FabricTable aborted commit for index {:#x} (isAddition: {}), removing!", commit_marker.fabric_index as u32, commit_marker.is_addition);
                    self.m_deleted_fabric_index_from_init = commit_marker.fabric_index;

                    // Can't do better on error. We just have to hope for the best.
                    self.delete(commit_marker.fabric_index);
                }
                Err(e) => {
                    // Got an error, but somehow value is not missing altogether: inconsistent state but touch nothing.
                    if e != chip_error_persisted_storage_value_not_found!() {
                        chip_log_error!(
                            FabricProvisioning,
                            "Error loading Table commit marker {}, hope for the best",
                            e
                        );
                    }
                }
            }

            chip_ok!()
        }
    }

    impl<PSD, OK, OCS> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        pub fn delete(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
            matter_trace_scope!("Delete", "Fabric");
            verify_or_return_error!(
                !self.m_storage.is_null(),
                Err(chip_error_invalid_argument!())
            );
            verify_or_return_error!(
                is_valid_fabric_index(fabric_index),
                Err(chip_error_invalid_argument!())
            );

            let mut delegate = self.m_delegate_list_root;
            unsafe {
                while delegate.is_some() {
                    let d = delegate.take().unwrap().as_mut().unwrap();
                    let next = d.next();
                    d.fabric_will_be_removed(self, fabric_index);
                    delegate = next;
                }
            }

            /*
            if let Some(mut delegate) = self.m_delegate_list_root {
                unsafe {
                    while !delegate.is_null() {
                        let delegate_ref = delegate.as_mut().unwrap();
                        let next_delegate = delegate_ref.next();
                        delegate_ref.fabric_will_be_removed(self, fabric_index);
                        delegate = next_delegate;
                    }
                }
            }
            */

            if self.has_pending_fabric_update()
                && (self.m_pending_fabric.get_fabric_index() == fabric_index)
            {
                self.revert_pending_fabric_data();
            }

            let metadata_err = self.delete_metadata_from_storage(fabric_index);

            let mut op_key_err = chip_ok!();

            let handle_not_having_data = |e: ChipError| -> Result<(), ChipError> {
                if e == chip_error_invalid_fabric_index!() {
                    chip_ok!()
                } else {
                    Err(e)
                }
            };

            if !self.m_operational_keystore.is_null() {
                unsafe {
                    op_key_err = self
                        .m_operational_keystore
                        .as_mut()
                        .unwrap()
                        .remove_op_keypair_for_fabric(fabric_index)
                        .or_else(|e| {
                            // Not having found data is not an error, we may just have gotten here
                            // on a fail-safe expiry after `RevertPendingFabricData`.
                            handle_not_having_data(e)
                        });
                }
            }

            let mut op_certs_err = chip_ok!();

            if !self.m_op_cert_store.is_null() {
                unsafe {
                    op_certs_err = self
                        .m_op_cert_store
                        .as_mut()
                        .unwrap()
                        .remove_certs_for_fabric(fabric_index)
                        .or_else(|e| handle_not_having_data(e));
                }
            }

            let fabric_info_option = self.get_mutable_fabric_by_index(fabric_index);
            let fabric_is_initialized = fabric_info_option
                .as_ref()
                .is_some_and(|info| info.is_initialized());

            if fabric_is_initialized {
                let fabric_info = fabric_info_option.unwrap();
                fabric_info.reset();

                if self.m_next_available_fabric_index.is_none() {
                    // We must have been in a situation where CHIP_CONFIG_MAX_FABRICS is 254
                    // and our fabric table was full, so there was no valid next index.  We
                    // have a single available index now, though; use it as
                    // mNextAvailableFabricIndex.
                    self.m_next_available_fabric_index = Some(fabric_index);
                }

                // If StoreFabricIndexInfo fails here, that's probably OK.  When we try to
                // read things from storage later we will realize there is nothing for this
                // index.
                self.store_fabric_index_info();

                if self.m_fabric_count == 0 {
                    chip_log_error!(
                        FabricProvisioning,
                        "Trying to delete a fabric, but the current fabric count is already 0"
                    );
                } else {
                    self.m_fabric_count -= 1;
                    chip_log_progress!(FabricProvisioning, "Fabric {:#x} deleted", fabric_index);
                }
            }

            let mut delegate = self.m_delegate_list_root;
            unsafe {
                while delegate.is_some() {
                    let d = delegate.take().unwrap().as_mut().unwrap();
                    let next = d.next();
                    d.on_fabric_removed(self, fabric_index);
                    delegate = next;
                }
            }

            if fabric_is_initialized {
                // Only return error after trying really hard to remove everything we could
                return metadata_err.and(op_key_err).and(op_certs_err);
            }

            Err(chip_error_not_found!())
        }

        pub fn delete_all_fabric(&mut self) {
            chip_static_assert!(KMAX_VALID_FABRIC_INDEX <= u8::MAX);

            self.revert_pending_fabric_data();

            let mut to_be_deleted: [bool; CHIP_CONFIG_MAX_FABRICS] =
                [false; CHIP_CONFIG_MAX_FABRICS];

            for fabric in &mut *self {
                let index = fabric.get_fabric_index() as usize;
                if index <= CHIP_CONFIG_MAX_FABRICS {
                    to_be_deleted[index] = true;
                } else {
                    chip_log_error!(FabricProvisioning, "cannot delete {}", index);
                }
            }

            for (index, deleted) in to_be_deleted.into_iter().enumerate() {
                if deleted {
                    self.delete(index as u8);
                }
            }
        }

        pub fn find_fabric(
            &self,
            root_pub_key: &P256PublicKey,
            fabric_id: FabricId,
        ) -> Option<&FabricInfo> {
            return self.find_fabric_common(root_pub_key, fabric_id);
        }

        pub fn find_fabric_with_index(&self, fabric_index: FabricIndex) -> Option<&FabricInfo> {
            if fabric_index == KUNDEFINED_FABRIC_INDEX {
                return None;
            }

            if self.has_pending_fabric_update()
                && (self.m_pending_fabric.get_fabric_index() == fabric_index)
            {
                return Some(&self.m_pending_fabric);
            }

            for fabric in &self.m_states {
                if !fabric.is_initialized() {
                    continue;
                }

                if fabric.get_fabric_index() == fabric_index {
                    return Some(fabric);
                }
            }

            return None;
        }

        pub fn find_indentiy(
            &self,
            root_pub_key: &P256PublicKey,
            fabric_id: FabricId,
            node_id: NodeId,
        ) -> Option<&FabricInfo> {
            return self.find_fabric_common_with_id(root_pub_key, fabric_id, Some(node_id));
        }

        pub fn find_fabric_with_compressed_id(
            &self,
            compressed_fabric_id: CompressedFabricId,
        ) -> Option<&FabricInfo> {
            if self.has_pending_fabric_update()
                && (self.m_pending_fabric.get_compressed_fabric_id() == compressed_fabric_id)
            {
                return Some(&self.m_pending_fabric);
            }

            for fabric in &self.m_states {
                if !fabric.is_initialized() {
                    continue;
                }

                // Don't need peer id, I guess?
                // if (compressedFabricId == fabric.GetPeerId().GetCompressedFabricId())
                if compressed_fabric_id == fabric.get_compressed_fabric_id() {
                    return Some(fabric);
                }
            }

            return None;
        }

        pub fn shutdown(&mut self) {
            if self.m_storage.is_null() {
                return;
            }
            chip_log_progress!(FabricProvisioning, "Shutting down FabricTable");

            let mut delegate = self.m_delegate_list_root;
            unsafe {
                while delegate.is_some() {
                    let d = delegate.take().unwrap().as_mut().unwrap();
                    let next = d.next();
                    d.remove_next();
                    delegate = next;
                }
            }

            self.revert_pending_fabric_data();

            for fabric in &mut self.m_states {
                fabric.reset();
            }

            self.m_storage = ptr::null_mut();
        }

        pub fn get_deleted_fabric_from_commit_marker(&mut self) -> FabricIndex {
            let ret_val = self.m_deleted_fabric_index_from_init;

            self.m_deleted_fabric_index_from_init = KUNDEFINED_FABRIC_INDEX;

            ret_val
        }

        pub fn clear_commit_marker(&mut self) {
            if self.m_storage.is_null() {
                return;
            }
            unsafe {
                self.m_storage.as_mut().unwrap().sync_delete_key_value(
                    DefaultStorageKeyAllocator::fabric_table_commit_marker_key().key_name_str(),
                );
            }
        }

        pub fn forget(&mut self, fabric_index: FabricIndex) {
            chip_log_progress!(
                FabricProvisioning,
                "Forgetting fabirc {:#x}",
                fabric_index as u32
            );

            let is_found = self.get_mutable_fabric_by_index(fabric_index).is_some();

            if is_found {
                self.revert_pending_fabric_data();
                if let Some(info) = self.get_mutable_fabric_by_index(fabric_index) {
                    info.reset();
                }
            }
        }

        pub fn add_fabric_delegate(
            &mut self,
            delegate: Option<*mut dyn Delegate<PSD, OK, OCS>>,
        ) -> ChipErrorResult {
            verify_or_return_error!(delegate.is_some(), Err(chip_error_invalid_argument!()));

            let delegate = delegate.unwrap();

            unsafe {
                let mut iter = self.m_delegate_list_root;
                while iter.is_some() {
                    let i = iter.take().unwrap();
                    if delegate == i {
                        return chip_ok!();
                    }
                    iter = i.as_ref().unwrap().next();
                }

                delegate
                    .clone()
                    .as_mut()
                    .unwrap()
                    .set_next(self.m_delegate_list_root);
                self.m_delegate_list_root = Some(delegate);
            }

            chip_ok!()
        }

        pub fn remove_fabric_delegate(
            &mut self,
            mut delegate: Option<*mut dyn Delegate<PSD, OK, OCS>>,
        ) {
            if delegate.is_none() {
                return;
            }

            unsafe {
                if self.m_delegate_list_root.is_some() && self.m_delegate_list_root == delegate {
                    let root = self.m_delegate_list_root.take().unwrap();
                    self.m_delegate_list_root = root.clone().as_mut().unwrap().next();
                } else {
                    let mut current = self.m_delegate_list_root;

                    while current.is_some() {
                        let peek_next = current.clone().take().unwrap().as_ref().unwrap().next();
                        let next = current.clone().take().unwrap().as_ref().unwrap().next();
                        if peek_next == delegate {
                            let temp = delegate.clone().take().unwrap().as_ref().unwrap().next();
                            current.take().unwrap().as_mut().unwrap().set_next(temp);
                            delegate.take().unwrap().as_mut().unwrap().set_next(None);
                            return;
                        }

                        current = next;
                    }
                }
            }
        }

        pub fn set_fabric_label(
            &mut self,
            fabric_index: FabricIndex,
            fabric_label: &str,
        ) -> ChipErrorResult {
            verify_or_return_error!(
                !self.m_storage.is_null(),
                Err(chip_error_incorrect_state!())
            );
            verify_or_return_error!(
                is_valid_fabric_index(fabric_index),
                Err(chip_error_invalid_fabric_index!())
            );
            verify_or_return_error!(
                fabric_label.len() <= KFABRIC_LABEL_MAX_LENGTH_IN_BYTES,
                Err(chip_error_invalid_argument!())
            );

            if !self
                .find_fabric_with_index(fabric_index)
                .is_some_and(|info| info.is_initialized())
            {
                return Err(chip_error_invalid_fabric_index!());
            }

            if let Some(info) = self.get_mutable_fabric_by_index(fabric_index) {
                info.set_fabric_label(fabric_label)?;
            }

            // we cannot borrow mut info and call the store_fabric_meta. So we have to borrow
            // immutable info once again to store the data
            if let Some(info) = self.find_fabric_with_index(fabric_index) {
                if !self
                    .m_state_flag
                    .intersects(StateFlags::KisAddPending | StateFlags::KisUpdatePending)
                    && info.get_fabric_index() != self.m_pending_fabric.get_fabric_index()
                {
                    self.store_fabric_metadata(info)?;
                }
            }

            chip_ok!()
        }

        pub fn get_fabric_label(
            &self,
            fabric_index: FabricIndex,
        ) -> Result<Option<&str>, ChipError> {
            if let Some(info) = self.find_fabric_with_index(fabric_index) {
                Ok(info.get_fabric_label())
            } else {
                Err(chip_error_invalid_fabric_index!())
            }
        }

        pub fn get_last_known_good_chip_epoch_time(&self) -> Result<Seconds32, ChipError> {
            self.m_last_known_good_time
                .get_last_known_good_chip_epoch_time()
        }

        pub fn set_last_known_good_chip_epoch_time(
            &mut self,
            last_known_good_chip_epoch_time: Seconds32,
        ) -> ChipErrorResult {
            let mut latest_not_before = Seconds32::from_secs(0);
            for fabric in &self.m_states {
                if !fabric.is_initialized() {
                    continue;
                }
                {
                    let mut rcac = CertBuffer::default();
                    self.fetch_root_cert(fabric.get_fabric_index(), &mut rcac)?;
                    let rcac_not_before =
                        extract_not_before_from_chip_cert_byte(rcac.const_bytes())?;
                    latest_not_before = core::cmp::max(latest_not_before, rcac_not_before);
                }
                {
                    let mut icac = CertBuffer::default();
                    self.fetch_icac_cert(fabric.get_fabric_index(), &mut icac)?;
                    if icac.length() > 0 {
                        let icac_not_before =
                            extract_not_before_from_chip_cert_byte(icac.const_bytes())?;
                        latest_not_before = core::cmp::max(latest_not_before, icac_not_before);
                    }
                }
                {
                    let mut noc = CertBuffer::default();
                    self.fetch_noc_cert(fabric.get_fabric_index(), &mut noc)?;
                    let noc_not_before = extract_not_before_from_chip_cert_byte(noc.const_bytes())?;
                    latest_not_before = core::cmp::max(latest_not_before, noc_not_before);
                }
            }

            self.m_last_known_good_time
                .set_last_known_good_chip_epoch_time(
                    last_known_good_chip_epoch_time,
                    latest_not_before,
                )?;
            chip_ok!()
        }

        pub fn fabric_count(&self) -> u8 {
            self.m_fabric_count
        }

        pub fn fetch_root_cert(
            &self,
            fabric_index: FabricIndex,
            out_cert: &mut CertBuffer,
        ) -> ChipErrorResult {
            matter_trace_scope!("FetchRootCert", "Fabric");
            verify_or_return_error!(
                !self.m_op_cert_store.is_null(),
                Err(chip_error_incorrect_state!())
            );

            unsafe {
                let size = self.m_op_cert_store.as_ref().unwrap().get_certificate(
                    fabric_index,
                    CertChainElement::Krcac,
                    out_cert.all_bytes(),
                )?;
                out_cert.set_length(size)?;
            }

            chip_ok!()
        }

        pub fn fetch_pending_non_fabric_associcated_root_cert(
            &self,
            _out_cert: &mut [u8],
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_icac_cert(
            &self,
            fabric_index: FabricIndex,
            out_cert: &mut CertBuffer,
        ) -> ChipErrorResult {
            matter_trace_scope!("FetchICACert", "Fabric");
            verify_or_return_error!(
                !self.m_op_cert_store.is_null(),
                Err(chip_error_incorrect_state!())
            );

            unsafe {
                match self.m_op_cert_store.as_ref().unwrap().get_certificate(
                    fabric_index,
                    CertChainElement::Kicac,
                    out_cert.all_bytes(),
                ) {
                    Ok(size) => {
                        out_cert.set_length(size)?;
                        return chip_ok!();
                    }
                    Err(e) => {
                        if e == chip_error_not_found!() {
                            if self
                                .m_op_cert_store
                                .as_ref()
                                .unwrap()
                                .has_certificate_for_fabric(fabric_index, CertChainElement::Knoc)
                            {
                                out_cert.set_length(0);
                                return chip_ok!();
                            }
                        }
                        return Err(e);
                    }
                }
            }
        }

        pub fn fetch_noc_cert(
            &self,
            fabric_index: FabricIndex,
            out_cert: &mut CertBuffer,
        ) -> ChipErrorResult {
            matter_trace_scope!("FetchNOCCert", "Fabric");
            verify_or_return_error!(
                !self.m_op_cert_store.is_null(),
                Err(chip_error_incorrect_state!())
            );

            unsafe {
                let size = self.m_op_cert_store.as_ref().unwrap().get_certificate(
                    fabric_index,
                    CertChainElement::Knoc,
                    out_cert.all_bytes(),
                )?;
                out_cert.set_length(size)?;
            }

            chip_ok!()
        }

        pub fn fetch_vid_verification_statement(
            &self,
            _fabric_index: FabricIndex,
            _out_vid_verification_statement: &mut [u8],
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_vvsc(
            &self,
            _fabric_index: FabricIndex,
            _out_vvsc: &mut [u8],
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_root_pubkey(
            &self,
            fabric_index: FabricIndex,
        ) -> Result<P256PublicKey, ChipError> {
            matter_trace_scope!("FetchRootPubkey", "Fabric");
            let fabric_info = self
                .find_fabric_with_index(fabric_index)
                .ok_or(chip_error_invalid_fabric_index!())?;

            return fabric_info.fetch_root_pubkey();
        }

        pub fn fetch_Cats(&self, _fabric_index: FabricIndex) -> Result<CatValues, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn sign_with_op_keypair(
            &self,
            fabric_index: FabricIndex,
            message: &[u8],
            out_signature: &mut P256EcdsaSignature,
        ) -> ChipErrorResult {
            if let Some(info) = self.find_fabric_with_index(fabric_index) {
                if info.has_operational_key() {
                    return info.sign_with_op_keypair(message, out_signature);
                }

                if !self.m_operational_keystore.is_null() {
                    unsafe {
                        return self
                            .m_operational_keystore
                            .as_ref()
                            .unwrap()
                            .sign_with_op_keypair(fabric_index, message, out_signature);
                    }
                }
            }
            Err(chip_error_key_not_found!())
        }

        pub fn allocate_ephemeral_keypair_for_case(&self) -> Result<P256Keypair, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn release_ephemeral_keypair(&self, _keypair: P256Keypair) {}

        pub fn allocate_pending_operation_key(
            &mut self,
            fabric_index: Option<FabricIndex>,
            out_csr: &mut [u8],
        ) -> Result<usize, ChipError> {
            verify_or_return_error!(
                !self.m_operational_keystore.is_null(),
                Err(chip_error_incorrect_state!())
            );

            verify_or_return_error!(
                !self
                    .m_state_flag
                    .contains(StateFlags::KisPendingFabricDataPresent),
                Err(chip_error_incorrect_state!())
            );
            verify_or_return_error!(
                out_csr.len() >= K_MIN_CSR_BUFFER_SIZE,
                Err(chip_error_buffer_too_small!())
            );

            self.ensure_next_available_fabric_index_updated();
            let mut fabric_index_to_use = KUNDEFINED_FABRIC_INDEX;

            if let Some(index) = fabric_index {
                verify_or_return_error!(
                    !self
                        .m_state_flag
                        .contains(StateFlags::KisTrustedRootPending),
                    Err(chip_error_incorrect_state!())
                );

                fabric_index_to_use = index;
                self.m_state_flag
                    .insert(StateFlags::KisPendingKeyForUpdateNoc);
            } else {
                if let Some(index) = self.m_next_available_fabric_index {
                    fabric_index_to_use = index;
                    self.m_state_flag
                        .remove(StateFlags::KisPendingKeyForUpdateNoc);
                } else {
                    return Err(chip_error_no_memory!());
                }
            }

            verify_or_return_error!(
                is_valid_fabric_index(fabric_index_to_use),
                Err(chip_error_invalid_fabric_index!())
            );
            verify_or_return_error!(
                self.set_pending_data_fabric_index(fabric_index_to_use),
                Err(chip_error_incorrect_state!())
            );
            let mut csr_size: usize = 0;
            unsafe {
                csr_size = self
                    .m_operational_keystore
                    .as_mut()
                    .unwrap()
                    .new_op_keypair_for_fabric(self.m_fabric_index_with_pending_state, out_csr)?;
            }

            self.m_state_flag
                .insert(StateFlags::KisOperationalKeyPending);

            Ok(csr_size)
        }

        pub fn has_pending_operational_key(
            &self,
            out_is_pending_key_for_update_noc: &mut bool,
        ) -> bool {
            let has_op_key_pending = self
                .m_state_flag
                .contains(StateFlags::KisOperationalKeyPending);

            if has_op_key_pending {
                *out_is_pending_key_for_update_noc = self
                    .m_state_flag
                    .contains(StateFlags::KisPendingKeyForUpdateNoc);
            }

            has_op_key_pending
        }

        pub fn has_operational_key_for_fabric(&self, fabric_index: FabricIndex) -> bool {
            if let Some(info) = self.find_fabric_with_index(fabric_index) {
                if info.has_operational_key() {
                    return true;
                }
                if !self.m_operational_keystore.is_null() {
                    unsafe {
                        return self
                            .m_operational_keystore
                            .as_ref()
                            .unwrap()
                            .has_op_keypair_for_fabric(fabric_index);
                    }
                }
            }

            false
        }

        pub fn get_pending_fabric_index(&self) -> FabricIndex {
            KUNDEFINED_FABRIC_INDEX
        }

        pub fn get_operational_keystore(&self) -> *const OK {
            self.m_operational_keystore
        }

        pub fn add_new_pending_trusted_root_cert(&mut self, rcac: &[u8]) -> ChipErrorResult {
            verify_or_return_error!(
                !self.m_op_cert_store.is_null(),
                Err(chip_error_incorrect_state!())
            );

            // We should not already have pending NOC chain elements when we get here
            verify_or_return_error!(
                !self.m_state_flag.intersects(
                    StateFlags::KisTrustedRootPending
                        | StateFlags::KisUpdatePending
                        | StateFlags::KisAddPending
                ),
                Err(chip_error_incorrect_state!())
            );

            self.ensure_next_available_fabric_index_updated();
            let mut fabric_index_to_use = KUNDEFINED_FABRIC_INDEX;

            if let Some(index) = self.m_next_available_fabric_index {
                fabric_index_to_use = index;
            } else {
                return Err(chip_error_no_memory!());
            }

            verify_or_return_error!(
                is_valid_fabric_index(fabric_index_to_use),
                Err(chip_error_invalid_fabric_index!())
            );
            verify_or_return_error!(
                self.set_pending_data_fabric_index(fabric_index_to_use),
                Err(chip_error_incorrect_state!())
            );

            unsafe {
                self.m_op_cert_store
                    .as_mut()
                    .unwrap()
                    .add_new_trusted_root_cert_for_fabric(fabric_index_to_use, rcac)?;
            }

            self.m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);
            self.m_state_flag.insert(StateFlags::KisTrustedRootPending);

            chip_ok!()
        }

        pub fn add_new_pending_fabric_with_operational_keystore(
            &mut self,
            _noc: &[u8],
            _icac: &[u8],
            _vendor_id: u16,
            _advertise_identity: Option<AdvertiseIdentity>,
        ) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_pending_fabric_with_provided_op_key(
            &mut self,
            _noc: &[u8],
            _icac: &[u8],
            _vendor_id: u16,
            _existeding_op_key: &P256Keypair,
            _is_existing_op_key_externally_owned: bool,
            _advertise_identity: Option<AdvertiseIdentity>,
        ) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn update_pending_fabric_with_operational_keystore(
            &mut self,
            _fabric_index: FabricIndex,
            _noc: &[u8],
            _icac: &[u8],
            _advertise_identity: Option<AdvertiseIdentity>,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn update_pending_fabric_with_provided_op_key(
            &mut self,
            _noc: &[u8],
            _icac: &[u8],
            _existeding_op_key: &P256Keypair,
            _is_existing_op_key_externally_owned: bool,
            _advertise_identity: Option<AdvertiseIdentity>,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn commit_pending_fabric_data(&mut self) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn revert_pending_fabric_data(&mut self) {
            matter_trace_scope!("RevertPendingFabricData", "Fabric");
            // Will clear pending UpdateNoc/AddNOC
            self.revert_pending_op_certs_except_root();

            if !self.m_operational_keystore.is_null() {
                unsafe {
                    self.m_operational_keystore
                        .as_mut()
                        .unwrap()
                        .revert_pending_keypair();
                }
            }

            if !self.m_op_cert_store.is_null() {
                unsafe {
                    self.m_op_cert_store
                        .as_mut()
                        .unwrap()
                        .revert_pending_op_certs_except_root();
                }
            }

            self.m_last_known_good_time
                .revert_pending_last_known_good_chip_epoch_time();

            self.m_state_flag.clear();
            self.m_fabric_index_with_pending_state = KUNDEFINED_FABRIC_INDEX;
        }

        pub fn revert_pending_op_certs_except_root(&mut self) {
            matter_trace_scope!("RevertPendingOpCertsExceptRoot", "Fabric");
            self.m_pending_fabric.reset();

            if self
                .m_state_flag
                .contains(StateFlags::KisPendingFabricDataPresent)
            {
                chip_log_error!(
                    FabricProvisioning,
                    "Reverting pending fabric data for fabric {:#x}",
                    self.m_fabric_index_with_pending_state
                );
            }

            if !self.m_op_cert_store.is_null() {
                unsafe {
                    self.m_op_cert_store
                        .as_mut()
                        .unwrap()
                        .revert_pending_op_certs_except_root();
                }
            }

            if self.m_state_flag.contains(StateFlags::KisAddPending) {
                self.delete(self.m_fabric_index_with_pending_state);
            }

            self.m_state_flag.remove(StateFlags::KisAddPending);
            self.m_state_flag.remove(StateFlags::KisUpdatePending);

            if self
                .m_state_flag
                .contains(StateFlags::KisTrustedRootPending)
            {
                self.m_fabric_index_with_pending_state = KUNDEFINED_FABRIC_INDEX;
            }
        }

        pub fn verify_credentials(
            &self,
            fabric_index: FabricIndex,
            noc: &[u8],
            icac: Option<&[u8]>,
            context: &mut ValidationContext,
        ) -> Result<
            (
                CompressedFabricId,
                FabricId,
                NodeId,
                P256PublicKey,
                P256PublicKey,
            ),
            ChipError,
        > {
            matter_trace_scope!("VerifyCredentials", "Fabric");
            let mut rcac = CertBuffer::default();
            self.fetch_root_cert(fabric_index, &mut rcac)?;

            return self.run_verify_credentials(noc, icac, rcac.const_bytes(), context);
        }

        pub fn run_verify_credentials<'a>(
            &self,
            noc: &[u8],
            icac: Option<&[u8]>,
            rcac: &[u8],
            context: &'a mut ValidationContext,
        ) -> Result<
            (
                CompressedFabricId,
                FabricId,
                NodeId,
                P256PublicKey,
                P256PublicKey,
            ),
            ChipError,
        > {
            //const K_MAX_NUM_CERTS_IN_OP_CERTS: u8 = 3;

            let mut certificates = ChipCertificateSet::default();
            certificates.load_cert(rcac, CertDecodeFlags::KisTrustAnchor)?;
            let mut is_icac_present = false;

            if let Some(icac_buf) = icac {
                certificates.load_cert(icac_buf, CertDecodeFlags::KgenerateTBSHash)?;
                is_icac_present = true
            }

            certificates.load_cert(noc, CertDecodeFlags::KgenerateTBSHash)?;

            let last_cert = certificates.get_last_cert().ok_or(chip_error_internal!())?;
            let noc_subject_dn = &last_cert.m_subject_dn;
            let noc_subject_key_id = &last_cert.m_subject_key_id;

            // find_valid_cert() checks the certificate set constructed by loading noc, icac and rcac.
            // It confirms that the certs link correctly (noc -> icac -> rcac), and have been correctly signed.
            let result_cert = certificates.find_valid_cert(noc_subject_dn, noc_subject_key_id, context, 0)?;

            let (out_node_id, out_fabric_id) = extract_node_id_fabric_id_from_op_cert(last_cert)?;

            if is_icac_present {
                match extract_fabric_id_from_cert(
                    certificates.get_cert_sets()[1].as_ref().ok_or(chip_error_internal!())?
                    ) {
                    Ok(icac_fabric_id) => {
                        verify_or_return_error!(icac_fabric_id == out_fabric_id, Err(chip_error_fabric_mismatch_on_ica!()));
                    },
                    Err(e) => {
                        // FabricId is optional field in ICAC and "not found" code is not treated as error.
                        if e == chip_error_not_found!() {
                            // do nothing
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

            match extract_fabric_id_from_cert(
                certificates.get_cert_sets()[0].as_ref().ok_or(chip_error_internal!())?
                ) {
                Ok(rcac_fabric_id) => {
                    verify_or_return_error!(rcac_fabric_id == out_fabric_id, Err(chip_error_wrong_cert_dn!()));
                },
                Err(e) => {
                    // FabricId is optional field in ICAC and "not found" code is not treated as error.
                    if e == chip_error_not_found!() {
                        // do nothing
                    } else {
                        return Err(e);
                    }
                }
            }

            let out_compressed_fabric_id: u64;
            let root_pub_key: P256PublicKey;
            // Extract compressed fabric ID and root public key
            {
                root_pub_key = P256PublicKey::default_with_raw_value(
                    &certificates.get_cert_sets()[0].as_ref().ok_or(chip_error_internal!())?.m_public_key);

                out_compressed_fabric_id = generate_compressed_fabric_id(&root_pub_key, out_fabric_id)?;
            }

            let noc_pub_key = P256PublicKey::default_with_raw_value(
                &certificates.get_cert_sets()[2].as_ref().ok_or(chip_error_internal!())?.m_public_key);


            return Ok((out_compressed_fabric_id, out_fabric_id, out_node_id, noc_pub_key, root_pub_key));
        }

        pub fn permit_colliding_fabrics(&mut self) {
            self.m_state_flag
                .insert(StateFlags::KareCollidingFabricsIgnored);
        }

        pub fn add_new_fabric_for_test(
            &mut self,
            _root_cert: &[u8],
            _icac_cert: &[u8],
            _noc_cert: &[u8],
            _ok_key: &[u8],
        ) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_uncommited_fabric_for_test(
            &mut self,
            _root_cert: &[u8],
            _icac_cert: &[u8],
            _noc_cert: &[u8],
            _ok_key: &[u8],
        ) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_fabric_for_test_ignoring_collisions(
            &mut self,
            root_cert: &[u8],
            icac_cert: &[u8],
            noc_cert: &[u8],
            ok_key: &[u8],
        ) -> Result<FabricIndex, ChipError> {
            self.permit_colliding_fabrics();
            self.m_state_flag
                .remove(StateFlags::KareCollidingFabricsIgnored);
            return self.add_new_fabric_for_test(root_cert, icac_cert, noc_cert, ok_key);
        }

        pub fn set_force_abort_commit_for_test(&mut self, abort_commit_for_test: bool) {
            if abort_commit_for_test {
                self.m_state_flag.insert(StateFlags::KabortCommitForTest);
            } else {
                self.m_state_flag.remove(StateFlags::KabortCommitForTest);
            }
        }

        pub fn peek_fabric_index_for_next_addition(&self) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn set_fabric_index_for_next_addition(
            &mut self,
            _fabric_index: FabricIndex,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn sign_vid_verification_request(
            &self,
            _fabric_index: FabricIndex,
            _client_challenge: &[u8],
            _attestation_challenge: &[u8],
            out_response: &mut SignVidVerificationResponseData,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn set_vid_verification_statement_elements(
            &self,
            _fabric_index: FabricIndex,
            _vendor_id: Option<u16>,
            _vid_verification_statement: Option<&[u8]>,
            _vvsc: Option<&[u8]>,
        ) -> Result<bool, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn get_mutable_fabric_by_index(
            &mut self,
            fabric_index: FabricIndex,
        ) -> Option<&mut FabricInfo> {
            if fabric_index == KUNDEFINED_FABRIC_INDEX {
                return None;
            }

            if self.has_pending_fabric_update()
                && (self.m_pending_fabric.get_fabric_index() == fabric_index)
            {
                return Some(&mut self.m_pending_fabric);
            }

            for fabric in &mut self.m_states {
                if !fabric.is_initialized() {
                    continue;
                }

                if fabric.get_fabric_index() == fabric_index {
                    return Some(fabric);
                }
            }

            return None;
        }

        fn store_fabric_metadata(&self, fabric_info: &FabricInfo) -> ChipErrorResult {
            verify_or_return_error!(
                !self.m_storage.is_null(),
                Err(chip_error_incorrect_state!())
            );

            let fabric_index = fabric_info.get_fabric_index();
            verify_or_return_error!(
                is_valid_fabric_index(fabric_index),
                Err(chip_error_internal!())
            );

            unsafe {
                fabric_info.commit_to_storge(self.m_storage.as_mut().unwrap())?;
            }

            chip_log_progress!(
                FabricProvisioning,
                "Metadata for fabric {:#x} persisted to storage.",
                fabric_index as u32
            );

            chip_ok!()
        }

        fn set_pending_data_fabric_index(&mut self, fabric_index: FabricIndex) -> bool {
            let is_legal = (self.m_fabric_index_with_pending_state == KUNDEFINED_FABRIC_INDEX)
                || (self.m_fabric_index_with_pending_state == fabric_index);

            if is_legal {
                self.m_fabric_index_with_pending_state = fabric_index;
            }

            is_legal
        }

        fn get_pending_new_fabric_index(&self) -> FabricIndex {
            if self.m_state_flag.contains(StateFlags::KisAddPending) {
                return self.m_fabric_index_with_pending_state;
            }

            KUNDEFINED_FABRIC_INDEX
        }

        fn add_or_update_inner(
            &mut self,
            _fabric_index: FabricIndex,
            _is_addition: bool,
            _existing_op_key: &P256Keypair,
            _is_existingg_op_key_externally_owned: bool,
            _vendor_id: u16,
            _advertise_identity: AdvertiseIdentity,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn add_new_pending_fabric_common(
            &mut self,
            _noc: &[u8],
            _icac: &[u8],
            _vendor_id: u16,
            _existeding_op_key: &P256Keypair,
            _is_existing_op_key_externally_owned: bool,
            _advertise_identity: AdvertiseIdentity,
        ) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn update_pending_fabric_common(
            &mut self,
            _noc: &[u8],
            _icac: &[u8],
            _existeding_op_key: &P256Keypair,
            _is_existing_op_key_externally_owned: bool,
            _advertise_identity: AdvertiseIdentity,
        ) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn find_fabric_common_with_id(
            &self,
            root_pub_key: &P256PublicKey,
            fabric_id: FabricId,
            node_id: Option<NodeId>,
        ) -> Option<&FabricInfo> {
            // Try to match pending fabric first if available
            if self.has_pending_fabric_update() {
                let candidate_pub_key = self.m_pending_fabric.fetch_root_pubkey();
                let matching_node_id = if let Some(id) = node_id {
                    id
                } else {
                    self.m_pending_fabric.get_node_id()
                };

                if candidate_pub_key
                    .as_ref()
                    .is_ok_and(|key| root_pub_key.matches(key))
                    && fabric_id == self.m_pending_fabric.get_fabric_id()
                    && matching_node_id == self.m_pending_fabric.get_node_id()
                {
                    return Some(&self.m_pending_fabric);
                }
            }

            for fabric in &self.m_states {
                let matching_node_id = if let Some(id) = node_id {
                    id
                } else {
                    fabric.get_node_id()
                };

                if !fabric.is_initialized() {
                    continue;
                }

                if let Ok(key) = fabric.fetch_root_pubkey() {
                    if root_pub_key.matches(&key)
                        && fabric_id == fabric.get_fabric_id()
                        && matching_node_id == fabric.get_node_id()
                    {
                        return Some(fabric);
                    }
                }
            }

            None
        }

        fn find_fabric_common(
            &self,
            root_pub_key: &P256PublicKey,
            fabric_id: FabricId,
        ) -> Option<&FabricInfo> {
            return self.find_fabric_common_with_id(root_pub_key, fabric_id, None);
        }

        fn update_next_available_fabric_index(&mut self) {
            if self.m_next_available_fabric_index.is_none() {
                return;
            }

            let mut candidate =
                next_fabric_index(self.m_next_available_fabric_index.clone().unwrap());

            while self
                .m_next_available_fabric_index
                .is_some_and(|index| index != candidate)
            {
                if self.find_fabric_with_index(candidate).is_none() {
                    self.m_next_available_fabric_index = Some(candidate);
                    return;
                }
                candidate = next_fabric_index(candidate);
            }
            self.m_next_available_fabric_index = None;
        }

        fn ensure_next_available_fabric_index_updated(&mut self) {
            if self.m_next_available_fabric_index.is_none()
                && self.m_fabric_count < KMAX_VALID_FABRIC_INDEX
            {
                // We must have a fabric index available here. This situation could
                // happen if we fail to store fabric index info when deleting a
                // fabric.
                self.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);
                if self
                    .find_fabric_with_index(KMIN_VALID_FABRIC_INDEX)
                    .is_some()
                {
                    self.update_next_available_fabric_index();
                }
            }
        }

        fn store_fabric_index_info(&mut self) -> ChipErrorResult {
            const SIZE: usize = index_info_tlv_max_size();
            let mut buf: [u8; SIZE] = [0; SIZE];

            let mut writer = TlvContiguousBufferWriter::default();
            writer.init(buf.as_mut_ptr(), buf.len() as u32);
            let mut outer_type = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut outer_type)?;

            if let Some(index) = self.m_next_available_fabric_index {
                writer.put_u8(next_available_fabric_index_tag(), index);
            } else {
                writer.put_null(next_available_fabric_index_tag());
            }

            let mut inner_container_type = TlvType::KtlvTypeNotSpecified;
            writer.start_container(
                fabric_indices_tag(),
                TlvType::KtlvTypeArray,
                &mut inner_container_type,
            )?;

            for f in &*self {
                writer.put_u8(anonymous_tag(), f.get_fabric_index());
            }

            writer.end_container(inner_container_type)?;
            writer.end_container(outer_type)?;

            let index_info_length = u16::try_from(writer.get_length_written())
                .map_err(|_| chip_error_buffer_too_small!())?;

            unsafe {
                self.m_storage.as_mut().unwrap().sync_set_key_value(
                    DefaultStorageKeyAllocator::fabric_index_info().key_name_str(),
                    &buf[0..index_info_length as usize],
                );
            }

            chip_ok!()
        }

        fn delete_metadata_from_storage(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
            verify_or_return_value!(
                is_valid_fabric_index(fabric_index),
                Err(chip_error_invalid_fabric_index!())
            );
            verify_or_return_value!(
                !self.m_storage.is_null(),
                Err(chip_error_incorrect_state!())
            );
            unsafe {
                match self.m_storage.as_mut().unwrap().sync_delete_key_value(
                    DefaultStorageKeyAllocator::fabric_metadata(fabric_index).key_name_str(),
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        let not_found = chip_error_persisted_storage_value_not_found!();
                        if e == not_found {
                            chip_log_error!(
                                FabricProvisioning,
                                "Warning: metadata not found during delete of fabric {:#x}",
                                fabric_index
                            );
                        } else {
                            chip_log_error!(
                                FabricProvisioning,
                                "Error deleting metadata for fabric fabric {:#x}: {}",
                                fabric_index,
                                e
                            );
                        }
                    }
                }
            }
            chip_ok!()
        }

        fn find_existing_fabric_by_noc_chaining(
            &self,
            pending_fabric_index: FabricIndex,
            noc: &[u8],
        ) -> Result<Option<FabricIndex>, ChipError> {
            matter_trace_scope!("FindExistingFabricByNocChaining", "Fabric");
            // Check whether we already have a matching fabric from a cert chain perspective.
            // To do so we have to extract the FabricID from the NOC and the root public key from the RCAC.
            // We assume the RCAC is currently readable from OperationalCertificateStore, whether pending
            // or persisted.
            let mut fabric_id = 0;
            {
                let mut unused: NodeId = 0;
                (unused, fabric_id) = extract_node_id_fabric_id_from_op_cert_byte(noc)?;
            }

            let mut candidate_root_key = P256PublicKey::default();
            {
                let mut temp_rcac = CertBuffer::default();
                self.fetch_root_cert(pending_fabric_index, &mut temp_rcac)?;
                candidate_root_key =
                    extract_public_key_from_chip_cert_byte(temp_rcac.const_bytes())?;
            }

            for existing_fabric in &*self {
                if existing_fabric.get_fabric_id() == fabric_id {
                    let existing_root_key =
                        self.fetch_root_pubkey(existing_fabric.get_fabric_index())?;

                    if existing_root_key.matches(&candidate_root_key) {
                        return Ok(Some(existing_fabric.get_fabric_index()));
                    }
                }
            }

            Ok(None)
        }

        fn get_shadow_pending_fabric_entry(&self) -> Option<&FabricInfo> {
            if self.has_pending_fabric_update() {
                Some(&self.m_pending_fabric)
            } else {
                None
            }
        }

        fn has_pending_fabric_update(&self) -> bool {
            return self.m_pending_fabric.is_initialized()
                && self.m_state_flag.contains(
                    StateFlags::KisPendingFabricDataPresent | StateFlags::KisUpdatePending,
                );
        }

        fn validate_incoming_noc_chain<Policy: CertificateValidityPolicy>(
            _noc: &[u8],
            _icac: &[u8],
            _rcac: &[u8],
            existing_fabric_id: FabricId,
            _policy: &Policy,
        ) -> Result<
            (
                CompressedFabricId,
                FabricId,
                NodeId,
                P256PublicKey,
                P256PublicKey,
            ),
            ChipError,
        > {
            Err(chip_error_not_implemented!())
        }

        fn notify_fabric_updated(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn notify_fabric_commited(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn store_commit_marker(&mut self, commit_marker: &CommitMarker) -> ChipErrorResult {
            const SIZE: usize = commit_marker_context_tlv_max_size();
            let mut raw_tlv: [u8; SIZE] = [0; SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut outer_container = TlvType::KtlvTypeNotSpecified;

            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                TlvType::KtlvTypeStructure,
                &mut outer_container,
            )?;

            writer.put_u8(marker_fabric_index_tag(), commit_marker.fabric_index as u8)?;

            writer.put_boolean(marker_is_addition_tag(), commit_marker.is_addition)?;

            // end of struct conatiner
            writer.end_container(outer_container)?;

            match u16::try_from(writer.get_length_written()) {
                Ok(size) => unsafe {
                    return self.m_storage.as_mut().unwrap().sync_set_key_value(
                        DefaultStorageKeyAllocator::fabric_table_commit_marker_key().key_name_str(),
                        &raw_tlv[..size as usize],
                    );
                },
                Err(e) => {
                    return Err(chip_error_buffer_too_small!());
                }
            }
        }

        fn get_commit_marker(&self) -> Result<CommitMarker, ChipError> {
            const TLV_SIZE: usize = commit_marker_context_tlv_max_size();
            let mut tlv_buf: [u8; TLV_SIZE] = [0; TLV_SIZE];

            let mut out_commit_marker = CommitMarker::default();

            let mut tlv_read_size = 0usize;
            unsafe {
                tlv_read_size = self.m_storage.as_mut().unwrap().sync_get_key_value(
                    DefaultStorageKeyAllocator::fabric_table_commit_marker_key().key_name_str(),
                    &mut tlv_buf,
                )?;
            }

            let mut reader = TlvContiguousBufferReader::default();
            reader.init(tlv_buf.as_ptr(), tlv_read_size);

            reader.next_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
            let container_type = reader.enter_container()?;

            reader.next_tag(marker_fabric_index_tag())?;
            out_commit_marker.fabric_index = FabricIndex::from(reader.get_u8()?);

            reader.next_tag(marker_is_addition_tag())?;
            out_commit_marker.is_addition = reader.get_boolean()?;

            // Don't try to exit container: we got all we needed. This allows us to
            // avoid erroring-out on newer versions.

            Ok(out_commit_marker)
        }
    }

    impl<PSD, OK, OCS> Default for FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        fn default() -> Self {
            fabric_table_const_default::<PSD, OK, OCS>()
        }
    }

    pub struct FabricIterator<'a> {
        m_next: core::slice::Iter<'a, FabricInfo>,
        m_pending: Option<&'a FabricInfo>,
    }

    impl<'a, PSD, OK, OCS> IntoIterator for &'a FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        type Item = &'a FabricInfo;
        type IntoIter = FabricIterator<'a>;

        fn into_iter(self) -> Self::IntoIter {
            let pending = if self.has_pending_fabric_update() {
                Some(&self.m_pending_fabric)
            } else {
                None
            };
            FabricIterator {
                m_next: self.m_states.iter(),
                m_pending: pending,
            }
        }
    }

    impl<'a> Iterator for FabricIterator<'a> {
        type Item = &'a FabricInfo;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(info) = self.m_next.next() {
                // check if this info is shadowed first
                if self
                    .m_pending
                    .as_ref()
                    .is_some_and(|pending| pending.get_fabric_index() == info.get_fabric_index())
                {
                    return self.m_pending.take();
                }

                if info.is_initialized() {
                    Some(info)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    pub struct FabricIteratorMut<'a> {
        m_next: core::slice::IterMut<'a, FabricInfo>,
        m_pending: Option<&'a mut FabricInfo>,
    }

    impl<'a, PSD, OK, OCS> IntoIterator for &'a mut FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        type Item = &'a mut FabricInfo;
        type IntoIter = FabricIteratorMut<'a>;

        fn into_iter(self) -> Self::IntoIter {
            let pending = if self.has_pending_fabric_update() {
                Some(&mut self.m_pending_fabric)
            } else {
                None
            };
            FabricIteratorMut {
                m_next: self.m_states.iter_mut(),
                m_pending: pending,
            }
        }
    }

    impl<'a> Iterator for FabricIteratorMut<'a> {
        type Item = &'a mut FabricInfo;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(info) = self.m_next.next() {
                // check if this info is shadowed first
                if self
                    .m_pending
                    .as_ref()
                    .is_some_and(|pending| pending.get_fabric_index() == info.get_fabric_index())
                {
                    return self.m_pending.take();
                }

                if info.is_initialized() {
                    Some(info)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::chip::{
            asn1::Oid,
            chip_lib::{
                core::{
                    case_auth_tag::CatValues,
                    chip_config::CHIP_CONFIG_MAX_FABRICS,
                    chip_encoding,
                    chip_persistent_storage_delegate::PersistentStorageDelegate,
                    data_model_types::{
                        is_valid_fabric_index, FabricIndex, KMAX_VALID_FABRIC_INDEX,
                        KMIN_VALID_FABRIC_INDEX, KUNDEFINED_COMPRESSED_FABRIC_ID,
                        KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX,
                    },
                    node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                    tlv_reader::{MockTlvReader, TlvContiguousBufferReader, TlvReader},
                    tlv_tags::{self, anonymous_tag},
                    tlv_types::TlvType,
                    tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                },
                support::{
                    default_storage_key_allocator::DefaultStorageKeyAllocator,
                    default_string::DefaultString, test_persistent_storage::TestPersistentStorage,
                },
            },
            credentials::{
                self,
                certificate_validity_policy::{CertificateValidityPolicy, IgnoreCertificateValidityPeriodPolicy},
                chip_cert::{
                    extract_node_id_fabric_id_from_op_cert_byte, ChipDN, CertType,
                    extract_public_key_from_chip_cert_byte, CertBuffer, K_MAX_CHIP_CERT_LENGTH,
                    tests::make_subject_key_id,
                },
                chip_certificate_set::{ValidationContext, tests::make_x509_cert_chain_3, EffectiveTime},
                fabric_table::{
                    fabric_info::{self, tests::*},
                    fabric_table::{
                        commit_marker_context_tlv_max_size, fabric_indices_tag,
                        index_info_tlv_max_size, marker_fabric_index_tag, marker_is_addition_tag,
                        next_available_fabric_index_tag, Delegate, FabricTable, InitParams,
                        StateFlags,
                    },
                },
                last_known_good_time::LastKnownGoodTime,
                operational_certificate_store::{
                    CertChainElement, MockOperationalCertificateStore, OperationalCertificateStore,
                },
                persistent_storage_op_cert_store::PersistentStorageOpCertStore,
            },
            crypto::{
                self,
                crypto_pal::{
                    ECPKey, ECPKeyTarget, ECPKeypair, P256EcdsaSignature, P256Keypair,
                    P256KeypairBase, P256PublicKey, P256SerializedKeypair,
                },
                generate_compressed_fabric_id,
                operational_keystore::MockOperationalKeystore,
                operational_keystore::OperationalKeystore,
                persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
                K_MIN_CSR_BUFFER_SIZE,
            },
            system::system_clock::Seconds32,
            CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
        };
        use crate::chip_core_error;
        use crate::chip_error_end_of_tlv;
        use crate::chip_error_internal;
        use crate::chip_error_invalid_fabric_index;
        use crate::chip_error_key_not_found;
        use crate::chip_error_not_found;
        use crate::chip_ok;
        use crate::chip_sdk_error;
        use crate::ChipError;
        use crate::ChipErrorResult;

        use core::ptr;
        use mockall::*;
        use static_cell::StaticCell;

        //use super::super::fabric_info::MockFabricInfo as FabricInfo;
        use super::super::fabric_info::tests as FabricInfoTest;
        use super::super::fabric_info::FabricInfo;

        type IgorePolicyValidate<'a> = ValidationContext<'a, IgnoreCertificateValidityPeriodPolicy>;

        type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
        type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;
        type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;

        type MockStorageTestFabricTable = FabricTable<
            TestPersistentStorage,
            MockOperationalKeystore,
            MockOperationalCertificateStore,
        >;

        #[derive(Default)]
        struct TestFabricTableDelegate<PSD, OK, OCS>
        where
            PSD: PersistentStorageDelegate,
            OK: crypto::OperationalKeystore,
            OCS: credentials::OperationalCertificateStore,
        {
            pub will_be_removed: FabricIndex,
            pub on_removed: FabricIndex,
            pub next: Option<*mut dyn Delegate<PSD, OK, OCS>>,
        }

        type NoMockFabricTableDelegate = TestFabricTableDelegate<TestPersistentStorage, OK, OCS>;

        impl<PSD, OK, OCS> Delegate<PSD, OK, OCS> for TestFabricTableDelegate<PSD, OK, OCS>
        where
            PSD: PersistentStorageDelegate,
            OK: crypto::OperationalKeystore,
            OCS: credentials::OperationalCertificateStore,
        {
            fn fabric_will_be_removed(
                &mut self,
                fabric_table: &FabricTable<PSD, OK, OCS>,
                fabric_index: FabricIndex,
            ) {
                self.will_be_removed = fabric_index;
            }

            fn on_fabric_removed(
                &mut self,
                fabric_table: &FabricTable<PSD, OK, OCS>,
                fabric_index: FabricIndex,
            ) {
                self.on_removed = fabric_index;
            }

            fn next(&self) -> Option<*mut dyn Delegate<PSD, OK, OCS>> {
                return self.next.clone();
            }

            fn remove_next(&mut self) {
                self.next = None;
            }

            fn set_next(&mut self, next: Option<*mut dyn Delegate<PSD, OK, OCS>>) {
                self.next = next;
            }
        }

        fn get_stub_fabric_info_with_index(fabric_index: FabricIndex) -> FabricInfo {
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_fabric_id = KUNDEFINED_FABRIC_ID + 1;
            init_pas.m_node_id = KUNDEFINED_NODE_ID + 1;

            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);

            fabric_info
        }

        fn set_up_stub_fabric(
            fabric_index: FabricIndex,
            pos: &mut OCS,
            ks: &mut OK,
            pa: *mut TestPersistentStorage,
        ) {
            const OFFSET: u8 = 50;
            // commit public key to storage
            ks.init(pa);
            let mut out_csr: [u8; 256] = [0; 256];
            let _ = ks.new_op_keypair_for_fabric(fabric_index, &mut out_csr);
            let pub_key = ks.get_pending_pub_key();
            assert!(pub_key.is_some());
            let pub_key = pub_key.unwrap();
            ks.activate_op_keypair_for_fabric(fabric_index, &pub_key);
            assert_eq!(true, ks.commit_op_keypair_for_fabric(fabric_index).is_ok());
            let mut serialized_keypair = P256SerializedKeypair::default();
            assert!(ks.export_op_keypair_for_fabric(fabric_index, &mut serialized_keypair).is_ok());
            let mut keypair = P256Keypair::default();
            assert!(keypair.deserialize(&serialized_keypair).is_ok());

            // commit fabric info to storage
            let mut info = get_stub_fabric_info_with_index(fabric_index);
            unsafe {
                assert_eq!(true, info.commit_to_storge(pa.as_mut().unwrap()).is_ok());
            }
            let mut root_keypair = P256Keypair::default();
            root_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_key_id = make_subject_key_id(1, 2);
            let mut root_subject_dn = ChipDN::default();
            root_subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterRCACId as Oid, 1 as u64);
            let empty_dn = ChipDN::default();
            let mut random_keypair = P256Keypair::default();
            random_keypair.initialize(ECPKeyTarget::Ecdh);
            let root_buffer = make_chip_cert_with_ids_and_times(&root_subject_dn, &empty_dn, root_keypair.public_key().const_bytes(),
                &root_key_id, &root_key_id, 0, 0, Some(&random_keypair), CertType::Kroot);
            assert!(root_buffer.is_ok());
            let root_buffer = root_buffer.unwrap();

            let node_key_id = make_subject_key_id(5, 6);
            let noc_keypair = stub_keypair();
            let mut subject_dn = ChipDN::default();
            assert!(subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as Oid, 1 as u64).is_ok());
            assert!(subject_dn.add_attribute(crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as Oid, 2 as u64).is_ok());

            let noc_buffer = make_chip_cert_with_ids_and_times(&subject_dn, &root_subject_dn, noc_keypair.public_key().const_bytes(),
                &node_key_id, &root_key_id, 0, 0, Some(&root_keypair), CertType::Knode);

            assert!(noc_buffer.is_ok());
            let noc_buffer = noc_buffer.unwrap();

            pos.init(pa);
            // commit certs to storage
            assert!(pos.add_new_trusted_root_cert_for_fabric(fabric_index, root_buffer.const_bytes()).inspect_err(|e| println!("err {}", e)).is_ok());
            assert!(pos.add_new_op_certs_for_fabric(fabric_index, noc_buffer.const_bytes(), &[]).is_ok());
            assert_eq!(true, pos.commit_certs_for_fabric(fabric_index).is_ok());
        }

        fn add_commit_marker(
            pa: &mut TestPersistentStorage,
            fabric_index: FabricIndex,
            is_addition: bool,
        ) {
            const SIZE: usize = commit_marker_context_tlv_max_size();
            let mut raw_tlv: [u8; SIZE] = [0; SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut outer_container = TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            writer.put_u8(marker_fabric_index_tag(), fabric_index as u8);

            writer.put_boolean(marker_is_addition_tag(), is_addition);

            // end of struct conatiner
            writer.end_container(outer_container);

            assert_eq!(
                true,
                pa.sync_set_key_value(
                    DefaultStorageKeyAllocator::fabric_table_commit_marker_key().key_name_str(),
                    &raw_tlv[..writer.get_length_written()]
                )
                .is_ok()
            );
        }

        fn add_fabric_index_info(
            pa: &mut TestPersistentStorage,
            next_index: Option<FabricIndex>,
            indices: &[FabricIndex],
        ) {
            const SIZE: usize = index_info_tlv_max_size();
            let mut raw_tlv: [u8; SIZE] = [0; SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);

            let mut outer_container = TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(
                tlv_tags::anonymous_tag(),
                TlvType::KtlvTypeStructure,
                &mut outer_container,
            );

            if let Some(next_index) = next_index {
                // put next available fabric index
                writer.put_u8(next_available_fabric_index_tag(), next_index);
            } else {
                writer.put_null(next_available_fabric_index_tag());
            }

            let mut outer_container_indices_array = TlvType::KtlvTypeNotSpecified;

            // start a index array
            writer
                .start_container(
                    fabric_indices_tag(),
                    TlvType::KtlvTypeArray,
                    &mut outer_container_indices_array,
                )
                .inspect_err(|e| println!("{:?}", e));

            for i in indices {
                // put a fabric index
                writer.put_u8(anonymous_tag(), *i);
            }

            // end of array conatiner
            writer.end_container(outer_container_indices_array);

            // end of struct conatiner
            writer.end_container(outer_container);

            assert_eq!(
                true,
                pa.sync_set_key_value(
                    DefaultStorageKeyAllocator::fabric_index_info().key_name_str(),
                    &raw_tlv[..writer.get_length_written()]
                )
                .is_ok()
            );
        }

        pub fn create_table_with_param<PSD, OK, OCS>(
            pa: *mut PSD,
            ks: *mut OK,
            pos: *mut OCS,
        ) -> FabricTable<PSD, OK, OCS>
        where
            PSD: PersistentStorageDelegate,
            OK: crypto::OperationalKeystore,
            OCS: credentials::OperationalCertificateStore,
        {
            // init the table with all the stroages
            let mut init_params = InitParams::<PSD, OK, OCS>::default();
            init_params.storage = pa;
            init_params.operational_keystore = ks;
            init_params.op_certs_store = pos;

            let mut table = FabricTable::<PSD, OK, OCS>::default();

            assert_eq!(true, table.init(&init_params).is_ok());

            return table;
        }

        pub fn add_stub_pending_fabric<PSD, OK, OCS>(
            table: &mut FabricTable<PSD, OK, OCS>,
            index: FabricIndex,
        ) where
            PSD: PersistentStorageDelegate,
            OK: crypto::OperationalKeystore,
            OCS: credentials::OperationalCertificateStore,
        {
            // to simulate an existed pending fabric info
            table.m_pending_fabric = get_stub_fabric_info_with_index(index);
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // set up the label to compare the result
            table.m_pending_fabric.set_fabric_label("pending");
        }

        #[test]
        fn default_init() {
            let table = TestFabricTable::default();
            assert_eq!(false, table.has_operational_key_for_fabric(0));
        }

        #[test]
        fn find_fabric_with_index_successfully() {
            let mut table = TestFabricTable::default();
            assert_eq!(
                true,
                table
                    .find_fabric_with_index(KUNDEFINED_FABRIC_INDEX)
                    .is_none()
            );
            table.m_states[0] = get_stub_fabric_info_with_index(1);
            assert_eq!(true, table.find_fabric_with_index(1).is_some());
        }

        #[test]
        fn find_no_fabric_with_index() {
            let mut table = TestFabricTable::default();
            assert_eq!(
                true,
                table
                    .find_fabric_with_index(KUNDEFINED_FABRIC_INDEX)
                    .is_none()
            );
            assert_eq!(true, table.find_fabric_with_index(1).is_none());
        }

        #[test]
        fn update_next_available_fabric_index() {
            let mut table = TestFabricTable::default();
            table.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);

            table.update_next_available_fabric_index();
            assert_eq!(
                true,
                table
                    .m_next_available_fabric_index
                    .is_some_and(|i| i == KMIN_VALID_FABRIC_INDEX + 1)
            );
        }

        #[test]
        fn update_next_available_fabric_index_with_existed_fabric() {
            let mut table = TestFabricTable::default();
            table.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);

            table.m_states[0] = get_stub_fabric_info_with_index(2);

            table.update_next_available_fabric_index();
            assert_eq!(
                true,
                table
                    .m_next_available_fabric_index
                    .is_some_and(|i| i == KMIN_VALID_FABRIC_INDEX + 2)
            );
        }

        /*
        #[test]
        fn update_next_available_fabric_index_no_avaiable_fabric() {
          // it is too hard to make the all fabric index 0~255 not avaliable
        }
        */

        #[test]
        fn fetch_noc_cert_successfully() {
            let mut table =
                FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default(
                );
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            mock_op_cert_store
                .expect_get_certificate()
                .times(1)
                .withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX))
                        && (*element == CertChainElement::Knoc)
                        && (out_cert.len() > 0)
                })
                .return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);
            let mut buf = CertBuffer::default();

            assert_eq!(
                true,
                table
                    .fetch_noc_cert(KMIN_VALID_FABRIC_INDEX, &mut buf)
                    .is_ok()
            );
        }

        #[test]
        fn fetch_root_cert_successfully() {
            let mut table =
                FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default(
                );
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            mock_op_cert_store
                .expect_get_certificate()
                .times(1)
                .withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX))
                        && (*element == CertChainElement::Krcac)
                        && (out_cert.len() > 0)
                })
                .return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);
            let mut buf = CertBuffer::default();

            assert_eq!(
                true,
                table
                    .fetch_root_cert(KMIN_VALID_FABRIC_INDEX, &mut buf)
                    .is_ok()
            );
        }

        #[test]
        fn load_one_fabric_info_from_storage_successfully() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());

            assert_eq!(
                true,
                table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok()
            );
        }

        #[test]
        fn load_from_storage_fetch_noc_failed() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());

            // inject posion key to corrupt noc op key storage
            pa.add_posion_key(
                DefaultStorageKeyAllocator::fabric_noc(KMIN_VALID_FABRIC_INDEX).key_name_str(),
            );

            assert_eq!(
                false,
                table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok()
            );
        }

        #[test]
        fn load_from_storage_fetch_root_failed() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());

            // inject posion key to corrupt rcac op key storage
            pa.add_posion_key(
                DefaultStorageKeyAllocator::fabric_rcac(KMIN_VALID_FABRIC_INDEX).key_name_str(),
            );

            assert_eq!(
                false,
                table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok()
            );
        }

        #[test]
        fn load_from_storage_fabric_failed() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());

            // inject posion key to corrupt fabric metadata
            pa.add_posion_key(
                DefaultStorageKeyAllocator::fabric_metadata(KMIN_VALID_FABRIC_INDEX).key_name_str(),
            );

            assert_eq!(
                false,
                table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok()
            );
        }

        #[test]
        fn read_one_fabric_info_successfully() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            // the fabric_index_info is empty, so this init call won't call read_fabric_info
            assert_eq!(true, table.init(&init_params).is_ok());

            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().return_const(Ok(()));
            reader
                .expect_enter_container()
                .return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().return_const(Ok(()));

            // next avaiable fabric index
            reader
                .expect_get_type()
                .return_const(TlvType::KtlvTypeUnsignedInteger);
            let mut seq = Sequence::new();
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(2u8));

            let mut num_next: usize = 0;
            reader.expect_next().returning(move || {
                if num_next < 1 {
                    num_next += 1;
                    return Ok(());
                } else {
                    num_next += 1;
                    return Err(chip_error_end_of_tlv!());
                }
            });
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(KMIN_VALID_FABRIC_INDEX as u8));
            reader.expect_exit_container().return_const(Ok(()));
            reader.expect_verify_end_of_container().return_const(Ok(()));

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(1, table.fabric_count());
        }

        #[test]
        fn read_two_fabric_info_successfully() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );
            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX + 1,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            // the fabric_index_info is empty, so this init call won't call read_fabric_info
            assert_eq!(true, table.init(&init_params).is_ok());

            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().return_const(Ok(()));
            reader
                .expect_enter_container()
                .return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().return_const(Ok(()));

            // next avaiable fabric index
            reader
                .expect_get_type()
                .return_const(TlvType::KtlvTypeUnsignedInteger);
            let mut seq = Sequence::new();
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(3u8));

            let mut num_next: usize = 0;
            reader.expect_next().returning(move || {
                if num_next < 2 {
                    num_next += 1;
                    return Ok(());
                } else {
                    num_next += 1;
                    return Err(chip_error_end_of_tlv!());
                }
            });
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(KMIN_VALID_FABRIC_INDEX as u8));
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok((KMIN_VALID_FABRIC_INDEX + 1) as u8));
            reader.expect_exit_container().return_const(Ok(()));
            reader.expect_verify_end_of_container().return_const(Ok(()));

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(2, table.fabric_count());
        }

        #[test]
        fn read_fabric_info_load_failed() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            // the fabric_index_info is empty, so this init call won't call read_fabric_info
            assert_eq!(true, table.init(&init_params).is_ok());

            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().return_const(Ok(()));
            reader
                .expect_enter_container()
                .return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().return_const(Ok(()));

            // next avaiable fabric index
            reader
                .expect_get_type()
                .return_const(TlvType::KtlvTypeUnsignedInteger);
            let mut seq = Sequence::new();
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(2u8));

            let mut num_next: usize = 0;
            reader.expect_next().returning(move || {
                if num_next < 1 {
                    num_next += 1;
                    return Ok(());
                } else {
                    num_next += 1;
                    return Err(chip_error_end_of_tlv!());
                }
            });
            reader
                .expect_get_u8()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(KMIN_VALID_FABRIC_INDEX as u8));
            reader.expect_exit_container().return_const(Ok(()));
            reader.expect_verify_end_of_container().return_const(Ok(()));

            // inject posion key to corrupt fabric metadata
            pa.add_posion_key(
                DefaultStorageKeyAllocator::fabric_metadata(KMIN_VALID_FABRIC_INDEX).key_name_str(),
            );

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(0, table.fabric_count());
        }

        #[test]
        fn init_with_one_index_info_successfull() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            add_fabric_index_info(&mut pa, Some(2), &[KMIN_VALID_FABRIC_INDEX]);

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());
            assert_eq!(1, table.fabric_count());
        }

        #[test]
        fn init_with_two_index_info_successfull() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );
            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX + 1,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            add_fabric_index_info(
                &mut pa,
                Some(3),
                &[KMIN_VALID_FABRIC_INDEX, KMIN_VALID_FABRIC_INDEX + 1],
            );

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());
            assert_eq!(2, table.fabric_count());
        }

        #[test]
        fn init_with_one_index_info_but_deleted_by_commit_marker_successfull() {
            let mut table = TestFabricTable::default();
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            set_up_stub_fabric(
                KMIN_VALID_FABRIC_INDEX,
                &mut pos,
                &mut ks,
                ptr::addr_of_mut!(pa),
            );

            add_fabric_index_info(&mut pa, Some(2), &[KMIN_VALID_FABRIC_INDEX]);

            // add a commit marker for KMIN_VALID_FABRIC_INDEX
            add_commit_marker(&mut pa, KMIN_VALID_FABRIC_INDEX, false);

            // init the table with all the stroages
            let mut init_params = InitParams::default();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.operational_keystore = ptr::addr_of_mut!(ks);
            init_params.op_certs_store = ptr::addr_of_mut!(pos);
            assert_eq!(true, table.init(&init_params).is_ok());

            // the KMIN_VALID_FABRIC_INDEX fabric should be deleted
            assert_eq!(0, table.fabric_count());

            assert_eq!(
                KMIN_VALID_FABRIC_INDEX,
                table.m_deleted_fabric_index_from_init
            );
        }

        #[test]
        fn delete_one_fabric_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = MockOperationalKeystore::new();
            let mut pos = MockOperationalCertificateStore::new();

            // expect remove one keypair
            ks.expect_remove_op_keypair_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .return_const(Ok(()));

            // expect remove one certification
            pos.expect_remove_certs_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .return_const(Ok(()));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            // to simulate an existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_fabric_count = 1;

            assert_eq!(
                true,
                table
                    .delete(KMIN_VALID_FABRIC_INDEX)
                    .inspect_err(|e| println!("error {}", e))
                    .is_ok()
            );
            assert_eq!(0, table.fabric_count());
        }

        #[test]
        fn delete_pending_fabric_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = MockOperationalKeystore::new();
            let mut pos = MockOperationalCertificateStore::new();

            let mut seq = Sequence::new();

            // expect revert certification except root
            // called in revert_root_cert
            pos.expect_revert_pending_op_certs_except_root()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());

            // expect revert key pair
            // called in revert pending fabric
            ks.expect_revert_pending_keypair()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());
            // expect revert certification except root once again
            pos.expect_revert_pending_op_certs_except_root()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());

            // expect remove one keypair
            // called in delete regardless the above result
            ks.expect_remove_op_keypair_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Err(chip_error_invalid_fabric_index!()));
            // expect remove one certification
            pos.expect_remove_certs_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Err(chip_error_invalid_fabric_index!()));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            // to simulate an existed pending fabric info
            table.m_pending_fabric = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            assert_eq!(
                false,
                table
                    .delete(KMIN_VALID_FABRIC_INDEX)
                    .inspect_err(|e| assert_eq!(true, *e == chip_error_not_found!()))
                    .is_ok()
            );
            assert_eq!(
                KUNDEFINED_FABRIC_INDEX,
                table.m_pending_fabric.get_fabric_index()
            );
        }

        #[test]
        fn delete_pending_and_existed_fabric_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = MockOperationalKeystore::new();
            let mut pos = MockOperationalCertificateStore::new();

            let mut seq = Sequence::new();

            // expect revert certification except root
            // called in revert_root_cert
            pos.expect_revert_pending_op_certs_except_root()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());

            // expect revert key pair
            // called in revert pending fabric
            ks.expect_revert_pending_keypair()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());
            // expect revert certification except root once again
            pos.expect_revert_pending_op_certs_except_root()
                .times(1)
                .in_sequence(&mut seq)
                .return_const(());

            // expect remove one keypair
            // called in delete regardless the above result
            ks.expect_remove_op_keypair_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(()));
            // expect remove one certification
            pos.expect_remove_certs_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .in_sequence(&mut seq)
                .return_const(Ok(()));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            // to simulate an existed pending fabric info
            table.m_pending_fabric = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // to simulate an existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_fabric_count = 1;

            assert_eq!(true, table.delete(KMIN_VALID_FABRIC_INDEX).is_ok());
            assert_eq!(
                KUNDEFINED_FABRIC_INDEX,
                table.m_pending_fabric.get_fabric_index()
            );
            assert_eq!(0, table.fabric_count());
        }

        #[test]
        fn delete_no_fabric() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = MockOperationalKeystore::new();
            let mut pos = MockOperationalCertificateStore::new();

            ks.expect_remove_op_keypair_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .return_const(Err(chip_error_invalid_fabric_index!()));
            // expect remove one certification
            pos.expect_remove_certs_for_fabric()
                .withf(|index| *index == KMIN_VALID_FABRIC_INDEX)
                .times(1)
                .return_const(Err(chip_error_invalid_fabric_index!()));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            assert_eq!(
                false,
                table
                    .delete(KMIN_VALID_FABRIC_INDEX)
                    .inspect_err(|e| println!("error {}", e))
                    .is_ok()
            );
        }

        #[test]
        fn iter_one_info_table() {
            let mut table = TestFabricTable::default();

            // to simulate an existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);

            assert_eq!(
                true,
                table
                    .into_iter()
                    .next()
                    .is_some_and(|info| info.get_fabric_index() == KMIN_VALID_FABRIC_INDEX)
            );

            for info in &table {
                assert_eq!(KMIN_VALID_FABRIC_INDEX, info.get_fabric_index());
            }
        }

        #[test]
        fn iter_two_info_table() {
            let mut table = TestFabricTable::default();

            // to simulate existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_states[1] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX + 1);

            let mut iter = table.into_iter();

            assert_eq!(
                true,
                iter.next()
                    .is_some_and(|info| info.get_fabric_index() == KMIN_VALID_FABRIC_INDEX)
            );
            assert_eq!(
                true,
                iter.next()
                    .is_some_and(|info| info.get_fabric_index() == KMIN_VALID_FABRIC_INDEX + 1)
            );
        }

        #[test]
        fn iter_two_info_with_pending_shadow() {
            let mut table = TestFabricTable::default();

            // to simulate existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_states[1] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX + 1);

            // to set up a name for fabric info at 0
            table.m_states[0].set_fabric_label("should be removed");

            // to simulate an existed pending fabric info
            table.m_pending_fabric = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_pending_fabric.set_fabric_label("pending");
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            let mut iter = table.into_iter();

            assert_eq!(
                true,
                iter.next()
                    .is_some_and(|info| info.get_fabric_index() == KMIN_VALID_FABRIC_INDEX
                        && info.get_fabric_label() == Some("pending"))
            );
            assert_eq!(
                true,
                iter.next()
                    .is_some_and(|info| info.get_fabric_index() == KMIN_VALID_FABRIC_INDEX + 1)
            );
        }

        #[test]
        fn find_fabric_common_on_pending_fabric_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("pending");
            table.m_pending_fabric = fabric_info;
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // get the root public key
            let root_key = table.m_pending_fabric.fetch_root_pubkey().unwrap();

            assert_eq!(
                true,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("pending"))
            );
        }

        #[test]
        fn find_fabric_common_on_pending_fabric_wrong_node_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("pending");
            table.m_pending_fabric = fabric_info;
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // get the root public key
            let root_key = table.m_pending_fabric.fetch_root_pubkey().unwrap();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id + 1)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("pending"))
            );
        }

        #[test]
        fn find_fabric_common_on_pending_fabric_wrong_fabric_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("pending");
            table.m_pending_fabric = fabric_info;
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // get the root public key
            let root_key = table.m_pending_fabric.fetch_root_pubkey().unwrap();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id + 1,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("pending"))
            );
        }

        #[test]
        fn find_fabric_common_on_pending_fabric_wrong_pub_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("pending");
            table.m_pending_fabric = fabric_info;
            table.m_state_flag.insert(StateFlags::KisUpdatePending);
            table
                .m_state_flag
                .insert(StateFlags::KisPendingFabricDataPresent);

            // get other random public key
            let mut keypair = P256Keypair::default();
            keypair.initialize(ECPKeyTarget::Ecdh);
            let root_key = keypair.public_key().clone();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("pending"))
            );
        }

        #[test]
        fn find_fabric_common_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("at0");

            table.m_states[0] = fabric_info;

            // get the root public key
            let root_key = table.m_states[0].fetch_root_pubkey().unwrap();

            assert_eq!(
                true,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("at0"))
            );
        }

        #[test]
        fn find_fabric_common_wrong_public_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("at0");

            table.m_states[0] = fabric_info;

            // get other random public key
            let mut keypair = P256Keypair::default();
            keypair.initialize(ECPKeyTarget::Ecdh);
            let root_key = keypair.public_key().clone();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("at0"))
            );
        }

        #[test]
        fn find_fabric_common_wrong_fabric_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("at0");

            table.m_states[0] = fabric_info;

            // get the root public key
            let root_key = table.m_states[0].fetch_root_pubkey().unwrap();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id + 1,
                        Some(expected_node_id)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("at0"))
            );
        }

        #[test]
        fn find_fabric_common_wrong_node_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("at0");

            table.m_states[0] = fabric_info;

            // get the root public key
            let root_key = table.m_states[0].fetch_root_pubkey().unwrap();

            assert_eq!(
                false,
                table
                    .find_fabric_common_with_id(
                        &root_key,
                        expected_fabric_id,
                        Some(expected_node_id + 1)
                    )
                    .is_some_and(|info| info.get_fabric_label() == Some("at0"))
            );
        }

        #[test]
        fn find_fabric_common_no_node_id_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let expected_fabric_id: FabricId = 10u64;
            let expected_node_id: NodeId = 11u64;

            // create and insert the pending fabric
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = KMIN_VALID_FABRIC_INDEX;
            init_pas.m_fabric_id = expected_fabric_id;
            init_pas.m_node_id = expected_node_id;
            let mut fabric_info = FabricInfo::default();
            fabric_info.init(&init_pas);
            fabric_info.set_fabric_label("at0");

            table.m_states[0] = fabric_info;

            // get the root public key
            let root_key = table.m_states[0].fetch_root_pubkey().unwrap();

            assert_eq!(
                true,
                table
                    .find_fabric_common_with_id(&root_key, expected_fabric_id, None)
                    .is_some_and(|info| info.get_fabric_label() == Some("at0"))
            );
        }

        #[test]
        fn add_one_delegate_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut d = NoMockFabricTableDelegate::default();

            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d)))
                    .is_ok()
            );
            table.delete(KMIN_VALID_FABRIC_INDEX + 10);
            assert_eq!(d.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
        }

        #[test]
        fn add_two_delegate_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut d = NoMockFabricTableDelegate::default();

            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d)))
                    .is_ok()
            );

            let mut d2 = NoMockFabricTableDelegate::default();

            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d2)))
                    .is_ok()
            );
            table.delete(KMIN_VALID_FABRIC_INDEX + 10);
            assert_eq!(d.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
            assert_eq!(d2.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
        }

        #[test]
        fn add_and_delete_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut d = NoMockFabricTableDelegate::default();

            // add
            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d)))
                    .is_ok()
            );
            // delete
            table.remove_fabric_delegate(Some(ptr::addr_of_mut!(d)));

            table.delete(KMIN_VALID_FABRIC_INDEX + 10);

            assert_ne!(d.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
        }

        #[test]
        fn add_three_and_delete_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut d = NoMockFabricTableDelegate::default();
            let mut d2 = NoMockFabricTableDelegate::default();
            let mut d3 = NoMockFabricTableDelegate::default();

            // add
            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d)))
                    .is_ok()
            );
            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d2)))
                    .is_ok()
            );
            assert_eq!(
                true,
                table
                    .add_fabric_delegate(Some(ptr::addr_of_mut!(d3)))
                    .is_ok()
            );
            // delete
            table.remove_fabric_delegate(Some(ptr::addr_of_mut!(d2)));

            table.delete(KMIN_VALID_FABRIC_INDEX + 10);

            assert_eq!(d.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
            assert_ne!(d2.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
            assert_eq!(d3.will_be_removed, KMIN_VALID_FABRIC_INDEX + 10);
        }

        #[test]
        fn set_fabric_label_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            // to simulate an existed fabric info
            table.m_states[0] = get_stub_fabric_info_with_index(KMIN_VALID_FABRIC_INDEX);
            table.m_fabric_count = 1;

            assert_eq!(
                true,
                table
                    .set_fabric_label(KMIN_VALID_FABRIC_INDEX, "at0")
                    .is_ok()
            );
        }

        #[test]
        fn set_fabric_label_to_not_init_one() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            assert_eq!(
                false,
                table
                    .set_fabric_label(KMIN_VALID_FABRIC_INDEX, "at0")
                    .is_ok()
            );
        }

        #[test]
        fn set_last_known_good_time_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let OFFSET = 50;

            // commit public key to storage
            ks.init(ptr::addr_of_mut!(pa));
            let mut out_csr: [u8; 256] = [0; 256];
            let _ = ks.new_op_keypair_for_fabric(fabric_index, &mut out_csr);
            let pub_key = ks.get_pending_pub_key();
            assert!(pub_key.is_some());
            let pub_key = pub_key.unwrap();
            ks.activate_op_keypair_for_fabric(fabric_index, &pub_key);
            assert_eq!(true, ks.commit_op_keypair_for_fabric(fabric_index).is_ok());

            // commit certs to storage
            pos.init(ptr::addr_of_mut!(pa));
            let rcac = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 1) as u64,
                pub_key.const_bytes(),
                None,
            )
            .unwrap();
            let icac = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET + 1) as u64,
                (fabric_index + OFFSET + 1) as u64,
                pub_key.const_bytes(),
                None,
            )
            .unwrap();
            let noc = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET + 2) as u64,
                (fabric_index + OFFSET + 3) as u64,
                pub_key.const_bytes(),
                None,
            )
            .unwrap();
            pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes());
            pos.add_new_op_certs_for_fabric(fabric_index, noc.const_bytes(), icac.const_bytes());
            assert_eq!(true, pos.commit_certs_for_fabric(fabric_index).is_ok());

            // all the not before is 0
            assert_eq!(
                true,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(1))
                    .is_ok()
            );
        }

        #[test]
        fn set_last_known_good_time_not_before_rcac_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let OFFSET = 50;

            // commit public key to storage
            ks.init(ptr::addr_of_mut!(pa));
            let mut out_csr: [u8; 256] = [0; 256];
            let _ = ks.new_op_keypair_for_fabric(fabric_index, &mut out_csr);
            let pub_key = ks.get_pending_pub_key();
            assert!(pub_key.is_some());
            let pub_key = pub_key.unwrap();
            ks.activate_op_keypair_for_fabric(fabric_index, &pub_key);
            assert_eq!(true, ks.commit_op_keypair_for_fabric(fabric_index).is_ok());
            let mut key_pair_buffer = crypto::P256SerializedKeypair::default();
            assert!(ks.export_op_keypair_for_fabric(fabric_index, &mut key_pair_buffer).is_ok());
            let mut key_pair = P256Keypair::default();
            assert!(key_pair.deserialize(&key_pair_buffer).is_ok());

            // commit certs to storage
            pos.init(ptr::addr_of_mut!(pa));
            let rcac = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(1),
                Seconds32::from_secs(0),
                Some(&key_pair),
            )
            .unwrap();
            let icac = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET + 1) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Some(&key_pair),
            )
            .unwrap();
            let noc = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET + 3) as u64,
                (fabric_index + OFFSET + 4) as u64,
                pub_key.const_bytes(),
                Some(&key_pair),
            )
            .unwrap();
            pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes());
            pos.add_new_op_certs_for_fabric(fabric_index, noc.const_bytes(), icac.const_bytes());
            assert_eq!(true, pos.commit_certs_for_fabric(fabric_index).is_ok());

            // to initialize the fabric
            table.m_states[0] = get_stub_fabric_info_with_index(fabric_index);

            // all the not before is 0
            assert_eq!(
                false,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(0))
                    .is_ok()
            );
            assert_eq!(
                true,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(1))
                    .inspect_err(|e| println!("{}", e))
                    .is_ok()
            );
        }

        #[test]
        fn set_last_known_good_time_not_before_icac_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let OFFSET = 50;

            // commit public key to storage
            ks.init(ptr::addr_of_mut!(pa));
            let mut out_csr: [u8; 256] = [0; 256];
            let _ = ks.new_op_keypair_for_fabric(fabric_index, &mut out_csr);
            let pub_key = ks.get_pending_pub_key();
            assert!(pub_key.is_some());
            let pub_key = pub_key.unwrap();
            ks.activate_op_keypair_for_fabric(fabric_index, &pub_key);
            assert_eq!(true, ks.commit_op_keypair_for_fabric(fabric_index).is_ok());

            // commit certs to storage
            pos.init(ptr::addr_of_mut!(pa));
            let rcac = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(1),
                Seconds32::from_secs(0),
                None,
            )
            .unwrap();
            let icac = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(2),
                Seconds32::from_secs(0),
                None,
            )
            .unwrap();
            let noc = FabricInfoTest::make_chip_cert(
                (fabric_index + OFFSET + 3) as u64,
                (fabric_index + OFFSET + 4) as u64,
                pub_key.const_bytes(),
                None,
            )
            .unwrap();
            pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes());
            pos.add_new_op_certs_for_fabric(fabric_index, noc.const_bytes(), icac.const_bytes());
            assert_eq!(true, pos.commit_certs_for_fabric(fabric_index).is_ok());

            // to initialize the fabric
            table.m_states[0] = get_stub_fabric_info_with_index(fabric_index);

            // all the not before is 0
            assert_eq!(
                false,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(1))
                    .is_ok()
            );
            assert_eq!(
                true,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(2))
                    .is_ok()
            );
        }

        #[test]
        fn set_last_known_good_time_not_before_noc_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let OFFSET = 50;

            // commit public key to storage
            ks.init(ptr::addr_of_mut!(pa));
            let mut out_csr: [u8; 256] = [0; 256];
            let _ = ks.new_op_keypair_for_fabric(fabric_index, &mut out_csr);
            let pub_key = ks.get_pending_pub_key();
            assert!(pub_key.is_some());
            let pub_key = pub_key.unwrap();
            ks.activate_op_keypair_for_fabric(fabric_index, &pub_key);
            assert_eq!(true, ks.commit_op_keypair_for_fabric(fabric_index).is_ok());

            // commit certs to storage
            pos.init(ptr::addr_of_mut!(pa));
            let rcac = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(1),
                Seconds32::from_secs(0),
                None,
            )
            .unwrap();
            let icac = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(2),
                Seconds32::from_secs(0),
                None,
            )
            .unwrap();
            let noc = FabricInfoTest::make_chip_cert_with_time(
                (fabric_index + OFFSET) as u64,
                (fabric_index + OFFSET + 2) as u64,
                pub_key.const_bytes(),
                Seconds32::from_secs(3),
                Seconds32::from_secs(0),
                None,
            )
            .unwrap();
            pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes());
            pos.add_new_op_certs_for_fabric(fabric_index, noc.const_bytes(), icac.const_bytes());
            assert_eq!(true, pos.commit_certs_for_fabric(fabric_index).is_ok());

            // to initialize the fabric
            table.m_states[0] = get_stub_fabric_info_with_index(fabric_index);

            // all the not before is 0
            assert_eq!(
                false,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(2))
                    .is_ok()
            );
            assert_eq!(
                true,
                table
                    .set_last_known_good_chip_epoch_time(Seconds32::from_secs(3))
                    .is_ok()
            );
        }

        #[test]
        fn has_op_key_for_fabric_true() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_fabric_id = KUNDEFINED_FABRIC_ID + 1;
            init_pas.m_node_id = KUNDEFINED_NODE_ID + 1;
            // create an op key
            let mut keypair = P256Keypair::default();
            keypair.initialize(ECPKeyTarget::Ecdh);
            init_pas.m_operation_key = ptr::addr_of_mut!(keypair);
            init_pas.m_has_externally_owned_operation_key = true;

            // to initialize the fabric with op key
            table.m_states[0].init(&init_pas);

            assert_eq!(true, table.has_operational_key_for_fabric(fabric_index));
        }

        #[test]
        fn has_op_key_for_fabric_from_storage() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // to initialize the fabric without op key
            table.m_states[0] = get_stub_fabric_info_with_index(fabric_index);
            // commit op key to storage
            set_up_stub_fabric(fabric_index, &mut pos, &mut ks, ptr::addr_of_mut!(pa));

            assert_eq!(true, table.has_operational_key_for_fabric(fabric_index));
        }

        #[test]
        fn has_op_key_false() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            assert_eq!(false, table.has_operational_key_for_fabric(fabric_index));
        }

        #[test]
        fn has_op_key_fabric_no_op_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // to initialize the fabric without op key
            table.m_states[0] = get_stub_fabric_info_with_index(fabric_index);

            assert_eq!(false, table.has_operational_key_for_fabric(fabric_index));
        }

        #[test]
        fn sign_with_op_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_fabric_id = KUNDEFINED_FABRIC_ID + 1;
            init_pas.m_node_id = KUNDEFINED_NODE_ID + 1;
            // create an op key
            let mut keypair = P256Keypair::default();
            keypair.initialize(ECPKeyTarget::Ecdh);
            init_pas.m_operation_key = ptr::addr_of_mut!(keypair);
            init_pas.m_has_externally_owned_operation_key = true;

            // to initialize the fabric with op key
            table.m_states[0].init(&init_pas);

            let mut sig = P256EcdsaSignature::default();

            assert_eq!(
                true,
                table
                    .sign_with_op_keypair(fabric_index, b"123", &mut sig)
                    .is_ok()
            );
        }

        #[test]
        fn sign_with_op_key_no_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            let mut sig = P256EcdsaSignature::default();

            assert_eq!(
                false,
                table
                    .sign_with_op_keypair(fabric_index, b"123", &mut sig)
                    .is_ok()
            );
        }

        #[test]
        fn allocate_pending_op_key_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            ks.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut csr: [u8; K_MIN_CSR_BUFFER_SIZE] = [0; K_MIN_CSR_BUFFER_SIZE];

            assert_eq!(
                Ok(68),
                table.allocate_pending_operation_key(Some(KMIN_VALID_FABRIC_INDEX), &mut csr)
            );

            let mut has_pending_key_for_noc = false;

            assert_eq!(
                true,
                table.has_pending_operational_key(&mut has_pending_key_for_noc)
            );
            assert_eq!(true, has_pending_key_for_noc);
        }

        #[test]
        fn allocate_pending_wihtout_given_index_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            ks.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut csr: [u8; K_MIN_CSR_BUFFER_SIZE] = [0; K_MIN_CSR_BUFFER_SIZE];

            assert_eq!(Ok(68), table.allocate_pending_operation_key(None, &mut csr));

            let mut has_pending_key_for_noc = false;

            assert_eq!(
                true,
                table.has_pending_operational_key(&mut has_pending_key_for_noc)
            );
            assert_eq!(false, has_pending_key_for_noc);
        }

        #[test]
        fn allocate_pending_op_key_but_root_present() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            ks.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut csr: [u8; K_MIN_CSR_BUFFER_SIZE] = [0; K_MIN_CSR_BUFFER_SIZE];

            table.m_state_flag.insert(StateFlags::KisTrustedRootPending);

            assert_eq!(
                false,
                table
                    .allocate_pending_operation_key(Some(KMIN_VALID_FABRIC_INDEX), &mut csr)
                    .is_ok()
            );
        }

        #[test]
        fn allocate_pending_op_key_calling_twice_with_other_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            ks.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut csr: [u8; K_MIN_CSR_BUFFER_SIZE] = [0; K_MIN_CSR_BUFFER_SIZE];

            assert_eq!(
                Ok(68),
                table.allocate_pending_operation_key(Some(KMIN_VALID_FABRIC_INDEX), &mut csr)
            );

            let mut has_pending_key_for_noc = false;

            assert_eq!(
                true,
                table.has_pending_operational_key(&mut has_pending_key_for_noc)
            );
            assert_eq!(true, has_pending_key_for_noc);

            assert_eq!(
                false,
                table
                    .allocate_pending_operation_key(Some(KMIN_VALID_FABRIC_INDEX + 1), &mut csr)
                    .is_ok()
            );
        }

        #[test]
        fn allocate_pending_trust_root_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut rcac: [u8; 1] = [0];

            assert_eq!(true, table.add_new_pending_trusted_root_cert(&rcac).is_ok());
        }

        #[test]
        fn allocate_pending_trust_root_calling_twice_failed() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut rcac: [u8; 1] = [0];

            assert_eq!(true, table.add_new_pending_trusted_root_cert(&rcac).is_ok());
            assert_eq!(
                false,
                table.add_new_pending_trusted_root_cert(&rcac).is_ok()
            );
        }

        #[test]
        fn find_existing_fabric_by_noc_successfully() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let node_id: NodeId = 1;
            let fabric_id: FabricId = 2;

            // create a noc and a rcac
            let pub_key = FabricInfoTest::stub_public_key();
            let rcac =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            let noc =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            // only update rcac to storage
            assert_eq!(
                true,
                pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes())
                    .is_ok()
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // init a fabric with the same public key and node id and fabric id
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_node_id = node_id;
            init_pas.m_fabric_id = fabric_id;
            init_pas.m_root_publick_key = P256PublicKey::default_with_raw_value(&pub_key[..]);

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            table.m_states[0].init(&init_pas);

            assert_eq!(
                true,
                table
                    .find_existing_fabric_by_noc_chaining(fabric_index, noc.const_bytes())
                    .is_ok_and(|index| Some(KMIN_VALID_FABRIC_INDEX) == index)
            );
        }

        #[test]
        fn find_existing_fabric_invalid_noc() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let node_id: NodeId = 1;
            let fabric_id: FabricId = 2;

            // create a noc and a rcac
            let pub_key = FabricInfoTest::stub_public_key();
            let rcac =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            //let noc = FabricInfoTest::make_chip_cert(node_id as u64,fabric_id as u64, &pub_key[..]).unwrap();
            // only update rcac to storage
            assert_eq!(
                true,
                pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes())
                    .is_ok()
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // init a fabric with the same public key and node id and fabric id
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_node_id = node_id;
            init_pas.m_fabric_id = fabric_id;
            init_pas.m_root_publick_key = P256PublicKey::default_with_raw_value(&pub_key[..]);

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            table.m_states[0].init(&init_pas);

            // use an empty noc
            assert_eq!(
                false,
                table
                    .find_existing_fabric_by_noc_chaining(fabric_index, &[])
                    .is_ok_and(|index| Some(KMIN_VALID_FABRIC_INDEX) == index)
            );
        }

        #[test]
        fn find_existing_fabric_no_root_public_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let node_id: NodeId = 1;
            let fabric_id: FabricId = 2;

            // create a noc and a rcac
            let pub_key = FabricInfoTest::stub_public_key();
            let rcac =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            let noc =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();

            // no rcac commit

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // init a fabric with the same public key and node id and fabric id
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_node_id = node_id;
            init_pas.m_fabric_id = fabric_id;
            init_pas.m_root_publick_key = P256PublicKey::default_with_raw_value(&pub_key[..]);

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            table.m_states[0].init(&init_pas);

            assert_eq!(
                false,
                table
                    .find_existing_fabric_by_noc_chaining(fabric_index, noc.const_bytes())
                    .is_ok_and(|index| Some(KMIN_VALID_FABRIC_INDEX) == index)
            );
        }

        #[test]
        fn find_existing_fabric_mismatched_fabric_id() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let node_id: NodeId = 1;
            let fabric_id: FabricId = 2;

            // create a noc and a rcac
            let pub_key = FabricInfoTest::stub_public_key();
            let rcac =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            // use different fabric id
            let noc = FabricInfoTest::make_chip_cert(
                node_id as u64,
                (fabric_id + 1) as u64,
                &pub_key[..],
                None
            )
            .unwrap();
            // only update rcac to storage
            assert_eq!(
                true,
                pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes())
                    .is_ok()
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // init a fabric with the same public key and node id and fabric id
            let mut init_pas = fabric_info::InitParams::default();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_node_id = node_id;
            init_pas.m_fabric_id = fabric_id;
            init_pas.m_root_publick_key = P256PublicKey::default_with_raw_value(&pub_key[..]);

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            table.m_states[0].init(&init_pas);

            assert_eq!(
                false,
                table
                    .find_existing_fabric_by_noc_chaining(fabric_index, noc.const_bytes())
                    .is_ok_and(|index| Some(KMIN_VALID_FABRIC_INDEX) == index)
            );
        }

        #[test]
        fn find_existing_fabric_mismatched_pub_key() {
            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            pos.init(ptr::addr_of_mut!(pa));

            let fabric_index = KMIN_VALID_FABRIC_INDEX;
            let node_id: NodeId = 1;
            let fabric_id: FabricId = 2;

            // create a noc and a rcac
            let pub_key = FabricInfoTest::stub_public_key();
            let rcac =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            let noc =
                FabricInfoTest::make_chip_cert(node_id as u64, fabric_id as u64, &pub_key[..], None)
                    .unwrap();
            // only update rcac to storage
            assert_eq!(
                true,
                pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac.const_bytes())
                    .is_ok()
            );

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            // init a fabric with the same public key and node id and fabric id
            let mut init_pas = fabric_info::InitParams::default();
            // use another public key to init the existed fabric info
            let pub_key_2 = FabricInfoTest::stub_public_key();
            init_pas.m_fabric_index = fabric_index;
            init_pas.m_node_id = node_id;
            init_pas.m_fabric_id = fabric_id;
            init_pas.m_root_publick_key = P256PublicKey::default_with_raw_value(&pub_key_2[..]);

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            table.m_states[0].init(&init_pas);

            assert_eq!(
                false,
                table
                    .find_existing_fabric_by_noc_chaining(fabric_index, noc.const_bytes())
                    .is_ok_and(|index| Some(KMIN_VALID_FABRIC_INDEX) == index)
            );
        }

        #[test]
        fn run_verify_credentials_successfully() {
            let (rcac, icac, noc) = make_x509_cert_chain_3();
            let rcac_buf = make_chip_cert_by_data(&rcac).unwrap();
            let icac_buf = make_chip_cert_by_data(&rcac).unwrap();
            let noc_buf = make_chip_cert_by_data(&noc).unwrap();

            let mut pa = TestPersistentStorage::default();
            let mut ks = OK::default();
            let mut pos = OCS::default();

            let fabric_index = KMIN_VALID_FABRIC_INDEX;

            pos.init(ptr::addr_of_mut!(pa));

            // only update rcac to storage
            assert_eq!(
                true,
                pos.add_new_trusted_root_cert_for_fabric(fabric_index, rcac_buf.const_bytes())
                    .is_ok()
            );

            let mut table = create_table_with_param(
                ptr::addr_of_mut!(pa),
                ptr::addr_of_mut!(ks),
                ptr::addr_of_mut!(pos),
            );

            let mut context = IgorePolicyValidate::default();
            context.m_effective_time = EffectiveTime::LastKnownGoodChipEpochTime(
                Seconds32::from_secs(1),
            );

            //assert!(table.run_verify_credentials(noc_buf.const_bytes(), Some(icac_buf.const_bytes()), rcac_buf.const_bytes(), &mut context).is_ok());
        }
    } // end of mod tests
} // end of mod fabric_table
