const KFABRIC_LABEL_MAX_LENGTH_IN_BYTES: usize = 32;
pub type FabricLabelString = crate::chip::chip_lib::support::default_string::DefaultString<KFABRIC_LABEL_MAX_LENGTH_IN_BYTES>;

mod fabric_info {
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
    use crate::chip_error_internal;
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
            pub fn fetch_root_pubkey<'a>(&'a self) -> Result<&'a P256PublicKey, ChipError>;
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
                message: &mut [u8],
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
            chip_encoding::big_endian::put_u64(compressed_fabric_id, self.get_compressed_fabric_id());
            chip_ok!()
        }

        //pub fn fetch_root_pubkey(&self, out_public_key: &mut P256PublicKey) -> ChipErrorResult {
        pub fn fetch_root_pubkey<'a>(&'a self) -> Result<&'a P256PublicKey, ChipError> {
            verify_or_return_error!(self.is_initialized(), Err(chip_error_key_not_found!()));

            return Ok(&self.m_root_publick_key);
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
            self.m_root_publick_key = P256PublicKey::default_with_raw_value(init_params.m_root_publick_key.const_bytes());
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

            if self.m_has_externally_owned_operation_key == false && self.m_operation_key.is_null() == false && self.m_internal_op_key_storage.is_some() {
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
            message: &mut [u8],
            out_signature: &mut P256EcdsaSignature,
        ) -> ChipErrorResult {
            verify_or_return_error!(!self.m_operation_key.is_null(), Err(chip_error_key_not_found!()));

            unsafe {
                return self.m_operation_key.as_ref().unwrap().ecdsa_sign_msg(message, out_signature);
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
        ) -> ChipErrorResult
        {
            let mut buf: [u8; metadata_tlv_max_size()] = [0; {metadata_tlv_max_size()}];
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

            let meta_data_len = u16::try_from(writer.get_length_written()).map_err(|_| {
                chip_error_buffer_too_small!()
            })?;
            return storage.sync_set_key_value(DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(), &buf[..meta_data_len as usize]);
        }

        pub(super) fn load_from_storage<'a, Storage: PersistentStorageDelegate>(
            &'a mut self,
            storage: &'a mut Storage,
            new_fabric_index: FabricIndex,
            rcac: &'a [u8],
            noc: &'a [u8],
        ) -> ChipErrorResult {
            //verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));
            self.m_fabric_index = new_fabric_index;
            {
                (self.m_node_id, self.m_fabric_id) = extract_node_id_fabric_id_from_op_cert_byte(noc)?;
                self.m_root_publick_key = extract_public_key_from_chip_cert_byte(rcac)?;
                self.m_compressed_fabric_id = generate_compressed_fabric_id(&self.m_root_publick_key, self.m_fabric_id)?;
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
                let data_size = storage.sync_get_key_value(DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(), &mut buffer[..])?;
                let mut reader = TlvContiguousBufferReader::const_default();
                reader.init(buffer.as_ptr(), data_size);
                reader.next_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
                let container_type = reader.enter_container()?;

                reader.next_tag(vendor_id_tag())?;
                self.m_vendor_id = reader.get_u16()?.into();

                reader.next_tag(fabric_label_tag())?;
                let label = reader.get_string()?.ok_or(chip_error_internal!())?;

                verify_or_return_error!(label.len() <= KFABRIC_LABEL_MAX_LENGTH_IN_BYTES, Err(chip_error_buffer_too_small!()));
                self.m_fabric_label = FabricLabelString::from(label);

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
    mod tests {
        use super::*;
        use crate::chip::{
            credentials::{
                persistent_storage_op_cert_store::PersistentStorageOpCertStore,
                chip_cert::ChipCertTag,
            },
            crypto::{
                persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
                K_P256_PUBLIC_KEY_LENGTH,
                P256Keypair, ECPKeyTarget, ECPKeypair, P256KeypairBase,
                *,
            },
            chip_lib::{
                support::test_persistent_storage::TestPersistentStorage,
                core::{
                    tlv_types::{self, TlvType},
                    tlv_tags::{self, is_context_tag, tag_num_from_tag},
                    tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                }
            }
        };
        use core::ptr;

        type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
        type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;
        //type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;
        const CHIP_CERT_SIZE: usize = 123 + K_P256_PUBLIC_KEY_LENGTH;

        fn stub_public_key() -> [u8; K_P256_PUBLIC_KEY_LENGTH] {
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            let mut keypair = P256Keypair::default();
            let _ = keypair.initialize(ECPKeyTarget::Ecdh);
            fake_public_key.copy_from_slice(keypair.public_key().const_bytes());
            return fake_public_key;
        }

        fn make_chip_cert(matter_id_value: u64, fabric_id_value: u64, public_key: &[u8]) -> Result<[u8; CHIP_CERT_SIZE], ()> {
            let mut raw_tlv: [u8; CHIP_CERT_SIZE] = [0; CHIP_CERT_SIZE];
            let mut writer: TlvContiguousBufferWriter = TlvContiguousBufferWriter::const_default();
            writer.init(raw_tlv.as_mut_ptr(), raw_tlv.len() as u32);
            let mut outer_container = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a struct
            writer.start_container(tlv_tags::anonymous_tag(), tlv_types::TlvType::KtlvTypeStructure, &mut outer_container);

            let mut outer_container_dn_list = tlv_types::TlvType::KtlvTypeNotSpecified;
            // start a dn list
            writer.start_container(tlv_tags::context_tag(ChipCertTag::KtagSubject as u8), tlv_types::TlvType::KtlvTypeList, &mut outer_container_dn_list).inspect_err(|e| println!("{:?}", e));
            // set up a tag number from matter id
            let matter_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterNodeId as u8;
            // no print string
            let is_print_string: u8 = 0x0;
            // put a matter id 0x1
            writer.put_u64(tlv_tags::context_tag((is_print_string | matter_id)), matter_id_value);
            // set up a tag number from fabric id
            let fabric_id = crate::chip::asn1::Asn1Oid::KoidAttributeTypeMatterFabricId as u8;
            // put a fabric id 0x02
            writer.put_u64(tlv_tags::context_tag((is_print_string | fabric_id)), fabric_id_value);
            // end of list conatiner
            writer.end_container(outer_container_dn_list);

            // add to cert
            writer.put_bytes(tlv_tags::context_tag(ChipCertTag::KtagEllipticCurvePublicKey as u8), public_key).inspect_err(|e| println!("{:?}", e));

            // end struct container
            writer.end_container(outer_container);

            return Ok(raw_tlv);
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
            assert_eq!(true, pa.has_key(DefaultStorageKeyAllocator::fabric_metadata(0).key_name_str()));
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

            let pub_key = stub_public_key();
            let rcac = make_chip_cert(1,2, &pub_key[..]).unwrap();
            let noc = make_chip_cert(3,4, &pub_key[..]).unwrap();

            let mut info_out = fabric_info_const_default();
            assert_eq!(true, info_out.load_from_storage(&mut pa, 0, &rcac, &noc).inspect_err(|e| println!("{:?}", e)).is_ok());
            assert_eq!(3, info_out.m_node_id);
            assert_eq!(4, info_out.m_fabric_id);
            assert_eq!(VendorId::Common, info_out.m_vendor_id);
            assert_eq!("abc", info_out.m_fabric_label.str().unwrap_or(&""));
        }

        #[test]
        fn set_op_keypair() {
            let mut info = fabric_info_const_default();
            let keypair = P256Keypair::default();

            assert_eq!(true, info.set_operational_keypair(ptr::addr_of!(keypair)).is_ok());
            assert_eq!(true, info.m_internal_op_key_storage.is_some());
            assert_eq!(keypair.public_key().const_bytes(), info.m_internal_op_key_storage.as_ref().unwrap().public_key().const_bytes());
        }
    } // end of mod tests
} // end of mod fabric_info


mod fabric_table {
    use crate::chip::{
        CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
        system::system_clock::Seconds32,
        chip_lib::{
            core::{
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                case_auth_tag::CatValues,
                tlv_types::TlvType,
                tlv_tags::{self, anonymous_tag, context_tag, Tag},
                data_model_types::{
                    KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX, is_valid_fabric_index,
                    KMIN_VALID_FABRIC_INDEX, KMAX_VALID_FABRIC_INDEX, FabricIndex,
                },
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                chip_encoding,
                chip_config::CHIP_CONFIG_MAX_FABRICS,
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
    use crate::chip_error_invalid_fabric_index;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_not_implemented;
    use crate::chip_error_persisted_storage_value_not_found;
    use crate::chip_error_incorrect_state;
    use crate::chip_error_internal;
    use crate::chip_error_key_not_found;
    use crate::chip_error_no_memory;
    use crate::chip_error_end_of_tlv;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipErrorResult;
    use crate::ChipError;
    use crate::matter_trace_scope;
    use crate::chip_static_assert;

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use crate::chip_log_progress;
    use crate::chip_log_detail;

    use bitflags::{bitflags, Flags};
    //use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES, fabric_info::{self, FabricInfo, fabric_info_const_default}};
    use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES, fabric_info::{self, fabric_info_const_default}};
    use core::{ptr, str::{self, FromStr}};

    use mockall_double::double;
    #[cfg(test)]
    use mockall::*;

    #[double]
    use super::fabric_info::FabricInfo;

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

        tlv_estimate_struct_overhead!(size_of::<FabricIndex>(), size_of::<bool>(), size_of::<u64>(), size_of::<u64>())
    }

    const fn index_info_tlv_max_size() -> usize {
        use core::mem;
        // We have a single next-available index and an array of anonymous-tagged
        // fabric indices.
        //
        // The max size of the list is (1 byte control + bytes for actual value)
        // times max number of list items, plus one byte for the list terminator.

        tlv_estimate_struct_overhead!(size_of::<FabricIndex>(), CHIP_CONFIG_MAX_FABRICS * (1 + size_of::<FabricIndex>()) + 1)
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

    struct Delegate {
        next: *mut Self,
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
        m_delegate_list_root: *mut Delegate,

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

    #[derive(Default)]
    pub struct InitParams<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        pub storage: * mut PSD,
        pub operational_keystore: * mut OK,
        pub op_certs_store: * mut OCS,
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
            m_delegate_list_root: ptr::null_mut(),
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
            m_states: [const {fabric_info_const_default()}; CHIP_CONFIG_MAX_FABRICS],
            m_pending_fabric: fabric_info_const_default(),
            m_storage: ptr::null_mut(),
            m_operational_keystore: ptr::null_mut(),
            m_op_cert_store: ptr::null_mut(),
            m_delegate_list_root: ptr::null_mut(),
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
    impl<PSD, OK, OCS> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {
        fn load_from_storage(&mut self, fabric_index: FabricIndex, index: usize) -> ChipErrorResult {
            verify_or_return_error!(!self.m_storage.is_null(), Err(chip_error_invalid_argument!()));
            verify_or_return_error!(!self.m_states[index].is_initialized(), Err(chip_error_incorrect_state!()));

            let mut noc_buf = CertBuffer::default();
            let mut rcac_buf = CertBuffer::default();

            let err = self.fetch_noc_cert(fabric_index, &mut noc_buf).and_then(|_| {
                self.fetch_root_cert(fabric_index, &mut rcac_buf).and_then(|_| {
                    unsafe {
                        self.m_states[index].load_from_storage(self.m_storage.as_mut().unwrap(), fabric_index, noc_buf.const_bytes(), rcac_buf.const_bytes())
                    }
                })
            });

            if err.is_err() {
                chip_log_error!(FabricProvisioning, "Failed to load fabric {:#x}: {}", fabric_index, err.err().unwrap());
                self.m_states[index].reset();
                return err;
            }

            chip_log_progress!(FabricProvisioning, "fabric index {:#x} was retrieved from storage. Compressed Fabric Id {:#x}, FabricId {:#x}, NodeId {:#x}, VendorId {:#x}",
                self.m_states[index].get_fabric_index(), self.m_states[index].get_compressed_fabric_id(), self.m_states[index].get_fabric_id(), self.m_states[index].get_node_id(), self.m_states[index].get_vendor_id() as u16);

            chip_ok!()
        }

        fn read_fabric_info<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
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
                if self.load_from_storage(current_fabric_index, self.m_fabric_count as usize).is_ok() {
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
            verify_or_return_error!(!init_params.storage.is_null(), Err(chip_error_invalid_argument!()));
            verify_or_return_error!(!init_params.op_certs_store.is_null(), Err(chip_error_invalid_argument!()));

            self.m_storage = init_params.storage;
            self.m_operational_keystore = init_params.operational_keystore;
            self.m_op_cert_store = init_params.op_certs_store;

            chip_log_detail!(FabricProvisioning, "Initializing FabricTable from persistent storage");

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
                match self.m_storage.as_mut().unwrap().sync_get_key_value(DefaultStorageKeyAllocator::fabric_index_info().key_name_str(), &mut buf) {
                    Ok(data_size) => {
                        let mut reader = TlvContiguousBufferReader::default();
                        reader.init(buf.as_ptr(), data_size);

                        self.read_fabric_info(&mut reader).inspect_err(|e| {
                            chip_log_error!(FabricProvisioning, "Error loading fabric table {}, we are in a bad state!", e);
                        })?;
                    },
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
                },
                Err(e) => {
                    // Got an error, but somehow value is not missing altogether: inconsistent state but touch nothing.
                    if e != chip_error_persisted_storage_value_not_found!() {
                        chip_log_error!(FabricProvisioning, "Error loading Table commit marker {}, hope for the best", e);
                    }
                }
            }

            chip_ok!()
        }
    }

    // To be able to mock FabricInfo::load_from_storage, the most easy way is to make the generic
    // parameter static. So we have a different implement for this function with test cfg.
    #[cfg(test)]
    impl<PSD, OK, OCS> FabricTable<PSD, OK, OCS>
    where
        PSD: PersistentStorageDelegate + 'static,
        OK: crypto::OperationalKeystore,
        OCS: credentials::OperationalCertificateStore,
    {

        fn load_from_storage(&mut self, fabric_index: FabricIndex, index: usize) -> ChipErrorResult {
            verify_or_return_error!(!self.m_storage.is_null(), Err(chip_error_invalid_argument!()));
            verify_or_return_error!(!self.m_states[index].is_initialized(), Err(chip_error_incorrect_state!()));

            let mut noc_buf = CertBuffer::default();
            let mut rcac_buf = CertBuffer::default();

            let err = self.fetch_noc_cert(fabric_index, &mut noc_buf).and_then(|_| {
                self.fetch_root_cert(fabric_index, &mut rcac_buf).and_then(|_| {
                    unsafe {
                        self.m_states[index].load_from_storage(self.m_storage.as_mut().unwrap(), fabric_index, noc_buf.const_bytes(), rcac_buf.const_bytes())
                    }
                })
            });

            let fabric = &mut self.m_states[index];

            if err.is_err() {
                chip_log_error!(FabricProvisioning, "Failed to load fabric {:#x}: {}", fabric_index, err.err().unwrap());
                fabric.reset();
                return err;
            }

            chip_log_progress!(FabricProvisioning, "fabric index {:#x} was retrieved from storage. Compressed Fabric Id {:#x}, FabricId {:#x}, NodeId {:#x}, VendorId {:#x}",
                fabric.get_fabric_index(), fabric.get_compressed_fabric_id(), fabric.get_fabric_id(), fabric.get_node_id(), fabric.get_vendor_id() as u16);

            chip_ok!()
        }

        fn read_fabric_info<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
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
                if self.load_from_storage(current_fabric_index, self.m_fabric_count as usize).is_ok() {
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
            verify_or_return_error!(!init_params.storage.is_null(), Err(chip_error_invalid_argument!()));
            verify_or_return_error!(!init_params.op_certs_store.is_null(), Err(chip_error_invalid_argument!()));

            self.m_storage = init_params.storage;
            self.m_operational_keystore = init_params.operational_keystore;
            self.m_op_cert_store = init_params.op_certs_store;

            chip_log_detail!(FabricProvisioning, "Initializing FabricTable from persistent storage");

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
                match self.m_storage.as_mut().unwrap().sync_get_key_value(DefaultStorageKeyAllocator::fabric_index_info().key_name_str(), &mut buf) {
                    Ok(data_size) => {
                        let mut reader = TlvContiguousBufferReader::default();
                        reader.init(buf.as_ptr(), data_size);

                        self.read_fabric_info(&mut reader).inspect_err(|e| {
                            chip_log_error!(FabricProvisioning, "Error loading fabric table {}, we are in a bad state!", e);
                        })?;
                    },
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
                },
                Err(e) => {
                    // Got an error, but somehow value is not missing altogether: inconsistent state but touch nothing.
                    if e != chip_error_persisted_storage_value_not_found!() {
                        chip_log_error!(FabricProvisioning, "Error loading Table commit marker {}, hope for the best", e);
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
        pub fn delete(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn delete_all_fabric(&mut self) {}

        pub fn find_fabric(&self, _root_pub_key: &P256PublicKey, _fabric_id: FabricId) -> Option<FabricInfo> {
            None
        }

        pub fn find_fabric_with_index(&self, fabric_index: FabricIndex) -> Option<&FabricInfo> {
            if fabric_index == KUNDEFINED_FABRIC_INDEX {
                return None;
            }

            if self.has_pending_fabric_update() && (self.m_pending_fabric.get_fabric_index() == fabric_index) {
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

        pub fn find_indentiy(&self, _root_pub_key: &P256PublicKey, _fabric_id: FabricId, _node_id: NodeId) -> Option<FabricInfo> {
            None
        }

        pub fn find_fabric_with_compressed_id(&self, _compressed_fabric_id: CompressedFabricId) -> Option<FabricInfo> {
            None
        }

        pub fn shutdown(&mut self) {}

        pub fn get_deleted_fabric_from_commit_marker(&self) -> FabricIndex {
            0
        }

        pub fn clear_commit_marker(&mut self) {}

        pub fn forget(&mut self, _fabric_index: FabricIndex) {}

        pub fn add_fabric_delegate(&mut self, _delegate: * mut Delegate) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn remove_fabric_delegate(&mut self, _delegate: * mut Delegate) {
        }

        pub fn set_fabric_label(&mut self, _fabric_index: FabricIndex, _fabric_label: &str) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn get_fabric_label(&self, _fabric_index: FabricIndex) -> Result<&str, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn get_last_known_good_chip_epoch_time(&self) -> Result<Seconds32, ChipError> {
            self.m_last_known_good_time.get_last_known_good_chip_epoch_time()
        }

        pub fn set_last_known_good_chip_epoch_time(&mut self, _last_known_good_chip_epoch_time: Seconds32) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fabric_count(&self) -> u8 {
            self.m_fabric_count
        }

        pub fn fetch_root_cert(&self, fabric_index: FabricIndex, out_cert: &mut CertBuffer) -> ChipErrorResult {
            matter_trace_scope!("FetchRootCert", "Fabric");
            verify_or_return_error!(!self.m_op_cert_store.is_null(), Err(chip_error_incorrect_state!()));

            unsafe {
                let size = self.m_op_cert_store.as_ref().unwrap().get_certificate(fabric_index, CertChainElement::Krcac, out_cert.all_bytes())?;
                out_cert.set_length(size)?;
            }

            chip_ok!()
        }

        pub fn fetch_pending_non_fabric_associcated_root_cert(&self, _out_cert: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_icac_cert(&self, _fabric_index: FabricIndex, _out_cert: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_noc_cert(&self, fabric_index: FabricIndex, out_cert: &mut CertBuffer) -> ChipErrorResult {
            matter_trace_scope!("FetchNOCCert", "Fabric");
            verify_or_return_error!(!self.m_op_cert_store.is_null(), Err(chip_error_incorrect_state!()));

            unsafe {
                let size = self.m_op_cert_store.as_ref().unwrap().get_certificate(fabric_index, CertChainElement::Knoc, out_cert.all_bytes())?;
                out_cert.set_length(size)?;
            }

            chip_ok!()
        }

        pub fn fetch_vid_verification_statement(&self, _fabric_index: FabricIndex, _out_vid_verification_statement: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_vvsc(&self, _fabric_index: FabricIndex, _out_vvsc: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn fetch_root_pubkey(&self, fabric_index: FabricIndex) -> Result<&P256PublicKey, ChipError> {
            matter_trace_scope!("FetchRootPubkey", "Fabric");
            let fabric_info = self.find_fabric_with_index(fabric_index).ok_or(chip_error_invalid_fabric_index!())?;

            return fabric_info.fetch_root_pubkey();
        }

        pub fn fetch_Cats(&self, _fabric_index: FabricIndex) -> Result<CatValues, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn sign_with_op_keypair(&self, _fabric_index: FabricIndex, _message: &[u8], _out_signature: &mut P256EcdsaSignature) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn allocate_ephemeral_keypair_for_case(&self) -> Result<P256Keypair, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn release_ephemeral_keypair(&self, _keypair: P256Keypair) {
        }

        pub fn allocate_pending_operation_key(&self, _fabric_index: Option<FabricIndex>, _out_csr: &mut [u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }


        /**
         * @brief Returns whether an operational key is pending (Some if `AllocatePendingOperationalKey` was
         *        previously successfully called, None otherwise).
         *
         * @return in option: this is set to true if the `AllocatePendingOperationalKey` had an
         *                                    associated fabric index attached, indicating it's for UpdateNoc
         */
        pub fn has_pending_operational_key(&self) -> Option<bool> {
            None
        }

        pub fn has_operational_key_for_fabric(&self, _fabric_index: FabricIndex) -> bool {
            false
        }

        pub fn get_pending_fabric_index(&self) -> FabricIndex {
            KUNDEFINED_FABRIC_INDEX
        }


        pub fn get_operational_keystore(&self) -> * const OK {
            self.m_operational_keystore
        }


        pub fn add_new_pending_trusted_root_cert(&mut self, _rcac: &[u8]) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_pending_fabric_with_operational_keystore(&mut self, _noc: &[u8], _icac: &[u8], _vendor_id: u16,
            _advertise_identity: Option<AdvertiseIdentity>) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_pending_fabric_with_provided_op_key(&mut self, _noc: &[u8], _icac: &[u8], _vendor_id: u16,
            _existeding_op_key: &P256Keypair, _is_existing_op_key_externally_owned: bool,
            _advertise_identity: Option<AdvertiseIdentity>) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }


        pub fn update_pending_fabric_with_operational_keystore(&mut self, _fabric_index: FabricIndex, _noc: &[u8], _icac: &[u8],
            _advertise_identity: Option<AdvertiseIdentity>) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn update_pending_fabric_with_provided_op_key(&mut self, _noc: &[u8], _icac: &[u8], 
            _existeding_op_key: &P256Keypair, _is_existing_op_key_externally_owned: bool,
            _advertise_identity: Option<AdvertiseIdentity>) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn commit_pending_fabric_data(&mut self) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn revert_pending_fabric_data(&mut self) { }

        pub fn revert_pending_op_certs_except_root(&mut self) { }

        pub fn verify_credentials(&self, _fabric_index: FabricIndex, _noc: &[u8], _icac: &[u8], _context: &mut ValidationContext,
            ) -> Result<(CompressedFabricId, FabricId, NodeId, P256PublicKey, P256PublicKey), ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn run_verify_credentials(_fabric_index: FabricIndex, _noc: &[u8], _icac: &[u8], _context: &mut ValidationContext,
            ) -> Result<(CompressedFabricId, FabricId, NodeId, P256PublicKey, P256PublicKey), ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn permit_colliding_fabrics(&mut self) { 
            self.m_state_flag.insert(StateFlags::KareCollidingFabricsIgnored);
        }

        pub fn add_new_fabric_for_test(&mut self, _root_cert: &[u8], _icac_cert: &[u8], _noc_cert: &[u8], _ok_key: &[u8]) -> 
            Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_uncommited_fabric_for_test(&mut self, _root_cert: &[u8], _icac_cert: &[u8], _noc_cert: &[u8], _ok_key: &[u8]) -> 
            Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        pub fn add_new_fabric_for_test_ignoring_collisions(&mut self, root_cert: &[u8], icac_cert: &[u8], noc_cert: &[u8], ok_key: &[u8]) -> 
            Result<FabricIndex, ChipError> {
                self.permit_colliding_fabrics();
                self.m_state_flag.remove(StateFlags::KareCollidingFabricsIgnored);
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

        pub fn set_fabric_index_for_next_addition(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn sign_vid_verification_request(&self, _fabric_index: FabricIndex, _client_challenge: &[u8], _attestation_challenge: &[u8], out_response: &mut SignVidVerificationResponseData) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        pub fn set_vid_verification_statement_elements(&self, _fabric_index: FabricIndex, _vendor_id: Option<u16>, _vid_verification_statement: Option<&[u8]>, _vvsc: Option<&[u8]>) -> Result<bool, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn get_mutable_fabric_by_index(&mut self, _fabric_index: FabricIndex) -> Result<&mut FabricInfo, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn store_fabric_metadata(&mut self, _fabric_info: &FabricInfo) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn set_pending_data_fabric_index(&mut self, _fabric_index: FabricIndex) -> bool {
            false
        }

        fn add_or_update_inner(&mut self, _fabric_index: FabricIndex, _is_addition: bool, _existing_op_key: &P256Keypair,
            _is_existingg_op_key_externally_owned: bool, _vendor_id: u16, _advertise_identity: AdvertiseIdentity) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn add_new_pending_fabric_common(&mut self, _noc: &[u8], _icac: &[u8], _vendor_id: u16,
            _existeding_op_key: &P256Keypair, _is_existing_op_key_externally_owned: bool,
            _advertise_identity: AdvertiseIdentity) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn update_pending_fabric_common(&mut self, _noc: &[u8], _icac: &[u8], 
            _existeding_op_key: &P256Keypair, _is_existing_op_key_externally_owned: bool,
            _advertise_identity: AdvertiseIdentity) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn find_fabric_common_with_id(&self, _root_pub_key: &P256EcdsaSignature, _fabric_id: FabricId, _node_id: NodeId) -> Option<&FabricInfo> {
            None
        }

        fn find_fabric_common(&self, root_pub_key: &P256EcdsaSignature, fabric_id: FabricId) -> Option<&FabricInfo> {
            return self.find_fabric_common_with_id(root_pub_key, fabric_id, KUNDEFINED_NODE_ID);
        }

        fn update_next_available_fabric_index(&mut self) {
            if self.m_next_available_fabric_index.is_none() {
                return;
            }

            let mut candidate = next_fabric_index(self.m_next_available_fabric_index.clone().unwrap());

            while self.m_next_available_fabric_index.is_some_and(|index| index != candidate) {
                if self.find_fabric_with_index(candidate).is_none() {
                    self.m_next_available_fabric_index = Some(candidate);
                    return;
                }
                candidate = next_fabric_index(candidate);
            }
            self.m_next_available_fabric_index = None;
        }

        fn ensure_next_available_fabric_index_updated(&mut self) {
            if self.m_next_available_fabric_index.is_none() && self.m_fabric_count < KMAX_VALID_FABRIC_INDEX {
                // We must have a fabric index available here. This situation could
                // happen if we fail to store fabric index info when deleting a
                // fabric.
                self.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);
                if self.find_fabric_with_index(KMIN_VALID_FABRIC_INDEX).is_some() {
                    self.update_next_available_fabric_index();
                }
            }
        }

        fn store_fabric_index_info(&mut self) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn delete_metadata_from_storage(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
            verify_or_return_value!(is_valid_fabric_index(fabric_index), Err(chip_error_invalid_fabric_index!()));
            verify_or_return_value!(!self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
            unsafe {
                match self.m_storage.as_mut().unwrap().sync_delete_key_value(DefaultStorageKeyAllocator::fabric_metadata(fabric_index).key_name_str()) {
                    Ok(_) => {},
                    Err(e) => {
                        let not_found = chip_error_persisted_storage_value_not_found!();
                        if e == not_found {
                            chip_log_error!(FabricProvisioning, "Warning: metadata not found during delete of fabric {:#x}", fabric_index);
                        } else {
                            chip_log_error!(FabricProvisioning, "Error deleting metadata for fabric fabric {:#x}: {}", fabric_index, e);
                        }
                    }
                }
            }
            chip_ok!()
        }

        fn find_existing_fabric_by_noc_chaining(&self, _current_fabric_index: FabricIndex, _noc: &[u8]) -> Result<FabricIndex, ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn get_shadow_pending_fabric_entry(&self) -> Option<&FabricInfo> {
            if self.has_pending_fabric_update() {
                Some(&self.m_pending_fabric)
            } else {
                None
            }
        }

        fn has_pending_fabric_update(&self) -> bool {
            return self.m_pending_fabric.is_initialized() && self.m_state_flag.contains(StateFlags::KisPendingFabricDataPresent | StateFlags::KisUpdatePending);
        }

        fn validate_incoming_noc_chain(_noc: &[u8], _icac: &[u8], _rcac: &[u8], existing_fabric_id: FabricId, _policy: &CertificateValidityPolicy,
            ) -> Result<(CompressedFabricId, FabricId, NodeId, P256PublicKey, P256PublicKey), ChipError> {
            Err(chip_error_not_implemented!())
        }

        fn notify_fabric_updated(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn notify_fabric_commited(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn store_commit_marker(&mut self, _commit_marker: &CommitMarker) -> ChipErrorResult {
            Err(chip_error_not_implemented!())
        }

        fn get_commit_marker(&self) -> Result<CommitMarker, ChipError> {
            const TLV_SIZE: usize = commit_marker_context_tlv_max_size();
            let mut tlv_buf: [u8; TLV_SIZE] = [0; TLV_SIZE];

            let mut out_commit_marker = CommitMarker::default();

            let mut tlv_read_size = 0usize;
            unsafe {
                tlv_read_size = self.m_storage.as_mut().unwrap().sync_get_key_value(DefaultStorageKeyAllocator::fabric_table_commit_marker_key().key_name_str(), &mut tlv_buf)?;
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


    #[cfg(test)]
    mod tests {
        use crate::chip::{
            CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
            system::system_clock::Seconds32,
            chip_lib::{
                core::{
                    tlv_reader::{TlvContiguousBufferReader, TlvReader, MockTlvReader},
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
                    chip_config::CHIP_CONFIG_MAX_FABRICS,
                },
                support::{
                    default_string::DefaultString,
                    default_storage_key_allocator::DefaultStorageKeyAllocator,
                    test_persistent_storage::TestPersistentStorage,
                }
            },
            credentials::{
                self, last_known_good_time::LastKnownGoodTime, chip_certificate_set::ValidationContext,
                certificate_validity_policy::CertificateValidityPolicy,
                operational_certificate_store::{CertChainElement, OperationalCertificateStore, MockOperationalCertificateStore},
                chip_cert::{CertBuffer, K_MAX_CHIP_CERT_LENGTH, extract_public_key_from_chip_cert_byte, extract_node_id_fabric_id_from_op_cert_byte},
                persistent_storage_op_cert_store::PersistentStorageOpCertStore,
                fabric_table::{
                    fabric_table::{FabricTable, InitParams},
                    fabric_info,
                },
            },
            crypto::{
                self,
                generate_compressed_fabric_id,
                crypto_pal::{P256EcdsaSignature, P256Keypair, P256PublicKey, ECPKey, ECPKeypair, P256KeypairBase, P256SerializedKeypair},
                persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
            },
        };
        use crate::ChipErrorResult;
        use crate::ChipError;
        use crate::chip_error_internal;
        use crate::chip_error_key_not_found;
        use crate::chip_error_end_of_tlv;
        use crate::chip_core_error;
        use crate::chip_ok;
        use crate::chip_sdk_error;

        use core::ptr;
        use static_cell::StaticCell;
        use mockall::*;
        use mockall_double::double;

        use super::super::fabric_info::MockFabricInfo as FabricInfo;

        type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
        type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;
        type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;

        #[test]
        fn default_init() {
            let table = TestFabricTable::default();
            assert_eq!(false, table.has_operational_key_for_fabric(0));
        }

        #[test]
        fn find_fabric_with_index_successfully() {
            let mut table = TestFabricTable::default();
            assert_eq!(true, table.find_fabric_with_index(KUNDEFINED_FABRIC_INDEX).is_none());
            table.m_pending_fabric.expect_is_initialized().
                times(1).
                return_const(true);

            // first fabric is matched.
            table.m_states[0].expect_is_initialized().
                times(1).
                return_const(true);
            table.m_states[0].expect_get_fabric_index().
                times(1).
                return_const(1);

            assert_eq!(true, table.find_fabric_with_index(1).is_some());
        }

        #[test]
        fn find_no_fabric_with_index() {
            let mut table = TestFabricTable::default();
            assert_eq!(true, table.find_fabric_with_index(KUNDEFINED_FABRIC_INDEX).is_none());
            table.m_pending_fabric.expect_is_initialized().
                times(1).
                return_const(true);
            // ensure none of the fabric is matched
            for f in &mut table.m_states {
                f.expect_is_initialized().
                    times(1).
                    return_const(true);
                f.expect_get_fabric_index().
                    times(1).
                    return_const(KUNDEFINED_FABRIC_INDEX);
            }
            assert_eq!(true, table.find_fabric_with_index(1).is_none());
        }

        #[test]
        fn update_next_available_fabric_index_no_avaiable() {
            let mut table = TestFabricTable::default();
            /*
            table.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);
            table.update_next_available_fabric_index();
            */
            assert_eq!(true, table.m_next_available_fabric_index.is_none());
        }

        #[test]
        fn update_next_available_fabric_index() {
            let mut table = TestFabricTable::default();
            table.m_next_available_fabric_index = Some(KMIN_VALID_FABRIC_INDEX);

            // pending fabric will be checked in the find_fabric_with_index
            table.m_pending_fabric.expect_is_initialized().
                times(1).
                return_const(true);

            // ensure all fabric won't return KMIN_VALID_FABRIC_INDEX.
            for f in &mut table.m_states {
                f.expect_is_initialized().
                    times(1).
                    return_const(true);
                f.expect_get_fabric_index().
                    times(1).
                    return_const(KUNDEFINED_FABRIC_INDEX);
            }

            table.update_next_available_fabric_index();
            assert_eq!(true, table.m_next_available_fabric_index.is_some_and(|i| i == KMIN_VALID_FABRIC_INDEX + 1));
        }

        /*
        #[test]
        fn update_next_available_fabric_index_no_avaiable_fabric() {
          // it is too hard to make the all fabric index 0~255 not avaliable
        }
        */


        #[test]
        fn fetch_noc_cert_successfully() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Knoc) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);
            let mut buf = CertBuffer::default();

            assert_eq!(true, table.fetch_noc_cert(KMIN_VALID_FABRIC_INDEX, &mut buf).is_ok());
        }

        #[test]
        fn fetch_root_cert_successfully() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Krcac) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);
            let mut buf = CertBuffer::default();

            assert_eq!(true, table.fetch_root_cert(KMIN_VALID_FABRIC_INDEX, &mut buf).is_ok());
        }

        #[test]
        fn load_from_storage_successfully() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Knoc) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            // mock root fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Krcac) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by laod_from_stgorage at fabric info
            table.m_states[0].expect_is_initialized().
                return_const(false);
            table.m_states[0].expect_load_from_storage::<TestPersistentStorage>().
                withf(|_, index, noc_len, rcac_len| {
                    (*index == KMIN_VALID_FABRIC_INDEX) && noc_len.len() == 1 && rcac_len.len() == 1
                }).
                return_const(Ok(()));

            // calls used by the log
            table.m_states[0].expect_get_fabric_index().return_const(1);
            table.m_states[0].expect_get_compressed_fabric_id().return_const(1u64);
            table.m_states[0].expect_get_fabric_id().return_const(1u64);
            table.m_states[0].expect_get_node_id().return_const(1u64);
            table.m_states[0].expect_get_vendor_id().return_const(VendorId::Common);

            assert_eq!(true, table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok());
        }

        #[test]
        fn load_from_storage_fetch_noc_failed() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Knoc) && (out_cert.len() > 0)
                }).
                return_const(Err(chip_error_internal!()));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by reset at fabric info
            /*
            let mut fabric = FabricInfo::default();
            fabric.expect_is_initialized().
                return_const(false);
            fabric.expect_reset().return_const(());

            assert_eq!(false, table.load_from_storage(KMIN_VALID_FABRIC_INDEX, &mut fabric).is_ok());
            */
            table.m_states[0].expect_is_initialized().
                return_const(false);
            table.m_states[0].expect_reset().return_const(());

            assert_eq!(false, table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok());
        }

        #[test]
        fn load_from_storage_fetch_root_failed() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Knoc) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            // mock root fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Krcac) && (out_cert.len() > 0)
                }).
                return_const(Err(chip_error_internal!()));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by reset at fabric info
            table.m_states[0].expect_is_initialized().
                return_const(false);
            table.m_states[0].expect_reset().return_const(());

            assert_eq!(false, table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok());
        }

        #[test]
        fn load_from_storage_fabric_failed() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Knoc) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            // mock root fetch
            mock_op_cert_store.expect_get_certificate().
                times(1).
                withf(|index, element, out_cert| {
                    (*index == (KMIN_VALID_FABRIC_INDEX)) && (*element == CertChainElement::Krcac) && (out_cert.len() > 0)
                }).
                return_const(Ok(1));
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by laod_from_stgorage at fabric info
            table.m_states[0].expect_is_initialized().
                return_const(false);
            table.m_states[0].expect_load_from_storage::<TestPersistentStorage>().
                return_const(Err(chip_error_internal!()));

            table.m_states[0].expect_reset().return_const(());

            assert_eq!(false, table.load_from_storage(KMIN_VALID_FABRIC_INDEX, 0).is_ok());
        }

        #[test]
        fn read_one_fabric_info_successfully() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // prepare load_from_storage call
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                return_const(Ok(1));
            // mock root fetch
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by laod_from_stgorage at fabric info
            for i in 0..1 {
                table.m_states[i].expect_is_initialized().
                    return_const(false);
                table.m_states[i].expect_load_from_storage::<TestPersistentStorage>().
                    return_const(Ok(()));

                // calls used by the log
                table.m_states[i].expect_get_fabric_index().return_const(i as u8);
                table.m_states[i].expect_get_compressed_fabric_id().return_const(i as u64);
                table.m_states[i].expect_get_fabric_id().return_const(i as u64);
                table.m_states[i].expect_get_node_id().return_const(i as u64);
                table.m_states[i].expect_get_vendor_id().return_const(VendorId::Common);
            }


            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().
                return_const(Ok(()));
            reader.expect_enter_container().
                return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().
                return_const(Ok(()));

            // next avaiable fabric index
            reader.expect_get_type().
                return_const(TlvType::KtlvTypeUnsignedInteger);
            reader.expect_get_u8().
                return_const(Ok(1u8));

            let mut num_next: usize = 0;
            reader.expect_next().
                returning(move || {
                    if num_next < 1 {
                        num_next += 1;
                        return Ok(());
                    } else {
                        num_next += 1;
                        return Err(chip_error_end_of_tlv!());
                    }
                });
            reader.expect_get_u8().
                return_const(Ok(0u8));
            reader.expect_exit_container().
                return_const(Ok(()));
            reader.expect_verify_end_of_container().
                return_const(Ok(()));

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(1, table.fabric_count());
        }

        #[test]
        fn read_two_fabric_info_successfully() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // prepare load_from_storage call
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                return_const(Ok(1));
            // mock root fetch
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by laod_from_stgorage at fabric info
            for i in 0..2 {
                table.m_states[i].expect_is_initialized().
                    return_const(false);
                table.m_states[i].expect_load_from_storage::<TestPersistentStorage>().
                    return_const(Ok(()));

                // calls used by the log
                table.m_states[i].expect_get_fabric_index().return_const(i as u8);
                table.m_states[i].expect_get_compressed_fabric_id().return_const(i as u64);
                table.m_states[i].expect_get_fabric_id().return_const(i as u64);
                table.m_states[i].expect_get_node_id().return_const(i as u64);
                table.m_states[i].expect_get_vendor_id().return_const(VendorId::Common);
            }


            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().
                return_const(Ok(()));
            reader.expect_enter_container().
                return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().
                return_const(Ok(()));

            // next avaiable fabric index
            reader.expect_get_type().
                return_const(TlvType::KtlvTypeUnsignedInteger);
            reader.expect_get_u8().
                return_const(Ok(3u8));

            let mut num_next: usize = 0;
            reader.expect_next().
                returning(move || {
                    if num_next < 2 {
                        num_next += 1;
                        return Ok(());
                    } else {
                        num_next += 1;
                        return Err(chip_error_end_of_tlv!());
                    }
                });
            reader.expect_get_u8().
                return_const(Ok(0u8));
            reader.expect_exit_container().
                return_const(Ok(()));
            reader.expect_verify_end_of_container().
                return_const(Ok(()));

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(2, table.fabric_count());
        }

        #[test]
        fn read_fabric_info_load_failed() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            // prepare load_from_storage call
            // mock noc fetch
            mock_op_cert_store.expect_get_certificate().
                return_const(Ok(1));
            // mock root fetch
            table.m_op_cert_store = ptr::addr_of_mut!(mock_op_cert_store);

            // update the persistent storage
            static PA: StaticCell<TestPersistentStorage> = StaticCell::new();
            let pa = PA.init(TestPersistentStorage::default());
            table.m_storage = pa;

            // calls used by laod_from_stgorage at fabric info
            for i in 0..1 {
                table.m_states[i].expect_is_initialized().
                    return_const(false);
                table.m_states[i].expect_load_from_storage::<TestPersistentStorage>().
                    return_const(Err(chip_error_internal!()));
                table.m_states[i].expect_reset().
                    return_const(());
            }


            let mut reader = MockTlvReader::new();
            reader.expect_next_type_tag().
                return_const(Ok(()));
            reader.expect_enter_container().
                return_const(Ok(TlvType::KtlvTypeStructure));
            reader.expect_next_tag().
                return_const(Ok(()));

            // next avaiable fabric index
            reader.expect_get_type().
                return_const(TlvType::KtlvTypeUnsignedInteger);
            reader.expect_get_u8().
                return_const(Ok(1u8));

            let mut num_next: usize = 0;
            reader.expect_next().
                returning(move || {
                    if num_next < 1 {
                        num_next += 1;
                        return Ok(());
                    } else {
                        num_next += 1;
                        return Err(chip_error_end_of_tlv!());
                    }
                });
            reader.expect_get_u8().
                return_const(Ok(0u8));
            reader.expect_exit_container().
                return_const(Ok(()));
            reader.expect_verify_end_of_container().
                return_const(Ok(()));

            assert_eq!(true, table.read_fabric_info(&mut reader).is_ok());
            assert_eq!(0, table.fabric_count());
        }

        #[test]
        fn init_with_no_index_info_successfull() {
            let mut table = FabricTable::<TestPersistentStorage, OK, MockOperationalCertificateStore>::default();
            let mut init_params = InitParams::default();
            let mut pa = TestPersistentStorage::default();
            let mut mock_op_cert_store = MockOperationalCertificateStore::new();
            init_params.storage = ptr::addr_of_mut!(pa);
            init_params.op_certs_store = ptr::addr_of_mut!(mock_op_cert_store);

            // reset all fabric
            for i in 0..table.m_states.len() {
                table.m_states[i].expect_reset().
                    return_const(());
            }

            assert_eq!(true, table.init(&init_params).is_ok());
        }
    } // end of mod tests
} // end of mod fabric_table
