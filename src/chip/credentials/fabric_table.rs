use crate::chip::{
    system::system_clock::Seconds32,
    chip_lib::{
        core::{
            tlv_reader::TlvContiguousBufferReader,
            case_auth_tag::CatValues,
            data_model_types::{
                KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX,
            }
        },
    }
};
use crate::chip::chip_lib::core::node_id::{is_operational_node_id, KUNDEFINED_NODE_ID};
use crate::chip::chip_lib::core::{
    chip_config::CHIP_CONFIG_MAX_FABRICS, chip_encoding,
    chip_persistent_storage_delegate::PersistentStorageDelegate,
};
use crate::chip::{CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId};

use crate::chip::chip_lib::core::data_model_types::FabricIndex;

use crate::chip::crypto::{
    self,
    crypto_pal::{P256EcdsaSignature, P256Keypair, P256PublicKey},
};

use crate::chip::credentials::{self, last_known_good_time::LastKnownGoodTime, chip_certificate_set::ValidationContext,
certificate_validity_policy::CertificateValidityPolicy};

use crate::chip_core_error;
use crate::chip_error_invalid_argument;
use crate::chip_error_not_implemented;
use crate::chip_ok;
use crate::chip_sdk_error;
use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::ChipErrorResult;
use crate::ChipError;

use bitflags::{bitflags, Flags};
use core::{ptr, str};

const KFABRIC_LABEL_MAX_LENGTH_IN_BYTES: usize = 32;

pub struct FabricInfo {
    m_node_id: NodeId,
    m_fabric_id: FabricId,
    m_compressed_fabric_id: CompressedFabricId,
    m_root_publick_key: P256PublicKey,
    m_fabric_label: [u8; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
    m_fabric_label_len: usize,
    m_fabric_index: FabricIndex,
    m_vendor_id: VendorId,
    m_has_externally_owned_operation_key: bool,
    m_should_advertise_identity: bool,
    m_operation_key: *mut P256Keypair,
}

impl Default for FabricInfo {
    fn default() -> Self {
        FabricInfo::const_default()
    }
}

impl FabricInfo {
    pub const fn const_default() -> Self {
        Self {
            m_node_id: KUNDEFINED_NODE_ID,
            m_fabric_id: KUNDEFINED_FABRIC_ID,
            m_compressed_fabric_id: KUNDEFINED_COMPRESSED_FABRIC_ID,
            m_root_publick_key: P256PublicKey::const_default(),
            m_fabric_label: [0; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES],
            m_fabric_label_len: 0,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_vendor_id: VendorId::NotSpecified,
            m_has_externally_owned_operation_key: false,
            m_should_advertise_identity: true,
            m_operation_key: ptr::null_mut(),
        }
    }

    pub fn get_fabric_label(&self) -> Option<&str> {
        match str::from_utf8(&self.m_fabric_label[..self.m_fabric_label_len]) {
            Ok(s) => Some(s),
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                unsafe {
                    Some(str::from_utf8_unchecked(
                        &self.m_fabric_label[..valid_up_to],
                    ))
                }
            }
        }
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

    pub fn fetch_root_pubkey(&self, out_public_key: &mut P256PublicKey) -> ChipErrorResult {
        chip_ok!()
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
}

impl Drop for FabricInfo {
    fn drop(&mut self) {
        self.reset();
    }
}

// TODO: we have to handle the transfer of ownership of operational keypair when we have an
// assignment. For examle, let info2 = info1

mod fabric_info_private {
    use super::FabricInfo;
    use super::KFABRIC_LABEL_MAX_LENGTH_IN_BYTES;

    use crate::chip::{
        chip_lib::{
            support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
            },
        },
        credentials::chip_cert::{extract_public_key_from_chip_cert_byte, extract_node_id_fabric_id_from_op_cert_byte},
        crypto::generate_compressed_fabric_id,
    };
    use crate::chip::chip_lib::core::{
        tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
        tlv_reader::{TlvContiguousBufferReader, TlvReader},
        tlv_types::TlvType,
        tlv_tags::{self, anonymous_tag},
        data_model_types::{
            FabricIndex, KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX,
        },
    };
    use crate::chip::chip_lib::core::node_id::{is_operational_node_id, KUNDEFINED_NODE_ID};
    use crate::chip::{CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId};

    use crate::chip::crypto::crypto_pal::{
        P256EcdsaSignature, P256Keypair, P256PublicKey, P256SerializedKeypair,
    };
    use crate::chip_core_error;
    use crate::chip_error_invalid_argument;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_internal;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;

    /*
    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_detail;
    use core::str::FromStr;
    */

    use crate::ChipErrorResult;

    use core::{ptr, str};

    const K_FABRIC_LABEL_MAX_LENGTH_IN_BYTES: u8 = 32;

    fn vendor_id_tag() -> tlv_tags::Tag {
        tlv_tags::context_tag(0)
    }

    fn fabric_label_tag() -> tlv_tags::Tag {
        tlv_tags::context_tag(1)
    }

    const fn metadata_tlv_max_size() -> usize {
        tlv_estimate_struct_overhead!(core::mem::size_of::<u16>(), K_FABRIC_LABEL_MAX_LENGTH_IN_BYTES as usize)
    }

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

    impl FabricInfo {
        pub(super) fn init(&mut self, init_params: InitParams) -> ChipErrorResult {
            init_params.are_valid()?;

            self.reset();

            self.m_node_id = init_params.m_node_id;
            self.m_fabric_id = init_params.m_fabric_id;
            self.m_fabric_index = init_params.m_fabric_index;
            self.m_compressed_fabric_id = init_params.m_compressed_fabric_id;
            self.m_root_publick_key = init_params.m_root_publick_key;
            self.m_vendor_id = init_params.m_vendor_id;
            self.m_should_advertise_identity = init_params.m_should_advertise_identity;

            if init_params.m_operation_key.is_null() == false {
                self.set_externally_owned_operational_keypair(init_params.m_operation_key)?;
            } else {
                self.set_operational_keypair(init_params.m_operation_key)?;
            }

            chip_ok!()
        }

        pub(super) fn set_operational_keypair(
            &mut self,
            keypair: *const P256Keypair,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn set_externally_owned_operational_keypair(
            &mut self,
            keypair: *mut P256Keypair,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn sign_with_op_keypair(
            &self,
            message: &mut [u8],
            out_signature: &mut P256EcdsaSignature,
        ) -> ChipErrorResult {
            chip_ok!()
        }

        pub(super) fn reset(&mut self) {
            self.m_node_id = KUNDEFINED_NODE_ID;
            self.m_fabric_id = KUNDEFINED_FABRIC_ID;
            self.m_fabric_index = KUNDEFINED_FABRIC_INDEX;
            self.m_compressed_fabric_id = KUNDEFINED_COMPRESSED_FABRIC_ID;

            self.m_vendor_id = VendorId::NotSpecified;
            self.m_fabric_label = [0; KFABRIC_LABEL_MAX_LENGTH_IN_BYTES];
            self.m_fabric_label_len = 0;

            if !self.m_has_externally_owned_operation_key
                && self.m_operation_key.is_null() == false
            {
                // TODO: delete by platform
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

        pub(super) fn commit_to_storge<Storage: PersistentStorageDelegate>(
            &self,
            storage: *mut Storage,
        ) -> ChipErrorResult {
            let mut buf: [u8; FabricInfo::metadata_tlv_max_size()] = [0; {FabricInfo::metadata_tlv_max_size()}];
            let mut writer = TlvContiguousBufferWriter::const_default();

            writer.init(buf.as_mut_ptr(), FabricInfo::metadata_tlv_max_size() as u32);

            let mut outer_type = TlvType::KtlvTypeNotSpecified;

            writer.start_container(
                tlv_tags::anonymous_tag(),
                TlvType::KtlvTypeStructure,
                &mut outer_type,
            )?;

            writer.put_u16(vendor_id_tag(), self.m_vendor_id as u16)?;
            let label = str::from_utf8(&self.m_fabric_label[..self.m_fabric_label_len]).map_err(|_| {
                chip_error_internal!()
            })?;
            writer.put_string(fabric_label_tag(), label)?;

            writer.end_container(outer_type)?;

            let meta_data_len = u16::try_from(writer.get_length_written()).map_err(|_| {
                chip_error_buffer_too_small!()
            })?;

            unsafe {
                return storage.as_mut().unwrap().sync_set_key_value(DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(), &buf[..meta_data_len as usize]);
            }
        }

        pub(super) fn load_from_storage<Storage: PersistentStorageDelegate>(
            &mut self,
            storage: *mut Storage,
            new_fabric_index: FabricIndex,
            rcac: &[u8],
            noc: &[u8],
        ) -> ChipErrorResult {
            verify_or_return_error!(!storage.is_null(), Err(chip_error_invalid_argument!()));
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
                unsafe {
                    storage.as_ref().unwrap().sync_get_key_value(DefaultStorageKeyAllocator::fabric_metadata(self.m_fabric_index).key_name_str(), &mut buffer[..])?;
                }
                let mut reader = TlvContiguousBufferReader::const_default();
                reader.init(buffer.as_ptr(), size);
                reader.next_type_tag(TlvType::KtlvTypeStructure, anonymous_tag())?;
                let container_type = reader.enter_container()?;

                reader.next_tag(vendor_id_tag())?;
                self.m_vendor_id = reader.get_u16()?.into();

                reader.next_tag(fabric_label_tag())?;
                let label = reader.get_string()?.ok_or(chip_error_internal!())?;

                verify_or_return_error!(label.len() <= KFABRIC_LABEL_MAX_LENGTH_IN_BYTES, Err(chip_error_buffer_too_small!()));
                self.m_fabric_label[..label.len()].copy_from_slice(label.as_bytes());
                self.m_fabric_label_len = label.len();

                reader.verify_end_of_container()?;
                reader.exit_container(container_type)?;
            }
            chip_ok!()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use super::super::*;
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
        type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;
        const CHIP_CERT_SIZE: usize = 123 + K_P256_PUBLIC_KEY_LENGTH;

        fn stub_public_key() -> [u8; K_P256_PUBLIC_KEY_LENGTH] {
            let mut fake_public_key: [u8; crate::chip::crypto::K_P256_PUBLIC_KEY_LENGTH] = [0; K_P256_PUBLIC_KEY_LENGTH];
            let mut keypair = P256Keypair::default();
            let _ = keypair.initialize(ECPKeyTarget::Ecdh);
            fake_public_key.copy_from_slice(keypair.ecdsa_pubkey().const_bytes());
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
            let info = FabricInfo::const_default();
            assert_eq!(false, info.has_operational_key());
        }

        #[test]
        fn commit() {
            let mut pa = TestPersistentStorage::default();
            let info = FabricInfo::const_default();
            assert_eq!(true, info.commit_to_storge(ptr::addr_of_mut!(pa)).is_ok());
            assert_eq!(true, pa.has_key(DefaultStorageKeyAllocator::fabric_metadata(0).key_name_str()));
        }

        #[test]
        fn load() {
            let mut pa = TestPersistentStorage::default();
            let mut info = FabricInfo::const_default();
            info.m_vendor_id = VendorId::Common;
            let label = "abc";
            info.m_fabric_label[..label.len()].copy_from_slice(label.as_bytes());
            info.m_fabric_label_len = label.len();
            // commit first
            assert_eq!(true, info.commit_to_storge(ptr::addr_of_mut!(pa)).is_ok());

            let pub_key = stub_public_key();
            let rcac = make_chip_cert(1,2, &pub_key[..]).unwrap();
            let noc = make_chip_cert(3,4, &pub_key[..]).unwrap();

            let mut info_out = FabricInfo::const_default();
            assert_eq!(true, info_out.load_from_storage(ptr::addr_of_mut!(pa), 0, &rcac, &noc).inspect_err(|e| println!("{:?}", e)).is_ok());
            assert_eq!(3, info_out.m_node_id);
            assert_eq!(4, info_out.m_fabric_id);
            assert_eq!(VendorId::Common, info_out.m_vendor_id);
            assert_eq!("abc".as_bytes(), &info_out.m_fabric_label[..info_out.m_fabric_label_len]);
        }
    } // end of mod tests
}

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

#[derive(Default)]
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

struct Delegate {
    next: *mut Self,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum AdvertiseIdentity {
    Yes,
    No,
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

impl<PSD, OK, OCS> FabricTable<PSD, OK, OCS>
where
    PSD: PersistentStorageDelegate,
    OK: crypto::OperationalKeystore,
    OCS: credentials::OperationalCertificateStore,
{
    pub const fn const_default() -> Self {
        Self {
            m_states: [const { FabricInfo::const_default() }; CHIP_CONFIG_MAX_FABRICS],
            m_pending_fabric: FabricInfo::const_default(),
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

    pub fn delete(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn delete_all_fabric(&mut self) {}

    pub fn find_fabric(&self, _root_pub_key: &P256PublicKey, _fabric_id: FabricId) -> Option<FabricInfo> {
        None
    }

    pub fn find_fabric_with_index(&self, _fabric_index: FabricIndex) -> Option<FabricInfo> {
        None
    }

    pub fn find_indentiy(&self, _root_pub_key: &P256PublicKey, _fabric_id: FabricId, _node_id: NodeId) -> Option<FabricInfo> {
        None
    }

    pub fn find_fabric_with_compressed_id(&self, _compressed_fabric_id: CompressedFabricId) -> Option<FabricInfo> {
        None
    }

    pub fn init(&mut self, _init_params: &InitParams<PSD, OK, OCS>) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
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

    pub fn fetch_root_cert(&self, _fabric_index: FabricIndex, _out_cert: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_pending_non_fabric_associcated_root_cert(&self, _out_cert: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_icac_cert(&self, _fabric_index: FabricIndex, _out_cert: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_noc_cert(&self, _fabric_index: FabricIndex, _out_cert: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_vid_verification_statement(&self, _fabric_index: FabricIndex, _out_vid_verification_statement: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_vvsc(&self, _fabric_index: FabricIndex, _out_vvsc: &mut [u8]) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    pub fn fetch_root_pubkey(&self, _fabric_index: FabricIndex) -> Result<P256PublicKey, ChipError> {
        Err(chip_error_not_implemented!())
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

    fn load_from_storage(&self, _fabric_index: FabricIndex) -> Result<* mut FabricInfo, ChipError> {
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

    fn update_next_available_fabric_index(&mut self) {}

    fn ensure_next_available_fabric_index_updated(&mut self) {}

    fn store_fabric_index_info(&mut self) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    fn delete_metadata_from_storage(&mut self, _fabric_index: FabricIndex) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
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

    fn read_fabric_info(&self, _reader: &mut TlvContiguousBufferReader) -> ChipErrorResult {
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
        Err(chip_error_not_implemented!())
    }
}

impl<PSD, OK, OCS> Default for FabricTable<PSD, OK, OCS>
where
    PSD: PersistentStorageDelegate,
    OK: crypto::OperationalKeystore,
    OCS: credentials::OperationalCertificateStore,
{
    fn default() -> Self {
        FabricTable::<PSD,OK,OCS>::const_default()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::{
        credentials::persistent_storage_op_cert_store::PersistentStorageOpCertStore,
        crypto::persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
        chip_lib::support::test_persistent_storage::TestPersistentStorage,
    };

    type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
    type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;
    type TestFabricTable = FabricTable<TestPersistentStorage, OK, OCS>;

    #[test]
    fn default_init() {
        let table = TestFabricTable::const_default();
        assert_eq!(false, table.has_operational_key_for_fabric(0));
    }
} // end of mod tests
