use crate::chip::chip_lib::{
    core::{
        chip_persistent_storage_delegate::PersistentStorageDelegate,
        data_model_types::{is_valid_fabric_index, FabricIndex, KUNDEFINED_FABRIC_INDEX},
        tlv_reader::{TlvContiguousBufferReader, TlvReader, TlvReaderBasic},
        tlv_tags,
        tlv_types::TlvType,
        tlv_writer::{TlvContiguousBufferWriter, TlvWriter, TlvWriterBasic},
    },
    support::default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
};

use crate::chip::crypto::{
    self, ECPKey, ECPKeypair, OperationalKeystore, P256EcdsaSignature, P256Keypair,
    P256KeypairBase, P256SerializedKeypair, SensitiveDataBuffer,
};

use crate::chip_core_error;
use crate::chip_error_not_implemented;
use crate::chip_sdk_error;
use crate::ChipError;
use crate::ChipErrorResult;

use crate::chip_error_buffer_too_small;
use crate::chip_error_incorrect_state;
use crate::chip_error_internal;
use crate::chip_error_invalid_argument;
use crate::chip_error_invalid_fabric_index;
use crate::chip_error_invalid_public_key;
use crate::chip_error_persisted_storage_value_not_found;
use crate::chip_error_version_mismatch;
use crate::chip_ok;

use crate::tlv_estimate_struct_overhead;
use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::{ptr, slice};

fn op_key_version_tag() -> tlv_tags::Tag {
    tlv_tags::context_tag(0)
}

fn op_key_data_tag() -> tlv_tags::Tag {
    tlv_tags::context_tag(1)
}

const K_OP_KEY_VERSION: u16 = 1;

const fn op_key_tlv_max_size() -> usize {
    tlv_estimate_struct_overhead!(
        core::mem::size_of::<u16>(),
        P256SerializedKeypair::capacity()
    )
}

fn store_operational_key<Delegate: PersistentStorageDelegate>(
    fabric_index: FabricIndex,
    storage: &mut Delegate,
    keypair: &P256Keypair,
) -> ChipErrorResult {
    verify_or_return_error!(
        is_valid_fabric_index(fabric_index),
        Err(chip_error_invalid_argument!())
    );
    // Use a SensitiveDataBuffer to get RAII secret data clearing on scope exit.
    let mut buf = SensitiveDataBuffer::<{ op_key_tlv_max_size() }>::default();
    let mut writer = TlvContiguousBufferWriter::const_default();

    writer.init(
        buf.bytes_raw(),
        SensitiveDataBuffer::<{ op_key_tlv_max_size() }>::capacity() as u32,
    );
    let mut outer_type = TlvType::KtlvTypeNotSpecified;

    writer.start_container(
        tlv_tags::anonymous_tag(),
        TlvType::KtlvTypeStructure,
        &mut outer_type,
    )?;
    writer.put_u16(op_key_version_tag(), K_OP_KEY_VERSION)?;

    let mut serialized_op_key = P256SerializedKeypair::default();
    keypair.serialize(&mut serialized_op_key)?;
    writer.put_bytes(
        op_key_data_tag(),
        &serialized_op_key.const_bytes()[..serialized_op_key.length()],
    )?;

    writer.end_container(outer_type)?;

    let op_key_length = writer.get_length_written();

    verify_or_return_error!(
        op_key_length < (u16::MAX as usize),
        Err(chip_error_buffer_too_small!())
    );

    storage.sync_set_key_value(
        DefaultStorageKeyAllocator::fabric_op_key(fabric_index).key_name_str(),
        &buf.const_bytes()[..op_key_length],
    )?;

    chip_ok!()
}

fn export_stored_op_key<Delegate: PersistentStorageDelegate>(
    fabric_index: FabricIndex,
    storage: &mut Delegate,
    serialized_op_key: &mut P256SerializedKeypair,
) -> ChipErrorResult {
    verify_or_return_error!(
        is_valid_fabric_index(fabric_index),
        Err(chip_error_invalid_fabric_index!())
    );
    // Use a SensitiveDataBuffer to get RAII secret data clearing on scope exit.
    let mut buf = SensitiveDataBuffer::<{ op_key_tlv_max_size() }>::default();
    let size = storage.sync_get_key_value(
        DefaultStorageKeyAllocator::fabric_op_key(fabric_index).key_name_str(),
        buf.bytes(),
    )?;

    buf.set_length(size);

    // Read-out the operational key TLV entry.
    let mut reader = TlvContiguousBufferReader::const_default();
    reader.init(buf.const_bytes_raw(), buf.length());

    reader.next_type_tag(TlvType::KtlvTypeStructure, tlv_tags::anonymous_tag())?;
    let container_type = reader.enter_container()?;

    reader.next_tag(op_key_version_tag())?;
    let op_key_version: u16 = reader.get_u16()?;
    verify_or_return_error!(
        op_key_version == K_OP_KEY_VERSION,
        Err(chip_error_version_mismatch!())
    );

    reader.next_tag(op_key_data_tag())?;

    let key_data = reader.get_bytes()?;
    // we have to do this pointer convert otherwise the rust would complain the exit_container uses
    // mutable reference twice when we were holding the key_data
    // we are sure that the exit_container won't change anything in the key_data, so it's safe to
    // do this.
    let key_data_ptr = key_data.as_ptr();
    let key_data_len = key_data.len();
    //drop(key_data);
    //let _ = key_data;

    verify_or_return_error!(
        key_data_len <= P256SerializedKeypair::capacity(),
        Err(chip_error_buffer_too_small!())
    );

    reader.exit_container(container_type)?;

    unsafe {
        serialized_op_key.bytes()[0..key_data_len]
            .copy_from_slice(slice::from_raw_parts(key_data_ptr, key_data_len));
    }

    return serialized_op_key.set_length(key_data_len);
}

fn sign_with_stored_op_key<Delegate: PersistentStorageDelegate>(
    fabric_index: FabricIndex,
    storage: &mut Delegate,
    message: &[u8],
    out_signature: &mut P256EcdsaSignature,
) -> ChipErrorResult {
    verify_or_return_error!(
        is_valid_fabric_index(fabric_index),
        Err(chip_error_invalid_argument!())
    );
    let mut keypair = P256Keypair::default();
    let mut serialized_keypair = P256SerializedKeypair::default();

    let _ = export_stored_op_key(fabric_index, storage, &mut serialized_keypair)?;

    let _ = keypair.deserialize(&serialized_keypair)?;

    let err = keypair.ecdsa_sign_msg(message, out_signature);

    // clear the keypair, clear will just generate another new keypair which is not used to sign
    // the message
    keypair.clear();

    return err;
}

pub struct PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    m_storage: *mut PA,
    m_pending_fabric_index: FabricIndex,
    //m_pending_keypair: * mut crypto::P256Keypair,
    m_pending_keypair: Option<crypto::P256Keypair>,
    m_is_pending_keypair_active: bool,
    //m_is_externally_owned_keypair: bool,
}

impl<PA> Default for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    fn default() -> Self {
        Self {
            m_storage: ptr::null_mut(),
            m_pending_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_pending_keypair: None,
            m_is_pending_keypair_active: false,
            //m_is_externally_owned_keypair: false
        }
    }
}

impl<PA> PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    pub fn init(&mut self, storage: *mut PA) -> ChipErrorResult {
        verify_or_return_error!(self.m_storage.is_null(), Err(chip_error_incorrect_state!()));
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
        //self.m_is_externally_owned_keypair = false;
        self.m_storage = storage;
        self.m_pending_keypair = None;
        self.m_is_pending_keypair_active = false;

        chip_ok!()
    }

    fn reset_pending_key(&mut self) {
        self.m_pending_keypair = None;
        self.m_is_pending_keypair_active = false;
        self.m_pending_fabric_index = KUNDEFINED_FABRIC_INDEX;
    }
}

impl<PA> OperationalKeystore for PersistentStorageOperationalKeystore<PA>
where
    PA: PersistentStorageDelegate,
{
    fn has_pending_op_keypair(&self) -> bool {
        false
    }

    fn has_op_keypair_for_fabric(&self, fabric_index: FabricIndex) -> bool {
        verify_or_return_error!(self.m_storage.is_null() == false, false);
        verify_or_return_error!(is_valid_fabric_index(fabric_index), false);

        if self.m_is_pending_keypair_active == true
            && (fabric_index == self.m_pending_fabric_index)
            && self.m_pending_keypair.is_some()
        {
            return true;
        }

        let mut buf = SensitiveDataBuffer::<{ op_key_tlv_max_size() }>::default();
        unsafe {
            return (*self.m_storage)
                .sync_get_key_value(
                    DefaultStorageKeyAllocator::fabric_op_key(fabric_index).key_name_str(),
                    buf.bytes(),
                )
                .is_ok();
        }
    }

    fn new_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        out_certificate_siging_request: &mut [u8],
    ) -> Result<usize, ChipError> {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );
        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        // If a key is pending, we cannot generate for a different fabric index until we commit or revert.
        if (self.m_pending_fabric_index != KUNDEFINED_FABRIC_INDEX)
            && (self.m_pending_fabric_index != fabric_index)
        {
            return Err(chip_error_invalid_fabric_index!());
        }

        verify_or_return_error!(
            out_certificate_siging_request.len() >= crypto::K_MIN_CSR_BUFFER_SIZE,
            Err(chip_error_buffer_too_small!())
        );

        // Replace previous pending keypair, if any was previously allocated
        self.reset_pending_key();

        let mut pending_keypair = crypto::P256Keypair::default();
        pending_keypair.initialize(crypto::ECPKeyTarget::Ecdh);

        match pending_keypair
            .new_certificate_signing_request(&mut out_certificate_siging_request[..])
        {
            Ok(csr_length) => {
                self.m_pending_keypair = Some(pending_keypair);
                self.m_pending_fabric_index = fabric_index;
                return Ok(csr_length);
            }
            Err(e) => {
                self.reset_pending_key();
                return Err(e);
            }
        }
    }

    fn activate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        noc_public_key: &crypto::P256PublicKey,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            (is_valid_fabric_index(fabric_index)) && (fabric_index == self.m_pending_fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        if let Some(keypair) = &self.m_pending_keypair {
            verify_or_return_error!(
                keypair.public_key().matches(noc_public_key),
                Err(chip_error_invalid_public_key!())
            );
        } else {
            return Err(chip_error_invalid_fabric_index!());
        }

        self.m_is_pending_keypair_active = true;

        chip_ok!()
    }

    fn commit_op_keypair_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            self.m_pending_keypair.is_some(),
            Err(chip_error_invalid_public_key!())
        );

        verify_or_return_error!(
            (is_valid_fabric_index(fabric_index)) && (fabric_index == self.m_pending_fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        verify_or_return_error!(
            self.m_is_pending_keypair_active == true,
            Err(chip_error_incorrect_state!())
        );

        unsafe {
            store_operational_key(
                fabric_index,
                &mut (*self.m_storage),
                self.m_pending_keypair.as_ref().unwrap(),
            )?;
        }

        self.reset_pending_key();

        chip_ok!()
    }

    fn export_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        out_keypair: &mut crypto::P256SerializedKeypair,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        unsafe {
            return export_stored_op_key(fabric_index, &mut (*self.m_storage), out_keypair);
        }
    }

    fn migrate_op_keypair_for_fabric(
        &mut self,
        fabric_index: FabricIndex,
        operational_keystore: &mut Self,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        let mut serialized_keypair = P256SerializedKeypair::default();

        if !self.has_op_keypair_for_fabric(fabric_index) {
            operational_keystore
                .export_op_keypair_for_fabric(fabric_index, &mut serialized_keypair)?;

            let mut keypair = P256Keypair::default();

            keypair.deserialize(&serialized_keypair)?;
            unsafe {
                match store_operational_key(fabric_index, &mut (*self.m_storage), &keypair) {
                    Err(e) => {
                        keypair.clear();
                        return Err(e);
                    }
                    _ => {}
                }
            }
            match operational_keystore.remove_op_keyapir_for_fabric(fabric_index) {
                Err(e) => {
                    keypair.clear();
                    return Err(e);
                }
                _ => {}
            }
        } else if self.has_op_keypair_for_fabric(fabric_index) {
            operational_keystore.remove_op_keyapir_for_fabric(fabric_index)?;
        }

        chip_ok!()
    }

    fn remove_op_keyapir_for_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        if self.m_pending_keypair.is_some() && self.m_pending_fabric_index == fabric_index {
            self.revert_pending_keypair();
        }

        unsafe {
            return (*self.m_storage)
                .sync_delete_key_value(
                    DefaultStorageKeyAllocator::fabric_op_key(fabric_index).key_name_str(),
                )
                .map_err(|e| {
                    let not_found = chip_error_persisted_storage_value_not_found!();
                    match e {
                        not_found => {
                            chip_error_invalid_fabric_index!()
                        }
                        _ => e,
                    }
                });
        }
    }

    fn revert_pending_keypair(&mut self) {
        if self.m_storage.is_null() {
            return;
        }

        // Just reset the pending key, we never stored anything
        self.reset_pending_key();
    }

    fn supports_sign_with_op_keypair_in_background(&self) -> bool {
        false
    }

    fn sign_with_op_keyapir(
        &self,
        fabric_index: FabricIndex,
        message: &[u8],
        out_signature: &mut crypto::P256EcdsaSignature,
    ) -> ChipErrorResult {
        verify_or_return_error!(
            self.m_storage.is_null() == false,
            Err(chip_error_incorrect_state!())
        );

        verify_or_return_error!(
            is_valid_fabric_index(fabric_index),
            Err(chip_error_invalid_fabric_index!())
        );

        if self.m_is_pending_keypair_active == true && (fabric_index == self.m_pending_fabric_index)
        {
            verify_or_return_error!(
                self.m_pending_keypair.is_some(),
                Err(chip_error_internal!())
            );
            return self
                .m_pending_keypair
                .as_ref()
                .unwrap()
                .ecdsa_sign_msg(message, out_signature);
        }

        unsafe {
            return sign_with_stored_op_key(
                fabric_index,
                &mut (*self.m_storage),
                message,
                out_signature,
            );
        }
    }

    fn allocate_ephemeral_keypair_for_case(&self) -> *mut crypto::P256Keypair {
        // TODO: we don't how to implement this yet
        ptr::null_mut()
    }

    fn release_ephemeral_keypair(keypair: *mut crypto::P256Keypair) {
        // TODO: we don't need this until we have the allocate_ephemeral_keypair_for_case
        // implementation.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::chip_lib::support::{
        default_storage_key_allocator::{DefaultStorageKeyAllocator, StorageKeyName},
        test_persistent_storage::TestPersistentStorage,
    };
    use crate::chip::crypto::{self, P256Keypair, P256PublicKey};
    use crate::chip::chip_lib::core::data_model_types::KMIN_VALID_FABRIC_INDEX;

    type Store = PersistentStorageOperationalKeystore<TestPersistentStorage>;

    fn setup(pa: *mut TestPersistentStorage) -> Store {
        let mut store = Store::default();
        let _ = store.init(pa);
        store
    }

    #[test]
    fn new_op_keypair_for_fabric() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(2, &mut out_csr[..])
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
    }

    #[test]
    fn invalid_fabric_index() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(u8::MAX, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn pending_keypair() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(2, &mut out_csr[..])
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );

        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(3, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn small_csr_buffer() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 0] = [];
        assert_eq!(
            true,
            store
                .new_op_keypair_for_fabric(u8::MAX, &mut out_csr[..])
                .is_err()
        );
    }

    #[test]
    fn activate_op_keyapir() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
    }

    #[test]
    fn activate_op_keyapir_with_wrong_pubkey() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .is_err()
        );
        assert_eq!(false, store.m_is_pending_keypair_active);
    }

    #[test]
    fn store_op_key() {
        let mut pa = TestPersistentStorage::default();
        let mut keypair = crypto::P256Keypair::default();
        let _ = keypair.initialize(crypto::ECPKeyTarget::Ecdh);

        assert_eq!(true, store_operational_key(KMIN_VALID_FABRIC_INDEX, &mut pa, &keypair).is_ok());

        let key = DefaultStorageKeyAllocator::fabric_op_key(KMIN_VALID_FABRIC_INDEX);
        let key_name = key.key_name_str();

        assert_eq!(true, pa.has_key(key_name));
        assert_eq!(true, pa.data_len(key_name) > 0);
    }

    #[test]
    fn commit_op_key() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
        // commit the op key
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        // check we have reset the pending key
        assert_eq!(true, store.m_pending_keypair.is_none());
    }

    #[test]
    fn export_stored_key() {
        let mut pa = TestPersistentStorage::default();
        let mut keypair = crypto::P256Keypair::default();
        let _ = keypair.initialize(crypto::ECPKeyTarget::Ecdh);

        assert_eq!(true, store_operational_key(KMIN_VALID_FABRIC_INDEX, &mut pa, &keypair).is_ok());

        let mut expected_serialized_op_key = P256SerializedKeypair::default();
        let _ = keypair.serialize(&mut expected_serialized_op_key);

        let mut output_serialized_op_key = P256SerializedKeypair::default();
        assert_eq!(
            true,
            export_stored_op_key(KMIN_VALID_FABRIC_INDEX, &mut pa, &mut output_serialized_op_key).is_ok()
        );
        assert_eq!(
            expected_serialized_op_key.const_bytes(),
            output_serialized_op_key.const_bytes()
        );
    }

    #[test]
    fn export_op_key() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
        // commit the op key
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        // check we have reset the pending key
        assert_eq!(true, store.m_pending_keypair.is_none());

        // export the op key
        let mut output_serialized_op_key = P256SerializedKeypair::default();
        assert_eq!(
            true,
            store
                .export_op_keypair_for_fabric(2, &mut output_serialized_op_key)
                .is_ok()
        );
    }

    #[test]
    fn remove_op_key() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
        // commit the op key
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        // removed it
        assert_eq!(true, store.remove_op_keyapir_for_fabric(2).is_ok());

        // try to export it, should fail
        let mut output_serialized_op_key = P256SerializedKeypair::default();
        assert_eq!(
            true,
            store
                .export_op_keypair_for_fabric(2, &mut output_serialized_op_key)
                .is_err()
        );
    }

    #[test]
    fn sign_message() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
        // commit the op key
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        let mut sig = P256EcdsaSignature::default();

        assert_eq!(
            true,
            sign_with_stored_op_key(2, &mut pa, &[1, 2, 3, 4], &mut sig).is_ok()
        );
    }

    #[test]
    fn sign_message_with_pending_keypair() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);

        let mut sig_with_pending_keypair = P256EcdsaSignature::default();
        // sign with pending key
        assert_eq!(
            true,
            store
                .sign_with_op_keyapir(2, &[1, 2, 3, 4], &mut sig_with_pending_keypair)
                .is_ok()
        );
        // commit it
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        let mut sig_with_stored_keypair = P256EcdsaSignature::default();

        // sign with pending key
        assert_eq!(
            true,
            store
                .sign_with_op_keyapir(2, &[1, 2, 3, 4], &mut sig_with_stored_keypair)
                .is_ok()
        );

        assert_eq!(
            sig_with_pending_keypair.const_bytes(),
            sig_with_stored_keypair.const_bytes()
        );
    }

    #[test]
    fn migrate_to_other() {
        let mut pa = TestPersistentStorage::default();
        let mut store = setup(core::ptr::addr_of_mut!(pa));
        let mut out_csr: [u8; 256] = [0; 256];
        let _ = store.new_op_keypair_for_fabric(2, &mut out_csr[..]);
        assert_eq!(false, store.m_is_pending_keypair_active);
        // create the noc public key
        let mut noc_pubkey: P256PublicKey = P256PublicKey::default();
        if let Some(keypair) = &store.m_pending_keypair {
            noc_pubkey =
                P256PublicKey::default_with_raw_value(keypair.public_key().const_bytes());
        } else {
            assert!(false);
        }
        // activate the op key
        assert_eq!(
            true,
            store
                .activate_op_keypair_for_fabric(2, &noc_pubkey)
                .inspect_err(|e| {
                    println!("err is {}", e);
                })
                .is_ok()
        );
        assert_eq!(true, store.m_is_pending_keypair_active);
        // commit the op key
        assert_eq!(
            true,
            store
                .commit_op_keypair_for_fabric(2)
                .inspect_err(|e| {
                    println!("commit err is {}", e);
                })
                .is_ok()
        );

        let mut pa1 = TestPersistentStorage::default();
        let mut store1 = setup(core::ptr::addr_of_mut!(pa1));
        // ensure there is no fabric index = 2
        assert_eq!(false, store1.has_op_keypair_for_fabric(2));
        // migrate
        assert_eq!(
            true,
            store1.migrate_op_keypair_for_fabric(2, &mut store).is_ok()
        );
        // chekc store1 has it
        assert_eq!(true, store1.has_op_keypair_for_fabric(2));
        // chekc store losts it
        assert_eq!(false, store.has_op_keypair_for_fabric(2));
    }
} // end of mod tests
