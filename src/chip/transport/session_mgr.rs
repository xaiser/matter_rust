use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
            },
            support::{
                iterators::Loop,
            },
        },
        credentials::{
            self, fabric_table::{FabricTable, FabricInfo},
        },
        crypto::{self, session_keystore::SessionKeystore, P256PublicKey},
        transport::{
            secure_session_table::SecureSessionTable,
            unauthenticated_session::UnauthenticatedSessionTable,
            group_peer_message_counter::GroupOutgoingCounters,
            session_message_delegate::SessionMessageDelegate,
            transport_mgr_base::TransportMgrBase,
            message_counter_manager_interface::MessageCounterManagerInterface,
            message_counter::MessageCounter,
            session::{SharedSession, SessionBase},
            secure_session::{SecureSession, AsRef},
        },
        ScopedNodeId, FabricIndex,
    },
    ChipError,
    ChipErrorResult,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_invalid_fabric_index,
    verify_or_die,
};

use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::system::LayerImpl;
use crate::chip::transport::raw::message_header::PacketHeader;

use core::ptr::NonNull;

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::str::FromStr;

/*
 *    The State of a secure transport object.
 */
#[derive(Copy, Clone, PartialEq)]
enum State {
    KnotReady,
    Kinitialized,
}

#[repr(u8)]
pub enum TransportPayloadCapability {
    KMrpPayload,
    KLargePayload,
    KMrpOrTcpCompatiablePayload,
}

#[derive(Clone)]
pub struct EncryptedPacketBufferHandle {
    m_packet_buffer_handle: PacketBufferHandle,
}

impl Default for EncryptedPacketBufferHandle {
    fn default() -> Self {
        EncryptedPacketBufferHandle::const_default()
    }
}

impl EncryptedPacketBufferHandle {
    pub const fn const_default() -> Self {
        Self {
            m_packet_buffer_handle: PacketBufferHandle::const_default(),
        }
    }

    pub fn get_raw(&mut self) -> &mut PacketBufferHandle {
        return &mut self.m_packet_buffer_handle;
    }

    pub fn has_chained_buffer(&self) -> bool {
        return self.m_packet_buffer_handle.has_chained_buffer();
    }

    pub fn get_message_counter(&self) -> u32 {
        let mut header: PacketHeader = PacketHeader::default();
        let mut header_size: u16 = 0;
        unsafe {
            let err = header.decode_with_raw(
                (*self.m_packet_buffer_handle.get_raw()).start(),
                (*self.m_packet_buffer_handle.get_raw()).data_len() as usize,
                &mut header_size,
            );

            if err.is_ok() {
                return header.get_message_counter();
            }

            chip_log_error!(
                Inet,
                "fail to decode EncryptedPacketBufferHandle header {}",
                err.err().unwrap()
            );
        }

        0
    }

    pub fn mark_encrypted(buffer: PacketBufferHandle) -> Self {
        Self {
            m_packet_buffer_handle: buffer,
        }
    }

    pub fn cast_to_writable(&mut self) -> PacketBufferHandle {
        return self.m_packet_buffer_handle.retain().unwrap();
    }
}

pub struct SessionManager<'a, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate,
    OK: crypto::OperationalKeystore,
    OCS: credentials::OperationalCertificateStore,
    SKS: SessionKeystore,
    SMD: SessionMessageDelegate,
    TMB: TransportMgrBase,
    MCMI: MessageCounterManagerInterface,
{
    m_system_layer: Option<NonNull<LayerImpl>>,
    m_fabric_table: Option<NonNull<FabricTable<'a, PSD, OK, OCS>>>,
    m_session_key_storage: Option<NonNull<SKS>>,
    m_unauthenticated_sessions: UnauthenticatedSessionTable,
    m_secure_sessions: SecureSessionTable,
    m_state: State,
    m_group_clinent_counter: GroupOutgoingCounters<PSD>,
    m_cb: Option<NonNull<SMD>>,
    m_transport_mgr: Option<NonNull<TMB>>,
    m_message_counter_manager: Option<NonNull<MCMI>>,
    m_global_unencrypted_message_counter: MessageCounter,
}

impl<'a, PSD, OK, OCS, SKS, SMD, TMB, MCMI> SessionManager<'a, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate,
    OK: crypto::OperationalKeystore,
    OCS: credentials::OperationalCertificateStore,
    SKS: SessionKeystore,
    SMD: SessionMessageDelegate,
    TMB: TransportMgrBase,
    MCMI: MessageCounterManagerInterface,
{
    pub const fn new() -> Self {
        Self {
            m_system_layer: None,
            m_fabric_table: None,
            m_session_key_storage: None,
            m_unauthenticated_sessions: UnauthenticatedSessionTable::new(),
            m_secure_sessions: SecureSessionTable::new(),
            m_state: State::KnotReady,
            m_group_clinent_counter: GroupOutgoingCounters::<PSD>::new(),
            m_cb: None,
            m_transport_mgr: None,
            m_message_counter_manager: None,
            m_global_unencrypted_message_counter: MessageCounter::new_global_unencrypted(),
        }
    }

    pub fn set_delegate(&mut self, cb: NonNull<SMD>) {
        self.m_cb = Some(cb);
    }

    pub fn for_each_matching_session<F>(&mut self, node: &ScopedNodeId, mut f: F)
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        self.m_secure_sessions.for_each_session(|session| {
            if session.try_borrow().is_ok_and(|session_ref| session_ref.get_peer() == *node) {
                f(session);
            }

            Loop::Continue
        });
    }

    pub fn for_each_matching_session_const<F>(&self, node: &ScopedNodeId, mut f: F)
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        self.m_secure_sessions.for_each_session_const(|session| {
            if session.try_borrow().is_ok_and(|session_ref| session_ref.get_peer() == *node) {
                f(session);
            }

            Loop::Continue
        });
    }

    pub fn for_each_matching_fabric_index_session<F>(&mut self, fabric_index: FabricIndex, mut f: F)
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        self.m_secure_sessions.for_each_session(|session| {
            if session.try_borrow().is_ok_and(|session_ref| session_ref.get_fabric_index() == fabric_index) {
                f(session);
            }

            Loop::Continue
        });
    }

    pub fn for_each_matching_fabric_index_session_const<F>(&self, fabric_index: FabricIndex, mut f: F)
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        self.m_secure_sessions.for_each_session_const(|session| {
            if session.try_borrow().is_ok_and(|session_ref| session_ref.get_fabric_index() == fabric_index) {
                f(session);
            }

            Loop::Continue
        });
    }

    pub fn for_each_matching_session_on_logical_fabric<F>(&mut self, node: &ScopedNodeId, mut f: F) -> ChipErrorResult
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        let (target_pub_key, target_fabric) = self.get_fabric_and_pub_key(node.get_fabric_index())?;
        self.m_secure_sessions.for_each_session(|session| {
            if let Ok(session_ref) = session.try_borrow() {
                let is_case_session = {
                    let secure_session: Option<&SecureSession> = session_ref.as_ref();
                    if let Some(ss) = secure_session {
                        ss.is_case_session()
                    } else {
                        false
                    }
                };

                //
                // It's entirely possible to either come across a PASE session OR, a CASE session
                // that has yet to be activated (i.e a CASEServer holding onto a SecureSession object
                // waiting for a Sigma1 message to arrive). Let's skip those.
                //
                if !is_case_session || (session_ref.get_fabric_index() == KUNDEFINED_FABRIC_INDEX) {
                    return Loop::Continue;
                }

                let compare_fabric = unsafe { self.m_fabric_table.as_ref().ok_or(chip_error_invalid_fabric_index!())?.as_ref().
                    find_fabric_with_index(fabric_index).ok_or(chip_error_invalid_fabric_index!())?
                };
                let target_pub_key = target_fabric.fetch_root_pubkey()?;

            }

            Loop::Continue
        });


        chip_ok!()
    }


    fn get_fabric_and_pub_key(&self, fabric_index: FabricIndex) -> Result<(P256PublicKey, &FabricInfo<'_>), ChipError> {
        let target_fabric = unsafe { self.m_fabric_table.as_ref().ok_or(chip_error_invalid_fabric_index!())?.as_ref().
            find_fabric_with_index(fabric_index).ok_or(chip_error_invalid_fabric_index!())?
        };
        let target_pub_key = target_fabric.fetch_root_pubkey()?;

        Ok((target_pub_key, target_fabric))
    }
}
