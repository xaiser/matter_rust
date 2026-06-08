use crate::{
    chip::{
        chip_lib::{
            core::chip_persistent_storage_delegate::PersistentStorageDelegate,
        },
        credentials::{
            self, fabric_table::FabricTable,
        },
        crypto::{self, session_keystore::SessionKeystore},
        transport::{
            secure_session_table::SecureSessionTable,
            unauthenticated_session::UnauthenticatedSessionTable,
            group_peer_message_counter::GroupOutgoingCounters,
            session_message_delegate::SessionMessageDelegate,
            transport_mgr_base::TransportMgrBase,
            message_counter_manager_interface::MessageCounterManagerInterface,
            message_counter::MessageCounter,
        },
    },
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
}
