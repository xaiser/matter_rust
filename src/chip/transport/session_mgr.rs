use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
                node_id::{KUNDEFINED_NODE_ID, is_operational_node_id},
            },
            support::{
                iterators::Loop,
            },
        },
        credentials::{
            self, fabric_table::{self , FabricTable},
        },
        crypto::{
            self, session_keystore::SessionKeystore, P256PublicKey, crypto_pal::ECPKey,
        },
        messaging::{
            reliable_message_protocol_config::ReliableMessageProtocolConfig,
        },
        transport::{
            raw::{
                peer_address::PeerAddress,
                base::MessageTransportContext,
            },
            secure_session_table::SecureSessionTable,
            unauthenticated_session::UnauthenticatedSessionTable,
            group_peer_message_counter::{GroupOutgoingCounters, GroupPeerTable},
            session_message_delegate::SessionMessageDelegate,
            transport_mgr::TransportMgrDelegate,
            transport_mgr_base::TransportMgrBase,
            message_counter_manager_interface::MessageCounterManagerInterface,
            message_counter::MessageCounter,
            session::{SharedSession, SessionHandle, SessionBase},
            secure_session::{SecureSession, AsRef, mark_for_evication},
        },
        ScopedNodeId, FabricIndex, FabricId, NodeId,
    },
    ChipError,
    ChipErrorResult,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_invalid_fabric_index,
    chip_error_incorrect_state,
    chip_error_invalid_argument,
    verify_or_return_error,
    verify_or_return_value,
    //verify_or_die,
};

use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::system::LayerImpl;
use crate::chip::transport::raw::message_header::{PacketHeader, PayloadHeader};

use core::ptr::{self, NonNull};

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use core::str::FromStr;

fn group_peer_table() -> NonNull<GroupPeerTable> {
    static mut G_GROUP_PEER_TABLE: GroupPeerTable = GroupPeerTable::new();

    unsafe {
        return NonNull::new_unchecked(ptr::addr_of_mut!(G_GROUP_PEER_TABLE));
    }
}

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

pub struct SessionManager<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate + 'd,
    OK: crypto::OperationalKeystore + 'd,
    OCS: credentials::OperationalCertificateStore + 'd,
    SKS: SessionKeystore + 'd,
    SMD: SessionMessageDelegate + 'd,
    TMB: TransportMgrBase + 'd,
    MCMI: MessageCounterManagerInterface + 'd,
{
    m_system_layer: Option<NonNull<LayerImpl>>,
    m_fabric_table: Option<NonNull<FabricTable<'d, PSD, OK, OCS>>>,
    m_session_key_storage: Option<NonNull<SKS>>,
    m_unauthenticated_sessions: UnauthenticatedSessionTable,
    m_secure_sessions: SecureSessionTable,
    m_state: State,
    m_group_clinent_counter: GroupOutgoingCounters<PSD>,
    m_cb: Option<NonNull<SMD>>,
    m_transport_mgr: Option<NonNull<TMB>>,
    m_message_counter_manager: Option<NonNull<MCMI>>,
    m_global_unencrypted_message_counter: MessageCounter,
    // TODO: use linkedlist
    m_next_table_delegate: Option<*mut (dyn fabric_table::Delegate<'d, PSD, OK, OCS> + 'd)>,
}

impl<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI> Drop for SessionManager<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate + 'd,
    OK: crypto::OperationalKeystore + 'd,
    OCS: credentials::OperationalCertificateStore + 'd,
    SKS: SessionKeystore + 'd,
    SMD: SessionMessageDelegate + 'd,
    TMB: TransportMgrBase + 'd,
    MCMI: MessageCounterManagerInterface + 'd,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI> SessionManager<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate + 'd,
    OK: crypto::OperationalKeystore + 'd,
    OCS: credentials::OperationalCertificateStore + 'd,
    SKS: SessionKeystore + 'd,
    SMD: SessionMessageDelegate + 'd,
    TMB: TransportMgrBase + 'd,
    MCMI: MessageCounterManagerInterface + 'd,
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
            m_next_table_delegate: None,
        }
    }

    pub fn init(&mut self, system_layer: Option<NonNull<LayerImpl>>, transport_mgr: Option<NonNull<TMB>>, 
        message_counter_manager: Option<NonNull<MCMI>>,
        storage_delegate: Option<NonNull<PSD>>, mut fabric_table: Option<NonNull<FabricTable<'d, PSD, OK, OCS>>>, 
        session_keystore: Option<NonNull<SKS>>) -> ChipErrorResult
    {
        verify_or_return_error!(self.m_state == State::KnotReady, Err(chip_error_incorrect_state!()));

        if let Some(table) = fabric_table.as_mut() {
            unsafe {
                table.as_mut().add_fabric_delegate(Some(ptr::addr_of_mut!(*self)))?;
            }
        } else {
            return Err(chip_error_invalid_argument!());
        }

        self.m_state = State::Kinitialized;
        self.m_system_layer = system_layer;
        self.m_transport_mgr = transport_mgr;
        self.m_message_counter_manager = message_counter_manager;
        self.m_fabric_table = fabric_table;
        self.m_session_key_storage = session_keystore;

        self.m_secure_sessions.init();

        self.m_global_unencrypted_message_counter.init();

        self.m_group_clinent_counter = GroupOutgoingCounters::new_with(storage_delegate);
        self.m_group_clinent_counter.init()?;

        unsafe {
            self.m_transport_mgr.as_mut().unwrap().as_mut().set_session_manager(ptr::addr_of_mut!(*self) as _);
        }

        chip_ok!()
    }

    pub fn shutdown(&mut self) {
        if let Some(mut table) = self.m_fabric_table.take() {
            unsafe {
                table.as_mut().remove_fabric_delegate(Some(ptr::addr_of_mut!(*self)));
            }
        }

        self.m_state = State::KnotReady;

        // Just in case some consumer forgot to do it, expire all our secure
        // sessions.  Note that this stands a good chance of crashing with a
        // null-deref if there are in fact any secure sessions left, since they will
        // try to notify their exchanges, which will then try to operate on
        // partially-shut-down objects.
        self.expire_all_secure_sessions();

        // We don't have a safe way to check or affect the state of our
        // mUnauthenticatedSessions.  We can only hope they got shut down properly.
        
        self.m_message_counter_manager = None;

        self.m_system_layer = None;
        self.m_transport_mgr = None;
        self.m_cb = None;
    }

    pub fn set_delegate(&mut self, cb: NonNull<SMD>) {
        self.m_cb = Some(cb);
    }

    pub fn fabric_removed(&mut self, fabric_index: FabricIndex) {
        unsafe {
            let _ = group_peer_table().as_mut().fabric_removed(fabric_index);
        }
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
        let (target_pub_key, target_fabric_id) = self.get_fabric_and_pub_key(node.get_fabric_index())?;
        self.m_secure_sessions.for_each_session(|session| {
            if let Ok(session_ref) = session.try_borrow() {
                let (is_case_session, peer_node_id) = {
                    let secure_session: Option<&SecureSession> = session_ref.as_ref();
                    if let Some(ss) = secure_session {
                        (ss.is_case_session(), ss.get_peer_node_id())
                    } else {
                        (false, KUNDEFINED_NODE_ID)
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

                let compare_fabric_option = unsafe {
                    if let Some(table) = self.m_fabric_table.as_ref() {
                        table.as_ref().find_fabric_with_index(session_ref.get_fabric_index())
                    } else {
                        None
                    }
                };

                if let Some(compare_fabric) = compare_fabric_option &&
                    let Ok(compare_pub_key) = compare_fabric.fetch_root_pubkey() 
                {
                    if compare_pub_key.matches(&target_pub_key) && target_fabric_id == compare_fabric.get_fabric_id() &&
                        peer_node_id == node.get_node_id() {
                            f(session);
                    }
                }
            }

            Loop::Continue
        });


        chip_ok!()
    }

    pub fn for_each_matching_session_on_logical_fabric_const<F>(&self, node: &ScopedNodeId, mut f: F) -> ChipErrorResult
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        let (target_pub_key, target_fabric_id) = self.get_fabric_and_pub_key(node.get_fabric_index())?;
        self.m_secure_sessions.for_each_session_const(|session| {
            if let Ok(session_ref) = session.try_borrow() {
                let (is_case_session, peer_node_id) = {
                    let secure_session: Option<&SecureSession> = session_ref.as_ref();
                    if let Some(ss) = secure_session {
                        (ss.is_case_session(), ss.get_peer_node_id())
                    } else {
                        (false, KUNDEFINED_NODE_ID)
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

                let compare_fabric_option = unsafe {
                    if let Some(table) = self.m_fabric_table.as_ref() {
                        table.as_ref().find_fabric_with_index(session_ref.get_fabric_index())
                    } else {
                        None
                    }
                };

                if let Some(compare_fabric) = compare_fabric_option &&
                    let Ok(compare_pub_key) = compare_fabric.fetch_root_pubkey() 
                {
                    if compare_pub_key.matches(&target_pub_key) && target_fabric_id == compare_fabric.get_fabric_id() &&
                        peer_node_id == node.get_node_id() {
                            f(session);
                    }
                }
            }

            Loop::Continue
        });


        chip_ok!()
    }

    pub fn for_each_matching_fabric_index_session_on_logical_fabric<F>(&mut self, fabric_index: FabricIndex, mut f: F) -> ChipErrorResult
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        let (target_pub_key, target_fabric_id) = self.get_fabric_and_pub_key(fabric_index)?;
        self.m_secure_sessions.for_each_session(|session| {
            if let Ok(session_ref) = session.try_borrow() {
                let (is_case_session, peer_node_id) = {
                    let secure_session: Option<&SecureSession> = session_ref.as_ref();
                    if let Some(ss) = secure_session {
                        (ss.is_case_session(), ss.get_peer_node_id())
                    } else {
                        (false, KUNDEFINED_NODE_ID)
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

                let compare_fabric_option = unsafe {
                    if let Some(table) = self.m_fabric_table.as_ref() {
                        table.as_ref().find_fabric_with_index(session_ref.get_fabric_index())
                    } else {
                        None
                    }
                };

                if let Some(compare_fabric) = compare_fabric_option &&
                    let Ok(compare_pub_key) = compare_fabric.fetch_root_pubkey() 
                {
                    if compare_pub_key.matches(&target_pub_key) && target_fabric_id == compare_fabric.get_fabric_id() {
                            f(session);
                    }
                }
            }

            Loop::Continue
        });


        chip_ok!()
    }

    pub fn for_each_matching_fabric_index_session_on_logical_fabric_const<F>(&self, fabric_index: FabricIndex, mut f: F) -> ChipErrorResult
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        let (target_pub_key, target_fabric_id) = self.get_fabric_and_pub_key(fabric_index)?;
        self.m_secure_sessions.for_each_session_const(|session| {
            if let Ok(session_ref) = session.try_borrow() {
                let (is_case_session, peer_node_id) = {
                    let secure_session: Option<&SecureSession> = session_ref.as_ref();
                    if let Some(ss) = secure_session {
                        (ss.is_case_session(), ss.get_peer_node_id())
                    } else {
                        (false, KUNDEFINED_NODE_ID)
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

                let compare_fabric_option = unsafe {
                    if let Some(table) = self.m_fabric_table.as_ref() {
                        table.as_ref().find_fabric_with_index(session_ref.get_fabric_index())
                    } else {
                        None
                    }
                };

                if let Some(compare_fabric) = compare_fabric_option &&
                    let Ok(compare_pub_key) = compare_fabric.fetch_root_pubkey() 
                {
                    if compare_pub_key.matches(&target_pub_key) && target_fabric_id == compare_fabric.get_fabric_id() {
                            f(session);
                    }
                }
            }

            Loop::Continue
        });


        chip_ok!()
    }

    pub fn create_unauthenticated_session(&mut self, peer_address: &PeerAddress, config: &ReliableMessageProtocolConfig) -> Option<SessionHandle> {
        let mut ephemeral_initiator_node_id = KUNDEFINED_NODE_ID;
        while !is_operational_node_id(ephemeral_initiator_node_id) {
            ephemeral_initiator_node_id = crypto::get_rand_u64() as NodeId;
        }

        return self.m_unauthenticated_sessions.alloc_initiator(ephemeral_initiator_node_id, peer_address, config).ok();
    }

    fn get_fabric_and_pub_key(&self, fabric_index: FabricIndex) -> Result<(P256PublicKey, FabricId), ChipError> {
        let target_fabric = unsafe { self.m_fabric_table.as_ref().ok_or(chip_error_invalid_fabric_index!())?.as_ref().
            find_fabric_with_index(fabric_index).ok_or(chip_error_invalid_fabric_index!())?
        };
        let target_pub_key = target_fabric.fetch_root_pubkey()?;

        Ok((target_pub_key, target_fabric.get_fabric_id()))
    }

    fn expire_all_secure_sessions(&mut self) {
        self.m_secure_sessions.for_each_session(|shared_session| {
            let handle = SessionHandle::new_with(shared_session);
            mark_for_evication(handle);

            Loop::Continue
        });
    }

    fn is_control_message(payload_header: &PayloadHeader) -> bool {
        payload_header.has_message_type(crate::chip::protocols::secure_channel::MsgType::MsgCounterSyncReq.into()) ||
        payload_header.has_message_type(crate::chip::protocols::secure_channel::MsgType::MsgCounterSyncRsp.into())
    }
}

impl<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI> fabric_table::Delegate<'d, PSD, OK, OCS> for SessionManager<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate + 'd,
    OK: crypto::OperationalKeystore + 'd,
    OCS: credentials::OperationalCertificateStore + 'd,
    SKS: SessionKeystore + 'd,
    SMD: SessionMessageDelegate + 'd,
    TMB: TransportMgrBase + 'd,
    MCMI: MessageCounterManagerInterface + 'd,
{
    fn fabric_will_be_removed(
        &mut self,
        _fabric_table: &FabricTable<PSD, OK, OCS>,
        _fabric_index: FabricIndex,
    ) {}

    fn on_fabric_removed(
        &mut self,
        _fabric_table: &FabricTable<PSD, OK, OCS>,
        _fabric_index: FabricIndex,
    ) {}

    fn on_fabric_updated(
        &mut self,
        _fabric_table: &FabricTable<PSD, OK, OCS>,
        _fabric_index: FabricIndex,
    ) {}

    fn on_fabric_commit(
        &mut self,
        _fabric_table: &FabricTable<PSD, OK, OCS>,
        _fabric_index: FabricIndex,
    ) {}

    fn next(&self) -> Option<*mut (dyn fabric_table::Delegate<'d, PSD, OK, OCS> + 'd)> {
        return self.m_next_table_delegate.clone();
    }

    fn remove_next(&mut self) {
        self.m_next_table_delegate = None;
    }

    fn set_next(&mut self, next: Option<*mut (dyn fabric_table::Delegate<'d, PSD, OK, OCS> + 'd)>) {
        self.m_next_table_delegate = next;
    }
}

impl<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI> TransportMgrDelegate for SessionManager<'d, PSD, OK, OCS, SKS, SMD, TMB, MCMI>
where
    PSD: PersistentStorageDelegate + 'd,
    OK: crypto::OperationalKeystore + 'd,
    OCS: credentials::OperationalCertificateStore + 'd,
    SKS: SessionKeystore + 'd,
    SMD: SessionMessageDelegate + 'd,
    TMB: TransportMgrBase + 'd,
    MCMI: MessageCounterManagerInterface + 'd,
{
    fn on_message_received(
        &mut self,
        _source: PeerAddress,
        _msg_buf: PacketBufferHandle,
        _ctext: *const MessageTransportContext,
    )
    {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                support::{
                    test_persistent_storage::TestPersistentStorage,
                },
            },
            credentials::persistent_storage_op_cert_store::PersistentStorageOpCertStore,
            crypto::{
                raw_session_keystore::RawKeySessionKeystore,
                persistent_storage_operational_keystore::PersistentStorageOperationalKeystore,
            },
            inet::{
                inet_layer::EndPointManager,
                test_end_point::TestEndPointManager,
            },
            transport::{
                raw::{
                    test::{Test, TestListenParameter},
                },
                transport_mgr::{TransportMgrReceiver, TransportMgr},
                session_message_delegate::DuplicateMessage,
            },
            platform::global::system_layer,
            system::system_layer::Layer,
        },
    };

    type OCS = PersistentStorageOpCertStore<TestPersistentStorage>;
    type OK = PersistentStorageOperationalKeystore<TestPersistentStorage>;

    struct TestSessionMessageDelegate(bool);

    impl TestSessionMessageDelegate {
        pub const fn new() -> Self {
            TestSessionMessageDelegate(false)
        }

        pub fn reset(&mut self) {
            self.0 = false;
        }
    }

    impl SessionMessageDelegate for TestSessionMessageDelegate {
        fn on_message_received(&mut self, _packet_header: &PacketHeader, _payload_header: &PayloadHeader,
            _session: &SessionHandle, _is_duplicate: DuplicateMessage, _msg_buf: &mut PacketBufferHandle) {
            self.0 = true;
        }
    }

    struct SessionMgrOp<'a> {
        session_mgr: * mut TestSessionManager<'a>,
    }

    impl TransportMgrDelegate for SessionMgrOp<'_>{
        fn on_message_received(
            &mut self,
            source: PeerAddress,
            msg_buf: PacketBufferHandle,
            ctext: *const MessageTransportContext,
        )
        {
            unsafe {
                self.session_mgr.as_mut().unwrap().on_message_received(source, msg_buf, ctext);
            }
        }
    }

    type TestTransportMgr<'a> = TransportMgr<
        (
            Test<TransportMgrReceiver<SessionMgrOp<'a>>>,
        ),
        SessionMgrOp<'a>,
    >;

    struct TestMessageCounterMgr;

    impl TestMessageCounterMgr {
        pub const fn new() -> Self {
            TestMessageCounterMgr
        }
    }

    impl MessageCounterManagerInterface for TestMessageCounterMgr {
        fn start_sync(&mut self, _session: &SessionHandle, _state: &mut SessionHandle) -> ChipErrorResult {
            chip_ok!()
        }


        fn queue_received_message_and_start_sync(&mut self, packet_header: &PacketHeader, session: &SessionHandle, state: &mut SessionHandle,
            peer_address: &PeerAddress) -> Result<PacketBufferHandle, ChipError>
        {
            Ok(PacketBufferHandle::default())
        }
    }

    type TestSessionManager<'a> = SessionManager<'a, TestPersistentStorage, OK, OCS, RawKeySessionKeystore,
       TestSessionMessageDelegate, TestTransportMgr<'a>, TestMessageCounterMgr>;

    type TestFabricTable<'d> = FabricTable<'d, TestPersistentStorage, OK, OCS>;

    fn setup<'a>() -> Result<(*mut crate::chip::system::LayerImpl, TestEndPointManager, TestTransportMgr<'a>, TestMessageCounterMgr,
        TestPersistentStorage, TestFabricTable<'a>, RawKeySessionKeystore, TestSessionManager<'a>), ChipError>
    {
        let system = system_layer();
        unsafe {
            (*system).init();
        }
        // init transport mgr
        let mut end_point_mgr = TestEndPointManager::default();
        end_point_mgr.init(system);
        let mut transport_mgr = TestTransportMgr::default();
        let mut message_counter_manager = TestMessageCounterMgr::new();
        //let test_param = TestListenParameter::default(ptr::addr_of_mut!(end_point_mgr));
        
        let mut pa = TestPersistentStorage::default();
        let mut table = TestFabricTable::default();
        let mut session_key_store = RawKeySessionKeystore::new();

        let mut sm = TestSessionManager::new();

        sm.init(NonNull::new(system), NonNull::new(ptr::addr_of_mut!(transport_mgr)), NonNull::new(ptr::addr_of_mut!(message_counter_manager)),
           NonNull::new(ptr::addr_of_mut!(pa)), NonNull::new(ptr::addr_of_mut!(table)), 
           NonNull::new(ptr::addr_of_mut!(session_key_store)))?;

        return Ok((system, end_point_mgr, transport_mgr, message_counter_manager, pa, table, session_key_store, sm));
    }

    #[test]
    fn init() {
        assert!(setup().is_ok());
    }

    #[test]
    fn init_no_table() {
        let system = system_layer();
        unsafe {
            (*system).init();
        }
        // init transport mgr
        let mut end_point_mgr = TestEndPointManager::default();
        end_point_mgr.init(system);
        let mut transport_mgr = TestTransportMgr::default();
        let mut message_counter_manager = TestMessageCounterMgr::new();
        //let test_param = TestListenParameter::default(ptr::addr_of_mut!(end_point_mgr));
        
        let mut pa = TestPersistentStorage::default();
        //let mut table = TestFabricTable::default();
        let mut session_key_store = RawKeySessionKeystore::new();

        let mut sm = TestSessionManager::new();

        assert!(!sm.init(NonNull::new(system), NonNull::new(ptr::addr_of_mut!(transport_mgr)), NonNull::new(ptr::addr_of_mut!(message_counter_manager)),
           NonNull::new(ptr::addr_of_mut!(pa)), None,
           NonNull::new(ptr::addr_of_mut!(session_key_store))).is_ok());
    }

    #[test]
    fn init_no_storage() {
        let system = system_layer();
        unsafe {
            (*system).init();
        }
        // init transport mgr
        let mut end_point_mgr = TestEndPointManager::default();
        end_point_mgr.init(system);
        let mut transport_mgr = TestTransportMgr::default();
        let mut message_counter_manager = TestMessageCounterMgr::new();
        //let test_param = TestListenParameter::default(ptr::addr_of_mut!(end_point_mgr));
        
        //let mut pa = TestPersistentStorage::default();
        let mut table = TestFabricTable::default();
        let mut session_key_store = RawKeySessionKeystore::new();

        let mut sm = TestSessionManager::new();

        assert!(!sm.init(NonNull::new(system), NonNull::new(ptr::addr_of_mut!(transport_mgr)), NonNull::new(ptr::addr_of_mut!(message_counter_manager)),
           None, NonNull::new(ptr::addr_of_mut!(table)), 
           NonNull::new(ptr::addr_of_mut!(session_key_store))).is_ok());
    }
} // end of mod tests
