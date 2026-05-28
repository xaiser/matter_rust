#![allow(dead_code)]
use crate::{
    chip::{
        access::{self, subject_descriptor::SubjectDescriptor},
        ble::ble_config::BTP_ACK_TIMEOUT_MS,
        chip_lib::core::{
            case_auth_tag::CATValues,
            node_id::{KUNDEFINED_NODE_ID, is_operational_node_id, is_pake_key_id},
            data_model_types::KUNDEFINED_FABRIC_INDEX,
        },
        transport::{
            session::{
                SessionType, SessionHolderList, SessionBase, new_session_holder_list, SessionBasePrivate, SessionHandle
            },
            secure_session_table::SecureSessionTable,
            raw::peer_address::{self, PeerAddress},
            crypto_context::CryptoContext,
        },
        messaging::{
            session_parameters::SessionParameters,
            reliable_message_protocol_config::ReliableMessageProtocolConfig,
        },
        system::system_clock::{Timestamp, Seconds, Milliseconds, get_monotonic_timestamp},
        ScopedNodeId, NodeId, FabricIndex,
    },
};

use crate::{
    ChipErrorResult,
    //ChipError,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    //chip_error_no_memory,
    //chip_error_incorrect_state,
    chip_error_invalid_argument,
    //chip_error_duplicate_message_received,
    //chip_error_internal,
    verify_or_die,
    //verify_or_return_error,
    //verify_or_return_value,
};

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_progress;
use crate::chip_log_detail;
use core::str::FromStr;

use core::cell::OnceCell;
use core::ptr::{self, NonNull};
use core::fmt;

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut SecureSession>;
}

pub trait AsRef {
    fn as_ref(&self) -> Option<&SecureSession>;
}

#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum State {
    //
    // Denotes a secure session object that is internally
    // reserved by the stack before and during session establishment.
    //
    // Although the stack can tolerate eviction of these (releasing one
    // out from under the holder would exhibit as CHIP_ERROR_INCORRECT_STATE
    // during CASE or PASE), intent is that we should not and would leave
    // these untouched until CASE or PASE complete.
    //
    // In this state, the reference count is held by the PairingSession.
    //
    Kestablishing = 1,

    //
    // The session is active, ready for use. When transitioning to this state via Activate, the
    // reference count is incremented by 1, and will subsequently be decremented
    // by 1 when MarkForEviction is called. This ensures the session remains resident
    // and active for future use even if there currently are no references to it.
    //
    Kactive = 2,

    //
    // The session is temporarily disabled due to suspicion of a loss of synchronization
    // with the session state on the peer (e.g transport failure).
    // In this state, no new outbound exchanges can be created. However, if we receive valid messages
    // again on this session, we CAN mark this session as being active again.
    //
    // Transitioning to this state does not detach any existing SessionHolders.
    //
    // In addition to any existing SessionHolders holding a reference to this session, the SessionManager
    // maintains a reference as well to the session that will only be relinquished when MarkForEviction is called.
    //
    Kdefunct = 3,

    //
    // The session has been marked for eviction and is pending deallocation. All SessionHolders would have already
    // been detached in a previous call to MarkForEviction. Future SessionHolders will not be able to attach to
    // this session.
    //
    // When all SessionHandles go out of scope, the session will be released automatically.
    //
    KpendingEviction = 4,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Kestablishing => {
                write!(f, "Kestablishing")
            },
            State::Kactive => {
                write!(f, "Kactive")
            },
            State::Kdefunct => {
                write!(f, "Kdefunct")
            },
            State::KpendingEviction => {
                write!(f, "KpendingEviction")
            },
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Type {
    Kpase = 1,
    Kcase = 2,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum EvicationOp {
    Knone,
    Krelease,
    Kfullrelease,
}

pub struct SecureSession {
    m_holders: SessionHolderList,
    m_peer_address: PeerAddress,
    m_remote_session_params: SessionParameters,
    m_last_peer_activity_time: Timestamp,
    m_last_activity_time: Timestamp,
    m_local_session_id: OnceCell<u16>,
    m_peer_node_id: NodeId,
    m_fabric_index: FabricIndex,
    m_local_node_id: NodeId,
    m_secure_session_type: Type,
    m_is_case_commissioning_session: bool,
    m_peer_cats: CATValues,
    m_crypto_context: CryptoContext,
    m_state: State,
    m_peer_session_id: u16,
    // TODO: find a way to remove this
    m_table: Option<NonNull<SecureSessionTable>>,
}

impl SessionBasePrivate for SecureSession {
    fn holders(&mut self) -> &mut SessionHolderList {
        &mut self.m_holders
    }
}

impl SessionBase for SecureSession {
    fn get_session_type(&self) -> SessionType {
        SessionType::KSecure
    }

    fn is_active_session(&self) -> bool {
        self.m_state == State::Kactive
    }

    fn get_ack_timeout(&self, is_first_message_on_exchange: bool) -> Milliseconds {
        match self.m_peer_address.get_transport_type() {
            peer_address::Type::KUdp => {
                let remote_mrp_config = self.m_remote_session_params.get_mrp_config();

                ReliableMessageProtocolConfig::get_retransmission_timeout(remote_mrp_config.m_active_retrans_timeout, remote_mrp_config.m_idle_retrans_timeout,
                    self.get_last_peer_activity_time(), remote_mrp_config.m_active_threshold_time,
                    is_first_message_on_exchange)
            },
            peer_address::Type::KTcp => {
                Seconds::from_secs(30)
            },
            peer_address::Type::KBle => {
                Milliseconds::from_millis(BTP_ACK_TIMEOUT_MS)
            },
            _ => {
                Milliseconds::ZERO
            }
        }
    }

    fn get_message_receipt_timeout(&self, our_last_activity: Timestamp, is_first_message_on_exchange: bool) -> Milliseconds {
        match self.m_peer_address.get_transport_type() {
            peer_address::Type::KUdp => {
                let local_mrp_config = ReliableMessageProtocolConfig::get_local_mrp_config().unwrap_or(ReliableMessageProtocolConfig::get_default_mrp_config());

                ReliableMessageProtocolConfig::get_retransmission_timeout(local_mrp_config.m_active_retrans_timeout, local_mrp_config.m_idle_retrans_timeout,
                    our_last_activity, local_mrp_config.m_active_threshold_time,
                    is_first_message_on_exchange)
            },
            peer_address::Type::KTcp => {
                Seconds::from_secs(30)
            },
            peer_address::Type::KBle => {
                Milliseconds::from_millis(BTP_ACK_TIMEOUT_MS)
            },
            _ => {
                Milliseconds::ZERO
            }
        }
    }

    fn get_peer(&self) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(self.m_peer_node_id, self.get_fabric_index())
    }

    fn get_fabric_index(&self) -> FabricIndex {
        self.m_fabric_index
    }

    fn get_local_scoped_node_id(&self) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(self.m_local_node_id, self.get_fabric_index())
    }

    fn get_subject_descriptor(&self) -> SubjectDescriptor {
        let mut subject_descriptor = SubjectDescriptor::new();

        if is_operational_node_id(self.m_peer_node_id) {
            subject_descriptor.fabric_index = self.get_fabric_index();
            subject_descriptor.auth_mode = access::auth_mode::AuthMode::KCase;
            subject_descriptor.subject = self.m_peer_node_id;
            subject_descriptor.cats = self.m_peer_cats;
            subject_descriptor.is_commissioning = self.is_commissioning_session();
        } else if is_pake_key_id(self.m_peer_node_id) {
            if self.m_crypto_context.is_responder() {
                subject_descriptor.auth_mode = access::auth_mode::AuthMode::KPase;
                subject_descriptor.subject = self.m_peer_node_id;
                subject_descriptor.fabric_index = self.get_fabric_index();
                subject_descriptor.is_commissioning = self.is_commissioning_session();
            }
        } else {
            verify_or_die!(false);
        }

        subject_descriptor
    }

    fn allows_mrp(&self) -> bool {
        self.m_peer_address.get_transport_type() == peer_address::Type::KUdp
    }

    fn allow_large_payload(&self) -> bool {
        self.m_peer_address.get_transport_type() == peer_address::Type::KTcp
    }

    fn get_remote_session_parameters(&self) -> &SessionParameters {
        &self.m_remote_session_params
    }

    fn get_mrp_base_timeout(&self) -> Timestamp {
        if self.is_peer_active() {
            self.get_remote_mrp_config().m_active_retrans_timeout
        } else {
            self.get_remote_mrp_config().m_idle_retrans_timeout
        }
    }

    fn is_commissioning_session(&self) -> bool {
        if self.is_pase_session() {
            return true;
        }

        // CASE session is a commissioning session if it was marked as such.
        // The SessionManager is what keeps track.
        if self.is_case_session() && self.m_is_case_commissioning_session {
            return true;
        }

        false
    }

    fn set_fabric_index(&mut self, fabric_index: FabricIndex) {
        self.m_fabric_index = fabric_index
    }

    // no used
    fn session_id_for_logging(&self) -> u16 { 0 }
}

impl SecureSession {
    pub const fn new() -> Self {
        Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new(),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_last_activity_time: Timestamp::ZERO,
            m_local_session_id: OnceCell::new(),
            m_peer_node_id: KUNDEFINED_NODE_ID,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_local_node_id: KUNDEFINED_NODE_ID,
            m_secure_session_type: Type::Kpase,
            m_is_case_commissioning_session: false,
            m_peer_cats: CATValues::new(),
            m_crypto_context: CryptoContext::new(),
            m_state: State::Kestablishing,
            m_peer_session_id: 0,
            m_table: None,
        }
    }

    pub fn new_with(table: *mut SecureSessionTable, secure_session_type: Type, local_session_id: u16) -> Self {
        let s = Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new(),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_last_activity_time: Timestamp::ZERO,
            m_local_session_id: OnceCell::new(),
            m_peer_node_id: KUNDEFINED_NODE_ID,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_local_node_id: KUNDEFINED_NODE_ID,
            m_is_case_commissioning_session: false,
            m_peer_cats: CATValues::new(),
            m_crypto_context: CryptoContext::new(),
            m_state: State::Kestablishing,
            m_secure_session_type: secure_session_type,
            m_peer_session_id: 0,
            m_table: NonNull::new(table),
        };

        let _ = s.m_local_session_id.set(local_session_id);

        s
    }

    pub fn new_with_test(table: *mut SecureSessionTable, secure_session_type: Type, local_session_id: u16, local_node_id: NodeId,
        peer_node_id: NodeId, peer_cats: CATValues, peer_session_id: u16, fabric: FabricIndex,
        config: &ReliableMessageProtocolConfig) -> Self {

        let mut s = Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new_with(config.clone()),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_last_activity_time: Timestamp::ZERO,
            m_local_session_id: OnceCell::new(),
            m_peer_node_id: peer_node_id,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_local_node_id: local_node_id,
            m_is_case_commissioning_session: false,
            m_peer_cats: peer_cats,
            m_crypto_context: CryptoContext::new(),
            m_state: State::Kestablishing,
            m_secure_session_type: secure_session_type,
            m_peer_session_id: peer_session_id,
            m_table: NonNull::new(table),
        };

        let _ = s.m_local_session_id.set(local_session_id);

        s.move_to_state(State::Kactive);
        s.set_fabric_index(fabric);

        chip_log_detail!(Inet, "SecureSession[{:p}]: Allocated for Test Type: {} LSID: {}", &s, s.m_secure_session_type as u8, s.m_local_session_id.get().cloned().unwrap_or(0));

        s
    }

    pub fn is_establishing(&self) -> bool {
        self.m_state == State::Kestablishing
    }

    pub fn is_pending_eviction(&self) -> bool {
        self.m_state == State::KpendingEviction
    }

    pub fn is_defunct(&self) -> bool {
        self.m_state == State::Kdefunct
    }

    pub fn get_local_session_id(&self) -> u16 {
        *(self.m_local_session_id.get_or_init(|| 0))
    }

    pub fn adopt_fabric_index(&mut self, index: FabricIndex) -> ChipErrorResult {
        if self.m_secure_session_type != Type::Kpase {
            return Err(chip_error_invalid_argument!());
        }

        self.set_fabric_index(index);

        chip_ok!()
    }

    pub fn mark_active(&mut self) {
        self.m_last_activity_time = get_monotonic_timestamp();
    }

    pub fn mark_active_rx(&mut self) {
        self.m_last_peer_activity_time = get_monotonic_timestamp();
        self.mark_active();

        if self.m_state == State::Kdefunct {
            self.move_to_state(State::Kactive)
        }
    }

    pub fn set_case_commissioning_session_status(&mut self, is_case_commissioning_session: bool) {
        verify_or_die!(self.get_secure_session_type() == Type::Kcase);
        self.m_is_case_commissioning_session = is_case_commissioning_session;
    }

    pub fn get_peer_node_id(&self) -> NodeId {
        self.m_peer_node_id
    }

    fn activate(&mut self, local_node: &ScopedNodeId, peer_node: &ScopedNodeId, peer_cats: CATValues, peer_session_id: u16,
        session_parameters: &SessionParameters)
    {
        verify_or_die!(self.m_state == State::Kestablishing);
        verify_or_die!(peer_node.get_fabric_index() == local_node.get_fabric_index());

        // PASE sessions must always start unassociated with a Fabric!
        verify_or_die!(!((self.m_secure_session_type == Type::Kpase) && (peer_node.get_fabric_index() != KUNDEFINED_FABRIC_INDEX)));
        // CASE sessions must always start "associated" a given Fabric!
        verify_or_die!(!((self.m_secure_session_type == Type::Kcase) && (peer_node.get_fabric_index() == KUNDEFINED_FABRIC_INDEX)));
        // CASE sessions can only be activated against operational node IDs!
        verify_or_die!(!((self.m_secure_session_type == Type::Kcase) && 
                (!is_operational_node_id(peer_node.get_node_id()) || !is_operational_node_id(local_node.get_node_id()))));

        self.m_peer_node_id = peer_node.get_node_id();
        self.m_local_node_id = local_node.get_node_id();
        self.m_peer_cats = peer_cats;
        self.m_peer_session_id = peer_session_id;
        self.m_remote_session_params = session_parameters.clone();
        self.set_fabric_index(peer_node.get_fabric_index());
        self.mark_active_rx();

        /*
        if let Some(mut table_ptr) = self.m_table {
            unsafe {
                table_ptr.as_mut().retain(self);
            }
        } else {
            verify_or_die!(false);
        }
        */

        self.move_to_state(State::Kactive);

        /*
        if self.m_secure_session_type == Type::Kcase {
            if let Some(mut table_ptr) = self.m_table {
                unsafe {
                    table_ptr.as_mut().newer_session_available(self);
                }
            } else {
                verify_or_die!(false);
            }
        }
        */

        chip_log_detail!(Inet, "SecureSession[{:p}]: Activated - Type: {} LSID:{}", self, self.m_secure_session_type as u8, self.m_local_session_id.get().cloned().unwrap_or(0));
    }

    pub fn mark_as_defunct(&mut self) {
        chip_log_detail!(Inet, "SecureSession[{:p}]: MarkAsDefunct Type: {} LSID:{}", self, self.m_secure_session_type as u8, self.m_local_session_id.get().cloned().unwrap_or(0));
        match self.m_state {
            State::Kestablishing => {
                //
                // A session can only be marked as defunct from the state of Active.
                //
                verify_or_die!(false);
            },
            State::Kactive => {
                self.move_to_state(State::Kdefunct);
            },
            _ => {
                //
                // Do nothing
                //
            }
        }
    }

    pub fn get_last_activity_time(&self) -> Timestamp { self.m_last_activity_time }
    pub fn get_last_peer_activity_time(&self) -> Timestamp { self.m_last_peer_activity_time }

    #[inline]
    pub fn get_peer_cats(&self) -> &CATValues {
        &self.m_peer_cats
    }

    #[inline]
    pub fn get_secure_session_type(&self) -> Type {
        self.m_secure_session_type
    }

    #[inline]
    fn is_case_session(&self) -> bool {
        self.get_secure_session_type() == Type::Kcase
    }

    #[inline]
    fn is_pase_session(&self) -> bool {
        self.get_secure_session_type() == Type::Kpase
    }

    fn is_peer_active(&self) -> bool {
        let now = get_monotonic_timestamp();
        if let Some(diff) = now.checked_sub(self.get_last_peer_activity_time()) {
            return diff < self.get_remote_mrp_config().m_active_threshold_time;
        }

        false
    }

    fn move_to_state(&mut self, target_state: State) {
        if self.m_state != target_state {
            chip_log_progress!(SecureChannel, "SecureSession[{:p}, LSID:{}]: State change '{}' --> '{}'", self, self.m_local_session_id.get().cloned().unwrap_or(0),
                self.m_state, target_state);

            self.m_state = target_state;
        }
    }

    pub fn get_state(&self) -> State {
        self.m_state
    }
}

pub fn activate(session_handle: &mut SessionHandle, local_node: &ScopedNodeId, peer_node: &ScopedNodeId,
    peer_cats: CATValues, peer_session_id: u16, session_parameters: &SessionParameters)
{
    let mut table: * mut SecureSessionTable = ptr::null_mut();
    if let Ok(mut session) = session_handle.try_mut() {
        let ss: Option<&mut SecureSession> = session.as_mut();
        if let Some(secure_session) = ss {
            if let Some(t) = secure_session.m_table {
                table = t.as_ptr();
            } else {
                panic!("empty table in activate");
            }
        } else {
            panic!("only secure session can be activated");
        }
    }

    unsafe {
        inner_activate(session_handle, table.as_mut().unwrap(), local_node, peer_node, peer_cats, peer_session_id, session_parameters);
    }
}

fn inner_activate(session_handle: &mut SessionHandle, table: &mut SecureSessionTable, local_node: &ScopedNodeId, peer_node: &ScopedNodeId,
    peer_cats: CATValues, peer_session_id: u16, session_parameters: &SessionParameters)
{
    if let Ok(mut session) = session_handle.try_mut() {
        let ss: Option<&mut SecureSession> = session.as_mut();
        if let Some(secure_session) = ss {
            secure_session.activate(local_node, peer_node, peer_cats, peer_session_id, session_parameters);
        } else {
            panic!("only secure session can be activated");
        }
    } else {
        panic!("cannot borrow session mut in secure session activate");
    };
    table.retain(session_handle);
    table.newer_session_available(session_handle);
}

pub fn mark_for_evication(session_handle: SessionHandle) {
    let mut table: * mut SecureSessionTable = ptr::null_mut();
    if let Ok(mut session) = session_handle.try_mut() {
        let ss: Option<&mut SecureSession> = session.as_mut();
        if let Some(secure_session) = ss {
            if let Some(t) = secure_session.m_table {
                table = t.as_ptr();
            } else {
                panic!("empty table in activate");
            }
        } else {
            panic!("only secure session can be activated");
        }
    }

    unsafe {
        inner_mark_for_evication(session_handle, table.as_mut().unwrap());
    }
}

fn inner_mark_for_evication(mut session_handle: SessionHandle, table: &mut SecureSessionTable) {
    let op = {
        if let Ok(session) = session_handle.try_mut() {
            if let Some(secure_session) = session.as_ref() {
                chip_log_detail!(Inet, "SecureSession[{:p}]: MarkForEviction Type: {} LSID:{}", secure_session, secure_session.m_secure_session_type as u8, secure_session.m_local_session_id.get().cloned().unwrap_or(0));

                match secure_session.m_state {
                    State::Kestablishing => {
                        EvicationOp::Krelease
                    },
                    State::Kactive | State::Kdefunct => {
                        EvicationOp::Kfullrelease
                    },
                    _ => {
                        EvicationOp::Knone
                    }
                }
            } else {
                panic!("cannot get secure session in mark for evic");
            }
        } else {
            panic!("cannot borrow session mut in mark for evic");
        }
    };

    // Safefy:
    // we are safe to unwrap directly here since we try in the check above
    match op {
        EvicationOp::Knone => {
        },
        EvicationOp::Krelease => {
            session_handle.try_mut().unwrap().as_mut().unwrap().move_to_state(State::KpendingEviction);
            // Interrupt the pairing
            session_handle.notify_session_released();
        },
        EvicationOp::Kfullrelease => {
            table.release(&mut session_handle);
            session_handle.try_mut().unwrap().as_mut().unwrap().move_to_state(State::KpendingEviction);
            session_handle.notify_session_released();
        },
    }
}

pub fn newer_session_available(session_handle: SessionHandle, new_session: &SessionHandle) {
    if let Ok(mut session) = session_handle.try_mut() {
        // must call from secure sessoion
        verify_or_die!(session.get_session_type() == SessionType::KSecure);

        let mut current = session.holders().front_mut();
        while !current.is_null() {
            if let Some(holder) = current.remove() {
                let _ = holder.session_released();
                // Safety:
                // We have release the session, just grab without check
                holder.grab_unchecked(new_session.clone());
            } else {
                // sholdn't reach here
                panic!("get not get holder in list");
            }
        }
    } else {
        panic!("cannot borrow session mut in notify_release");
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn activate_pase_successfully() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kpase, 0);
        let node_id = KUNDEFINED_NODE_ID + 1;
        let local_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX);
        let peer_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    fn activate_case_successfully() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kcase, 0);
        let node_id = KUNDEFINED_NODE_ID + 1;
        let fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let local_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let peer_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    #[should_panic]
    fn not_same_fabric_index() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kpase, 0);
        let node_id = KUNDEFINED_NODE_ID + 1;
        let local_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX);
        let peer_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX + 1);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    #[should_panic]
    fn pase_with_known_fabric() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kpase, 0);
        let node_id = KUNDEFINED_NODE_ID + 1;
        let local_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX + 1);
        let peer_node = ScopedNodeId::default_with_ids(node_id, KUNDEFINED_FABRIC_INDEX + 1);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    #[should_panic]
    fn case_with_unknown_fabric() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kcase, 0);
        let node_id = KUNDEFINED_NODE_ID + 1;
        let fabric_index = KUNDEFINED_FABRIC_INDEX;
        let local_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let peer_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    #[should_panic]
    fn case_with_no_op_node() {
        let mut table = SecureSessionTable::new();
        let mut session = SecureSession::new_with(ptr::addr_of_mut!(table), Type::Kcase, 0);
        let node_id = KUNDEFINED_NODE_ID;
        let fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let local_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let peer_node = ScopedNodeId::default_with_ids(node_id, fabric_index);
        let cat = CATValues::new();
        let sp = SessionParameters::new();

        assert!(State::Kactive != session.get_state());
        session.activate(&local_node, &peer_node, cat, 1, &sp);
        assert!(State::Kactive == session.get_state());
    }

    #[test]
    fn newer_session_successfully() {
        // TODO: test it when we get secure session table ready
    }
}
