use crate::{
    chip_internal_log, chip_log_error, chip_internal_log_impl,
    chip::{
        access::subject_descriptor::SubjectDescriptor,
        chip_lib::{
            support::{
                intrusive_list::{
                    unsafe_ref::UnsafeRef,
                    linked_list::LinkedList,
                }
            },
        },
        messaging::{
            reliable_message_protocol_config::ReliableMessageProtocolConfig,
            session_parameters::SessionParameters,
        },
        system::system_clock::{get_monotonic_timestamp, Timeout, Milliseconds, Timestamp},
        transport::{
            unauthenticated_session::{self, UnauthenticatedSession},
            secure_session::{self, SecureSession},
            group_session::{self, IncomingGroupSession, OutgoingGroupSession},
        },
        ScopedNodeId, FabricIndex,
    },
};

use core::str::FromStr;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionType {
    KUndefined = 0,
    KUnauthenticated = 1,
    KSecure = 2,
    KGroupIncoming = 3,
    KGroupOutgoing = 4,
}

mod session_handle {
    use crate::{
        chip::chip_lib::{
            core::reference_counted::rc::{DefaultAlloactor, Rc},
        }
    };

    use super::Session;

    // Alloactor for reference counted pointer of session
    pub const ALLOACTOR_CAP: usize = crate::chip::chip_lib::core::chip_config::CHIP_CONFIG_MAX_SECURE_SESSION_POOL_SIZE;
    pub type Alloactor = DefaultAlloactor<Session, ALLOACTOR_CAP>;
    pub type SessionHandle= Rc<Session, Alloactor>;

    pub const fn new_session_alloactor() -> Alloactor {
        Alloactor::new()
    }

    pub fn try_new_handle(session: Session, alloactor: &mut Alloactor) -> Result<SessionHandle, ()> {
        SessionHandle::try_new_in(session, alloactor)
    }
}

// At the monent, the user must ensure the holder is not moved after allocated.
mod session_holder {
    use crate::{
        chip::{
            chip_lib::{
                support::{
                    intrusive_list::{
                        linked_list::{self, Link},
                        adapter,
                        unsafe_ref::UnsafeRef,
                    },
                },
            },
            transport::secure_session::AsRef,
        }
    };

    use super::{SessionBase, session_handle::SessionHandle};

    // Adapter for holder linked list
    type Adapter = adapter::linked_list::unsafe_ref::DefaultAdapter<SessionHolder>;
    pub type LinkedList = linked_list::LinkedList<Adapter>;

    // Handle for holder
    pub type Handle = UnsafeRef<SessionHolder>;

    const fn new_session_holder_adapter() -> Adapter {
        Adapter::new()
    }

    pub const fn new_session_holder_list() -> LinkedList {
        LinkedList::new(new_session_holder_adapter())
    }

    pub struct SessionHolder {
        #[allow(dead_code)]
        m_link: Link,
        m_session: Option<SessionHandle>,
    }

    impl Drop for SessionHolder {
        fn drop(&mut self) {
            self.release();
        }
    }

    impl SessionHolder {
        pub fn new() -> Self {
            Self {
                m_link: Link::new(),
                m_session: None,
            }
        }

        pub fn contain(&self, session: &SessionHandle) -> bool {
            self.m_session.as_ref().is_some_and(|s| SessionHandle::ptr_eq(s, session))
        }

        pub fn is_some(&self) -> bool {
            self.m_session.is_some()
        }

        pub fn get(&self) -> Option<SessionHandle> {
            self.m_session.clone()
        }

        pub fn grab_pairing_session(&mut self, session: SessionHandle) -> Result<(), SessionHandle> {
            self.release();

            if session.as_ref().as_ref().is_some_and(|s| s.is_establishing()) {
                self.grab_unchecked(session);
                return Ok(());
            }

            Err(session)
        }

        pub fn grab(&mut self, session: SessionHandle) -> Result<(), SessionHandle> {
            self.release();

            if !session.is_active_session() {
                return Err(session);
            }

            self.grab_unchecked(session);

            Ok(())
        }

        fn grab_unchecked(&mut self, mut session: SessionHandle) {
            if self.m_session.is_some() {
                // should never reach here
                panic!("grab but not release session");
            }

            // Safety:
            // 1. There is only 1 owner will access the holder list at a time since CHIP stack
            //    is running on a single thread.
            // 2. The rest of session data will remain the same so other owner should still see
            //    the same data, therefore, keep acting as if no changes in the session.
            // 3. Since this session is still holded at this monent, the underlying session
            //    object must be alive.
            unsafe {
                SessionHandle::get_mut_unchecked(&mut session).add_holder(self);
            }
            self.m_session = Some(session);
        }

        pub fn as_ref(&self) -> Option<&SessionHandle> {
            self.m_session.as_ref()
        }

        pub fn release(&mut self) {
            let session = self.m_session.take();
            if session.is_none() {
                return;
            }
            let mut session = session.unwrap();
            // Safety:
            // 1. There is only 1 owner will access the holder list at a time since CHIP stack
            //    is running on a single thread.
            // 2. The rest of session data will remain the same so other owner should still see
            //    the same data, therefore, keep acting as if no changes in the session.
            // 3. Since this session is still holded at this monent, the underlying session
            //    object must be alive.
            unsafe {
                SessionHandle::get_mut_unchecked(&mut session).remove_holder(self);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use super::super::{
            session_handle::{
                new_session_alloactor, try_new_handle,
            },
            SessionBasePrivate,
            Session,
        };
        use crate::chip::chip_lib::support::{
            pool::{ObjectPool, KInline, BitMapObjectPool},
        };

        const POOL_SIZE: usize = 1;
        type TestPool = BitMapObjectPool<Holder, POOL_SIZE>;

        struct Holder {
            pub m_session: SessionHolder,
        }

        impl Holder {
            pub fn new() -> Self {
                Self {
                    m_session: SessionHolder::new(),
                }
            }
        }

        #[test]
        fn new_holder_successfully() {
            let mut pool = TestPool::new();
            let holder = pool.allocate(Holder::new());
            assert!(!holder.is_null());
        }

        #[test]
        fn grab_successfully() {
            let mut holder_pool = TestPool::new();
            let mut holder = holder_pool.allocate(Holder::new());

            let mut session_pool = new_session_alloactor();
            let mut session = try_new_handle(Session::new_secure(), &mut session_pool);
            assert!(session.is_ok());
            let mut session = session.unwrap();

            unsafe {
                assert!((*holder).m_session.grab(session).is_ok());
            }
        }

        #[test]
        fn drop_successfully() {
            let mut holder_pool = TestPool::new();
            let mut holder = holder_pool.allocate(Holder::new());

            let mut session_pool = new_session_alloactor();
            let mut session = try_new_handle(Session::new_secure(), &mut session_pool);
            assert!(session.is_ok());
            let session = session.unwrap();
            // make some copies used later for check
            let mut session_copy = session.clone();
            let session_copy_2 = session.clone();

            assert_eq!(3, SessionHandle::strong_count(&session_copy));

            unsafe {
                assert!((*holder).m_session.grab(session).is_ok());
            }

            // ensure grab doesn't increase the reference count
            assert_eq!(3, SessionHandle::strong_count(&session_copy));

            unsafe {
                // ensure there is only one holders
                assert!(SessionHandle::get_mut_unchecked(&mut session_copy).holders().front().get().
                    is_some_and(|h| h.contain(&session_copy_2)));
                assert!(SessionHandle::get_mut_unchecked(&mut session_copy).holders().back().get().
                    is_some_and(|h| h.contain(&session_copy_2)));

                core::ptr::drop_in_place(holder);

                // ensure the holder list is empty
                assert!(SessionHandle::get_mut_unchecked(&mut session_copy).holders().front().get().
                    is_none());
            }

            // the count should be 2
            assert_eq!(2, SessionHandle::strong_count(&session_copy));
        }
    } // end of tests
}

pub type SessionHolderHandle = session_holder::Handle;
pub type SessionHolder = session_holder::SessionHolder;
pub type SessionHolderList = session_holder::LinkedList;
pub use session_holder::new_session_holder_list;

pub trait SessionBasePrivate {
    fn holders(&mut self) -> &mut SessionHolderList;
}

pub trait SessionBase: SessionBasePrivate {
    fn get_session_type(&self) -> SessionType;

    fn add_holder(&mut self, holder: &SessionHolder) {
        let list = self.holders();
        unsafe {
            let _ = list.push_back(SessionHolderHandle::from_raw(holder)).inspect_err(|_|
                chip_log_error!(SecureChannel, "list full")
            );
        }
    }

    fn remove_holder(&mut self, holder: &SessionHolder) {
        let list = self.holders();
        unsafe {
            let mut cur_mut = list.cursor_mut_from_ptr(holder);
            cur_mut.remove();
        }
    }

    fn is_active_session(&self) -> bool;

    fn is_group_session(&self) -> bool {
        match self.get_session_type() {
            SessionType::KGroupIncoming | SessionType::KGroupOutgoing => {
                true
            },
            _ => {
                false
            }
        }
    }

    fn compute_round_trip_timeout(&self, upperlayer_processing_timeout: Timeout, is_first_message_on_exchange: bool) -> Timeout {
        if self.is_group_session() {
            return Timeout::ZERO;
        }

        self.get_ack_timeout(is_first_message_on_exchange).saturating_add(upperlayer_processing_timeout).saturating_add(self.get_message_receipt_timeout(get_monotonic_timestamp(), false))
    }

    fn get_ack_timeout(&self, is_first_message_on_exchange: bool) -> Milliseconds;

    fn get_message_receipt_timeout(&self, our_last_activity: Timestamp, is_first_message_on_exchange: bool) -> Milliseconds;

    fn session_id_for_logging(&self) -> u16;

    fn get_peer(&self) -> ScopedNodeId;

    fn get_fabric_index(&self) -> FabricIndex;

    fn get_local_scoped_node_id(&self) -> ScopedNodeId;

    fn get_subject_descriptor(&self) -> SubjectDescriptor;
    /*

    fn allows_mrp(&self) -> bool;

    fn allow_large_payload(&self) -> bool;

    fn get_remote_session_parameters(&self) -> &SessionParameters;

    fn get_mrp_base_timeout(&self) -> Timeout;

    fn is_comissioning_session(&self) -> bool { false }

    fn get_remote_mrp_config(&self) -> &ReliableMessageProtocolConfig {
        self.get_remote_session_parameters().get_mrp_config()
    }

    fn is_sescure_session(&self) -> bool {
        self.get_session_type() == SessionType::KSecure
    }

    fn is_unauthenticated_session(&self) -> bool {
        self.get_session_type() == SessionType::KUnauthenticated
    }

    fn notify_session_hang(&self);

    fn notify_session_released(&self);

    fn set_fabric_index(&mut self, fabric_index: FabricIndex);
    */
}

pub enum Session {
    Secure(SecureSession),
    Unauthenticated(UnauthenticatedSession),
    IncomingGroupSession(IncomingGroupSession),
    OutgoingGroupSession(OutgoingGroupSession),
}

impl secure_session::AsMut for Session {
    fn as_mut(&mut self) -> Option<&mut SecureSession> {
        match self {
            Session::Secure(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl secure_session::AsRef for Session {
    fn as_ref(&self) -> Option<&SecureSession> {
        match self {
            Session::Secure(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl unauthenticated_session::AsMut for Session {
    fn as_mut(&mut self) -> Option<&mut UnauthenticatedSession> {
        match self {
            Session::Unauthenticated(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl unauthenticated_session::AsRef for Session {
    fn as_ref(&self) -> Option<&UnauthenticatedSession> {
        match self {
            Session::Unauthenticated(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl group_session::incoming::AsMut for Session {
    fn as_mut(&mut self) -> Option<&mut IncomingGroupSession> {
        match self {
            Session::IncomingGroupSession(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl group_session::incoming::AsRef for Session {
    fn as_ref(&self) -> Option<&IncomingGroupSession> {
        match self {
            Session::IncomingGroupSession(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl group_session::outgoing::AsMut for Session {
    fn as_mut(&mut self) -> Option<&mut OutgoingGroupSession> {
        match self {
            Session::OutgoingGroupSession(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl group_session::outgoing::AsRef for Session {
    fn as_ref(&self) -> Option<&OutgoingGroupSession> {
        match self {
            Session::OutgoingGroupSession(session) => {
                Some(session)
            },
            _ => {
                None
            }
        }
    }
}

impl SessionBasePrivate for Session {
    fn holders(&mut self) -> &mut SessionHolderList {
        match self {
            Session::Unauthenticated(session) => {
                session.holders()
            },
            Session::Secure(session) => {
                session.holders()
            },
            Session::IncomingGroupSession(session) => {
                session.holders()
            },
            Session::OutgoingGroupSession(session) => {
                session.holders()
            },
        }
    }
}

impl SessionBase for Session {
    fn get_session_type(&self) -> SessionType {
        match self {
            Session::Unauthenticated(_) => {
                SessionType::KUnauthenticated
            },
            Session::Secure(_) => {
                SessionType::KSecure
            },
            Session::IncomingGroupSession(_) => {
                SessionType::KGroupIncoming
            },
            Session::OutgoingGroupSession(_) => {
                SessionType::KGroupOutgoing
            },
        }
    }

    fn is_active_session(&self) -> bool {
        match self {
            Session::Unauthenticated(session) => {
                session.is_active_session()
            },
            Session::Secure(session) => {
                session.is_active_session()
            },
            Session::IncomingGroupSession(session) => {
                session.is_active_session()
            },
            Session::OutgoingGroupSession(session) => {
                session.is_active_session()
            },
        }
    }

    fn get_ack_timeout(&self, is_first_message_on_exchange: bool) -> Milliseconds {
        match self {
            Session::Unauthenticated(session) => {
                session.get_ack_timeout(is_first_message_on_exchange)
            },
            Session::Secure(session) => {
                session.get_ack_timeout(is_first_message_on_exchange)
            },
            Session::IncomingGroupSession(session) => {
                session.get_ack_timeout(is_first_message_on_exchange)
            },
            Session::OutgoingGroupSession(session) => {
                session.get_ack_timeout(is_first_message_on_exchange)
            },
        }
    }

    fn get_message_receipt_timeout(&self, our_last_activity: Timestamp, is_first_message_on_exchange: bool) -> Milliseconds {
        match self {
            Session::Unauthenticated(session) => {
                session.get_message_receipt_timeout(our_last_activity, is_first_message_on_exchange)
            },
            Session::Secure(session) => {
                session.get_message_receipt_timeout(our_last_activity, is_first_message_on_exchange)
            },
            Session::IncomingGroupSession(session) => {
                session.get_message_receipt_timeout(our_last_activity, is_first_message_on_exchange)
            },
            Session::OutgoingGroupSession(session) => {
                session.get_message_receipt_timeout(our_last_activity, is_first_message_on_exchange)
            },
        }
    }

    fn session_id_for_logging(&self) -> u16 {
        match self {
            Session::Unauthenticated(session) => {
                0
            },
            Session::Secure(session) => {
                session.get_local_session_id()
            },
            Session::IncomingGroupSession(session) => {
                session.get_group_id()
            },
            Session::OutgoingGroupSession(session) => {
                session.get_group_id()
            },
        }
    }

    fn get_peer(&self) -> ScopedNodeId {
        match self {
            Session::Unauthenticated(session) => {
                session.get_peer()
            },
            Session::Secure(session) => {
                session.get_peer()
            },
            Session::IncomingGroupSession(session) => {
                session.get_peer()
            },
            Session::OutgoingGroupSession(session) => {
                session.get_peer()
            },
        }
    }

    fn get_fabric_index(&self) -> FabricIndex {
        match self {
            Session::Unauthenticated(session) => {
                session.get_fabric_index()
            },
            Session::Secure(session) => {
                session.get_fabric_index()
            },
            Session::IncomingGroupSession(session) => {
                session.get_fabric_index()
            },
            Session::OutgoingGroupSession(session) => {
                session.get_fabric_index()
            },
        }
    }

    fn get_local_scoped_node_id(&self) -> ScopedNodeId {
        match self {
            Session::Unauthenticated(session) => {
                session.get_local_scoped_node_id()
            },
            Session::Secure(session) => {
                session.get_local_scoped_node_id()
            },
            Session::IncomingGroupSession(session) => {
                session.get_local_scoped_node_id()
            },
            Session::OutgoingGroupSession(session) => {
                session.get_local_scoped_node_id()
            },
        }
    }

    fn get_subject_descriptor(&self) -> SubjectDescriptor {
        match self {
            Session::Unauthenticated(session) => {
                session.get_subject_descriptor()
            },
            Session::Secure(session) => {
                session.get_subject_descriptor()
            },
            Session::IncomingGroupSession(session) => {
                session.get_subject_descriptor()
            },
            Session::OutgoingGroupSession(session) => {
                session.get_subject_descriptor()
            },
        }
    }
}

impl Session {
    pub const fn new_secure() -> Session {
        Session::Secure(SecureSession::new())
    }

    pub const fn new_unauthenticated() -> Session {
        Session::Unauthenticated(UnauthenticatedSession::new())
    }
    pub const fn new_incoming_group() -> Session {
        Session::IncomingGroupSession(IncomingGroupSession::new())
    }

    pub const fn new_outgoing_group() -> Session {
        Session::OutgoingGroupSession(OutgoingGroupSession::new())
    }
}

pub fn get_session_type_string(session: &session_handle::SessionHandle) -> &str {
    match session.get_session_type() {
        SessionType::KGroupIncoming => {
            "G"
        },
        SessionType::KGroupOutgoing => {
            "G"
        },
        SessionType::KSecure => {
            "S"
        },
        SessionType::KUnauthenticated => {
            "U"
        },
        _ => {
            "?"
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session_successfully() {
        let session = Session::new_secure();

        assert_eq!(SessionType::KSecure, session.get_session_type());
    }

    #[test]
    fn get_round_trip_timeout() {
        let session = Session::new_secure();

        assert!(session.compute_round_trip_timeout(Timeout::from_millis(1), true).as_millis() != 0);
    }

    #[test]
    fn get_round_trip_timeout_group() {
        let session = Session::new_incoming_group();

        assert!(session.compute_round_trip_timeout(Timeout::from_millis(1), true) == Timeout::ZERO);
    }
} // end of tests
