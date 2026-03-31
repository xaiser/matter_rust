use crate::{
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
        system::system_clock::{Timeout, Milliseconds, Timestamp},
        transport::{
            unauthenticated_session::{self, UnauthenticatedSession},
            secure_session::{self, SecureSession},
        },
        ScopedNodeId, FabricIndex,
    },
};

#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum SessionType {
    KUndefined = 0,
    KUnauthenticated = 1,
    KSecure = 2,
    KGroupIncoming = 3,
    KGroupOutgoing = 4,
}

mod session_holder {
    use crate::{
        //create_object_pool,
        chip::chip_lib::{
            core::reference_counted::rc::{DefaultAlloactor, Rc},
            support::{
                intrusive_list::{
                    linked_list::{self, Link},
                    adapter,
                    unsafe_ref::UnsafeRef,
                },
                //pool::{ObjectPool, KInline, BitMapObjectPool},
            },
        }
    };

    use super::Session;

    // Alloactor for reference counted pointer of session
    pub const ALLOACTOR_CAP: usize = crate::chip::chip_lib::core::chip_config::CHIP_CONFIG_MAX_SECURE_SESSION_POOL_SIZE;
    type Alloactor = DefaultAlloactor<Session, ALLOACTOR_CAP>;
    type SessionHandle = Rc<Session, Alloactor>;

    // Adapter for holder linked list
    type Adapter = adapter::linked_list::unsafe_ref::DefaultAdapter<SessionHolder>;
    pub type LinkedList = linked_list::LinkedList<Adapter>;

    // Handle for holder
    pub type Handle = UnsafeRef<SessionHolder>;

    const fn new_session_alloactor() -> Alloactor {
        Alloactor::new()
    }

    const fn new_session_holder_adapter() -> Adapter {
        Adapter::new()
    }

    const fn new_session_holder_list() -> LinkedList {
        LinkedList::new(new_session_holder_adapter())
    }

    pub struct SessionHolder {
        link: Link,
        m_session: Option<SessionHandle>,
    }

    impl SessionHolder {
        pub fn new() -> Self {
            Self {
                link: Link::new(),
                m_session: None,
            }
        }
    }
}

pub type SessionHolderHandle = session_holder::Handle;
pub type SessionHolder = session_holder::SessionHolder;
pub type SessionHolderList = session_holder::LinkedList;

pub trait SessionBase {
    fn get_session_type(&self) -> SessionType;

    fn holders(&mut self) -> &mut SessionHolderList;

    fn add_holder(&mut self, holder: SessionHolderHandle) {
        let mut list = self.holders();
        list.push_back(holder);
    }

    fn remove_holder(&mut self, holder: SessionHolderHandle) {
        let mut list = self.holders();
        unsafe {
            let mut cur_mut = list.cursor_mut_from_ptr(SessionHolderHandle::into_raw(holder));
            cur_mut.remove();
        }
    }

    /*
    fn is_active_session(&self) -> bool;

    fn get_peer(&self) -> ScopedNodeId;

    fn get_local_scoped_node_id(&self) -> ScopedNodeId;

    fn get_subject_descritptor(&self) -> SubjectDescriptor;

    fn allows_mrp(&self) -> bool;

    fn allow_large_payload(&self) -> bool;

    fn get_remote_session_parameters(&self) -> &SessionParameters;

    fn get_mrp_base_timeout(&self) -> Timeout;

    fn is_comissioning_session(&self) -> bool { false }

    fn get_ack_timeout(&self, is_first_message_on_exchange: bool) -> Milliseconds;

    fn get_message_receipt_timeout(&self, our_last_activity: Timestamp, is_first_message_on_exchange: bool) -> Milliseconds;

    fn get_remote_mrp_config(&self) -> &ReliableMessageProtocolConfig {
        self.get_remote_session_parameters().get_mrp_config()
    }

    fn compute_round_trip_timeout(&self, upperlayer_processing_timeout: Timeout, is_first_message_on_exchange: bool) -> Timeout;

    fn get_fabric_index(&self) -> FabricIndex;

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

    fn is_sescure_session(&self) -> bool {
        self.get_session_type() == SessionType::KSecure
    }

    fn is_unauthenticated_session(&self) -> bool {
        self.get_session_type() == SessionType::KUnauthenticated
    }

    fn notify_session_hang(&self);

    fn session_id_for_logging(&self) -> u16;

    fn notify_session_released(&self);

    fn set_fabric_index(&mut self, fabric_index: FabricIndex);
    */
}

pub enum Session {
    Secure(SecureSession),
    Unauthenticated(UnauthenticatedSession),
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

impl SessionBase for Session {
    fn get_session_type(&self) -> SessionType {
        match self {
            Session::Unauthenticated(_) => {
                SessionType::KUnauthenticated
            },
            Session::Secure(_) => {
                SessionType::KSecure
            },
        }
    }
    fn holders(&mut self) -> &mut SessionHolderList {
        match self {
            Session::Unauthenticated(session) => {
                session.holders()
            },
            Session::Secure(session) => {
                session.holders()
            },
        }
    }
    /*
    fn add_holder(&mut self, holder: SessionHolderHandle) {
        match self {
            Session::Unauthenticated(session) => {
                session.add_holder(holder);
            },
            Session::Secure(session) => {
                session.add_holder(holder);
            },
            _ => {
            }
        }
    }

    fn remove_holder(&mut self, holder: SessionHolderHandle) {
        match self {
            Session::Unauthenticated(session) => {
                session.remove_holder(holder)
            },
            Session::Secure(session) => {
                session.add_holder(holder);
            },
            _ => {
            }
        }
    }
    */
}
