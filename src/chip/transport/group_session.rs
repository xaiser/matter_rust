#![allow(dead_code)]

pub mod incoming {
    use crate::{
        verify_or_die,
        chip::{
            transport::session::{
                SessionType, SessionHolderList, SessionBase, 
                new_session_holder_list, SessionBasePrivate
            },
            system::system_clock::{Milliseconds, Timestamp},
        },
    };

    pub trait AsMut {
        fn as_mut(&mut self) -> Option<&mut IncomingGroupSession>;
    }

    pub trait AsRef {
        fn as_ref(&self) -> Option<&IncomingGroupSession>;
    }

    pub struct IncomingGroupSession {
        m_holders: SessionHolderList,
    }

    impl SessionBasePrivate for IncomingGroupSession {
        fn holders(&mut self) -> &mut SessionHolderList {
            &mut self.m_holders
        }
    }

    impl SessionBase for IncomingGroupSession {
        fn get_session_type(&self) -> SessionType {
            SessionType::KGroupIncoming
        }

        fn is_active_session(&self) -> bool {
            // TODO: this is just a stub return value
            true
        }

        fn get_ack_timeout(&self, _is_first_message_on_exchange: bool) -> Milliseconds {
            verify_or_die!(false);
            Milliseconds::ZERO
        }

        fn get_message_receipt_timeout(&self, _our_last_activity: Timestamp, _is_first_message_on_exchange: bool) -> Milliseconds {
            verify_or_die!(false);
            Milliseconds::ZERO
        }
    }

    impl IncomingGroupSession {
        pub const fn new() -> Self {
            Self {
                m_holders: new_session_holder_list(),
            }
        }
    }
}

pub use incoming::IncomingGroupSession;

pub mod outgoing {
    use crate::{
        verify_or_die,
        chip::{
            transport::session::{
                SessionType, SessionHolderList, SessionBase, 
                new_session_holder_list, SessionBasePrivate
            },
            system::system_clock::{Milliseconds, Timestamp},
        },
    };

    pub trait AsMut {
        fn as_mut(&mut self) -> Option<&mut OutgoingGroupSession>;
    }

    pub trait AsRef {
        fn as_ref(&self) -> Option<&OutgoingGroupSession>;
    }

    pub struct OutgoingGroupSession {
        m_holders: SessionHolderList,
    }

    impl SessionBasePrivate for OutgoingGroupSession {
        fn holders(&mut self) -> &mut SessionHolderList {
            &mut self.m_holders
        }
    }

    impl SessionBase for OutgoingGroupSession {
        fn get_session_type(&self) -> SessionType {
            SessionType::KGroupOutgoing
        }

        fn is_active_session(&self) -> bool {
            // TODO: this is just a stub return value
            true
        }

        fn get_ack_timeout(&self, _is_first_message_on_exchange: bool) -> Milliseconds {
            verify_or_die!(false);
            Milliseconds::ZERO
        }

        fn get_message_receipt_timeout(&self, _our_last_activity: Timestamp, _is_first_message_on_exchange: bool) -> Milliseconds {
            verify_or_die!(false);
            Milliseconds::ZERO
        }
    }

    impl OutgoingGroupSession {
        pub const fn new() -> Self {
            Self {
                m_holders: new_session_holder_list(),
            }
        }
    }
}

pub use outgoing::OutgoingGroupSession;
