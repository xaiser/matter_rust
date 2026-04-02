#![allow(dead_code)]

pub mod incoming {
    use crate::{
        verify_or_die,
        chip::{
            access::subject_descriptor::SubjectDescriptor,
            chip_lib::core::{
                node_id::KUNDEFINED_NODE_ID,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
            },
            transport::session::{
                SessionType, SessionHolderList, SessionBase, 
                new_session_holder_list, SessionBasePrivate
            },
            system::system_clock::{Milliseconds, Timestamp},
            GroupId, ScopedNodeId, NodeId, FabricIndex,
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
        m_group_id: GroupId,
        m_peer_node_id: NodeId,
        m_fabric_index: FabricIndex,
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

        fn get_peer(&self) -> ScopedNodeId {
            ScopedNodeId::default_with_ids(self.m_peer_node_id, self.get_fabric_index())
        }

        fn get_fabric_index(&self) -> FabricIndex {
            self.m_fabric_index
        }

        fn get_local_scoped_node_id(&self) -> ScopedNodeId {
            ScopedNodeId::default_with_ids(KUNDEFINED_NODE_ID, self.get_fabric_index())
        }

        fn get_subject_descriptor(&self) -> SubjectDescriptor {
            SubjectDescriptor::new()
        }

        // no used
        fn session_id_for_logging(&self) -> u16 { 0 }
    }

    impl IncomingGroupSession {
        pub const fn new() -> Self {
            Self {
                m_holders: new_session_holder_list(),
                m_group_id: 0,
                m_fabric_index: KUNDEFINED_FABRIC_INDEX,
                m_peer_node_id: KUNDEFINED_NODE_ID,
            }
        }

        pub fn get_group_id(&self) -> GroupId {
            self.m_group_id
        }
    }
}

pub use incoming::IncomingGroupSession;

pub mod outgoing {
    use crate::{
        verify_or_die,
        chip::{
            access::subject_descriptor::SubjectDescriptor,
            chip_lib::core::{
                node_id::KUNDEFINED_NODE_ID,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
            },
            transport::session::{
                SessionType, SessionHolderList, SessionBase, 
                new_session_holder_list, SessionBasePrivate
            },
            system::system_clock::{Milliseconds, Timestamp},
            ScopedNodeId, GroupId, FabricIndex,
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
        m_group_id: GroupId,
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

        fn get_subject_descriptor(&self) -> SubjectDescriptor {
            SubjectDescriptor::new()
        }

        // no used
        fn session_id_for_logging(&self) -> u16 { 0 }

        fn get_fabric_index(&self) -> FabricIndex {
            KUNDEFINED_FABRIC_INDEX
        }

        fn get_peer(&self) -> ScopedNodeId {
            ScopedNodeId::const_default()
        }

        fn get_local_scoped_node_id(&self) -> ScopedNodeId {
            ScopedNodeId::const_default()
        }
    }

    impl OutgoingGroupSession {
        pub const fn new() -> Self {
            Self {
                m_holders: new_session_holder_list(),
                m_group_id: 0,
            }
        }

        pub fn get_group_id(&self) -> GroupId {
            self.m_group_id
        }
    }
}

pub use outgoing::OutgoingGroupSession;
