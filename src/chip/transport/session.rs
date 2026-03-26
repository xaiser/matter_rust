use crate::{
    chip::{
        access::subject_descriptor::SubjectDescritpor,
        chip_lib::{
            support::intrusive_list::unsafe_ref::UnsafeRef,
        },
    },
    ScopedNodeId,
};

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SessionType {
    KUndefined = 0,
    KUnauthenticated = 1,
    KSecure = 2,
    KGroupIncoming = 3,
    KGroupOutgoing = 4,
}

mod session_holder {
    use crate::chip::chip_lib::support::intrusive_list::linked_list::Link;

    pub struct SessionHolder {
        link: Link,
    };

}

type SessionHolderHandle = UnsefeRef<session_holder::SessionHolder>;

pub trait Session {
    fn get_session_type(&self) -> SessionType;

    fn add_holder(&mut self, holder: SessionHolderHandle);

    fn remove_holder(&mut self, holder: SessionHolderHandle);

    fn is_active_session(&self) -> bool;

    fn get_peer(&self) -> ScopedNodeId;

    fn get_local_scoped_node_id(&self) -> ScopedNodeId;

    fn get_subject_descritptor(&self) -> SubjectDescritpor;

    fn allows_mrp(&self) -> bool;

    fn allow_large_payload(&self) -> bool;
}
