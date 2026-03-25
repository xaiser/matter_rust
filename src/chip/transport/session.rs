use crate::chip::chip_lib::support::intrusive_list::unsafe_ref::UnsafeRef;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SessionType {
    K_UNDEFINED = 0,
    K_UNAUTHENTICATED = 1,
    K_SECURE = 2,
    K_GROUP_INCOMING = 3,
    K_GROUP_OUTGOGIN = 4,
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
}
