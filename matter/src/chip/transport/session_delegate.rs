use crate::{
    chip::{
        messaging::{
            exchange_context::ExchangeContextSessionDelegate,
        },
        transport::{
            session::SessionHangOp,
        },
    },
};

macro_rules! call_on_all_variants {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            SessionDelegate::ExchangeContext(ec) => ec.$method($($args),*),
        }
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NewSessionHandlingPolicy {
    KshiftToNewSession,
    KstayAtOldSession,
}

pub trait SessionDelegateTrait {
    /*
     * @brief
     *   Called when a new secure session to the same peer is established, over the delegate of SessionHolderWithDelegate object. It
     *   is suggested to shift to the newly created session.
     *
     *   Our security model is built upon Exchanges and Sessions, but not SessionHolders, such that SessionHolders should be able to
     *   shift to a new session freely. If an application is holding a session which is not intended to be shifted, it can provide
     *   its shifting policy by overriding GetNewSessionHandlingPolicy in SessionDelegate. For example SessionHolders inside
     *   ExchangeContext and PairingSession are not eligible for auto-shifting.
     *
     * Note: the default implementation orders shifting to the new session, it should be fine for all users, unless the
     *       SessionHolder object is expected to be sticky to a specified session.
     *
     * Note: the implementation MUST NOT modify the session pool or the state of session holders (eg, adding new session, removing
     *       old session) from inside this callback.
     */
    fn get_new_session_handling_policy(&self) -> NewSessionHandlingPolicy {
        NewSessionHandlingPolicy::KshiftToNewSession
    }

    /*
     * @brief
     *   Called when a session is releasing. Callees SHALL NOT make synchronous calls into SessionManager to allocate a new session.
     *   If they desire to do so, it MUST be done asynchronously.
     */
    fn on_session_released(&self);

    /*
     * @brief
     *   Called when a session is unresponsive for a while (detected by MRP). Callees SHALL NOT make synchronous calls into
     * SessionManager to allocate a new session. If they desire to do so, it MUST be done asynchronously.
     */
    fn on_session_hang(&self) -> Option<SessionHangOp>;
}

pub enum SessionDelegate {
    ExchangeContext(ExchangeContextSessionDelegate),
}

impl SessionDelegate {
    pub fn new_exchange_context(ec: ExchangeContextSessionDelegate) -> Self {
        SessionDelegate::ExchangeContext(ec)
    }
}

impl SessionDelegateTrait for SessionDelegate {
    fn get_new_session_handling_policy(&self) -> NewSessionHandlingPolicy {
        call_on_all_variants!(self, get_new_session_handling_policy)
    }

    fn on_session_released(&self) {
        call_on_all_variants!(self, on_session_released)
    }

    fn on_session_hang(&self) -> Option<SessionHangOp> {
        call_on_all_variants!(self, on_session_hang)
        /*
        match self {
            SessionDelegate::ExchangeContext(ec) => ec.on_session_hang(),
        }
        */
    }
}
