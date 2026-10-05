use crate::{
    chip::{
        chip_lib::{
            support::{
                logging::text_only_logging::{
                    chip_log_value_exchange_id, chip_log_option_non_null, chip_log_value_protocol_id,
                    chip_log_value_exchange,
                },
            },
        },
        protocols::{
            self, protocols::MessageTypeTrait,
        },
        system::{
            system_packet_buffer::PacketBufferHandle,
        },
        messaging::{
            exchange_mgr::ExchangeManager,
            exchange_delegate::ExchangeDelegate,
            exchange_message_dispatch::{
                ExchangeMessageDispatchHandle,
                ExchangeMessageDispatch,
            },
            reliable_message_mgr::SharedReliableMessageMgr,
            reliable_message_context::{ReliableMessageContext, BaseReliableMessageContext, MessageFlags as Flags},
            flags::SendMessageFlags as SendFlags,
        },
        transport::{
            session::{
                SessionHolder, session_holder_delegate, SessionHandle,
                Session, SessionAccess, AccessError, Variant, SessionBase,
            },
        },
        system::{
            system_clock::{
                Timeout,
            },
        },
    },
    ChipErrorResult, chip_ok,
    chip_error_invalid_argument,
    chip_core_error, chip_sdk_error,
    verify_or_die,

    chip_internal_log,
    chip_internal_log_impl,
    chip_log_error,
};

use core::str::FromStr;
use core::ptr::NonNull;
use core::cell::{Ref, RefMut};

fn default_on_message_received(ec: &ExchangeContext, protocol_id: protocols::Id, msg_type: u8, message_counter: u32,
    _payload: PacketBufferHandle)
{
    chip_log_error!(ExchangeManager, 
        "Dropping unexpected message of type {} with protocol Id {} and MessageCounter: {} on exchange {}",
        msg_type, chip_log_value_protocol_id(&protocol_id), message_counter, chip_log_value_exchange(ec));
}

struct ExchangeSessionHolder {
    pub session_holder: SessionHolder,
}

impl ExchangeSessionHolder {
    pub const fn new() -> Self {
        Self {
            session_holder: SessionHolder::new(),
        }
    }

    pub fn new_with(exchange: session_holder_delegate::Context) -> Self {
        Self {
            session_holder: SessionHolder::new_with_delegate(
                                session_holder_delegate::Delegate::new(
                                    session_delegate::on_release,
                                    session_delegate::get_policy,
                                    session_delegate::on_hang,
                                    exchange,
                                )
                            ),
        }
    }
}

impl SessionAccess for ExchangeSessionHolder {
    fn with<ST: Variant, R>(&self, f: impl Fn(&ST) -> R) -> Result<R, AccessError>
    {
        self.session_holder.with(f)
    }

    fn with_mut<ST: Variant, R>(&mut self, f: impl Fn(&mut ST) -> R) -> Result<R, AccessError>
    {
        self.session_holder.with_mut(f)
    }
}

pub(super) mod session_delegate {
    use crate::{
        chip::{
            transport::{
                session::{
                    NewSessionHandlingPolicy,
                    session_holder_delegate::{Context},
                    SessionHangOp,
                },
            },
        },
    };
    pub(super) fn on_release(_ec: Context) {}
    pub(super) fn get_policy(_ec: Context) -> NewSessionHandlingPolicy {
        NewSessionHandlingPolicy::KstayAtOldSession
    }
    pub(super) fn on_hang(_ec: Context) -> Option<SessionHangOp> {
        None
    }
}

pub struct ExchangeContext<'a> {
    m_response_timeout: Timeout,
    m_delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>,
    m_exchange_mgr: Option<NonNull<ExchangeManager>>,
    m_dispatch: ExchangeMessageDispatchHandle,
    m_session: ExchangeSessionHolder,
    m_exchange_id: u16,
    m_reliable_message_context: BaseReliableMessageContext,
}

impl<'a> ExchangeContext<'a> {
    pub const fn new() -> Self {
        Self {
            m_response_timeout: Timeout::from_secs(0),
            m_delegate: None,
            m_exchange_mgr: None,
            m_dispatch: ExchangeMessageDispatchHandle::new(),
            m_session: ExchangeSessionHolder::new(),
            m_exchange_id: 0,
            m_reliable_message_context: BaseReliableMessageContext::new(),
        }
    }

    /*
    pub fn new_with(em: Option<NonNull<ExchangeManager>>, exchange_id: u16, session: &SessionHandle, initiator: bool,
        delegate: NonNull<dyn ExchangeDelegate>, _is_ephemeral_exchange: bool) -> Self
    {
    }
    */

    pub fn is_encryption_required(&self) -> bool {
        self.m_dispatch.is_encryption_required()
    }

    pub fn is_group_exchange_context(&self) -> bool {
        self.m_session.with(|s: &Session| s.is_group_session()).is_ok_and(|b| b)
    }

    pub fn get_exchange_id(&self) -> u16 {
        self.m_exchange_id
    }

    pub fn is_initiator(&self) -> bool {
        self.base().m_flags.intersects(Flags::KflagInitiator)
    }

    pub fn is_response_expected(&self) -> bool {
        self.base().m_flags.intersects(Flags::KflagResponseExpected)
    }

    // Applies a suggested response timeout value based on the session type and the given upper layer processing time for
    // the next message to the exchange. The exchange context must have a valid session when calling this function.
    //
    // This function is an equivalent of SetResponseTimeout(mSession->ComputeRoundTripTimeout(applicationProcessingTimeout))
    pub fn use_suggested_response_timeout(&mut self, application_processing_timeout: Timeout) {
        let _ = self.m_session.with(|s: &Session| 
            s.compute_round_trip_timeout(application_processing_timeout, !self.has_received_at_least_one_message())).
            and_then(|timeout| {
                self.set_response_timeout(timeout);
                chip_ok!()
            });
    }

    // Set the response timeout for the exchange context, regardless of the underlying session type. Using
    // UseSuggestedResponseTimeout to set a timeout based on the type of the session and the application processing time instead of
    // using this function is recommended.
    //
    // If a timeout of 0 is provided, it implies no response is expected. Consequently, ExchangeDelegate::OnResponseTimeout will not
    // be called.
    //
    pub fn set_response_timeout(&mut self, timeout: Timeout) {
        self.m_response_timeout = timeout;
    }

    /*
     *  Send a CHIP message on this exchange.
     *
     *  If SendMessage returns success and the message was not expecting a
     *  response, the exchange will close itself before returning, unless the
     *  message being sent is a standalone ack.  If SendMessage returns failure,
     *  the caller is responsible for deciding what to do (e.g. closing the
     *  exchange, trying to re-establish a secure session, etc).
     */
    pub fn send_message_id_type(&mut self, _protocol_id: protocols::Id, _msg_type: u8, _msg_payload: PacketBufferHandle,
        _send_flags: &SendFlags) -> ChipErrorResult {

        chip_ok!()
    }

    pub fn send_message<MsgType: MessageTypeTrait>(&mut self, msg_type: MsgType, msg_payload: PacketBufferHandle,
        send_flags: &SendFlags) -> ChipErrorResult 
        where
            u8: From<MsgType>
    {
        self.send_message_id_type(<MsgType as MessageTypeTrait>::PROTOCOL_ID, msg_type.into()
                , msg_payload, send_flags)
    }

    pub fn will_send_message(&mut self) {
        self.base_mut().m_flags.insert(Flags::KflagWillSendMessage);
    }

    pub fn get_delegaet(&self) -> Option<NonNull<dyn ExchangeDelegate + 'a>> {
        self.m_delegate
    }

    pub fn set_delegaet(&mut self, delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>) {
        self.m_delegate = delegate;
    }

    pub fn get_exchange_mgr(&self) -> Option<NonNull<ExchangeManager>> {
        self.m_exchange_mgr
    }

    pub fn get_session_handle(&self) -> SessionHandle {
        if let Some(session) = self.m_session.session_holder.get() {
            session
        } else {
            panic!("cannot get session handle");
        }
    }

    pub fn has_session_handle(&self) -> bool {
        self.m_session.session_holder.is_some()
    }

    pub fn is_send_expected(&self) -> bool {
        self.base().m_flags.intersects(Flags::KflagWillSendMessage)
    }

    #[inline]
    pub fn has_received_at_least_one_message(&self) -> bool {
        self.base().m_flags.intersects(Flags::KflagReceivedAtLeastOneMessage)
    }

    pub fn dump_to_log(&self) {
        chip_log_error!(ExchangeManager, "ExchangeContext: {} delegate={}", chip_log_value_exchange_id(self.get_exchange_id(),
        self.is_initiator()), chip_log_option_non_null(self.m_delegate));
    }

    #[inline]
    fn set_ignor_session_release(&mut self, should_ignore: bool) {
        self.base_mut().m_flags.set(Flags::KflagIgnoreSessionRelease, should_ignore);
    }

    #[inline]
    fn should_ignore_session_release(&self) -> bool {
        self.base().m_flags.intersects(Flags::KflagIgnoreSessionRelease)
    }

    #[inline]
    fn set_has_received_at_least_one_message(&mut self, has_received_message: bool) {
        self.base_mut().m_flags.set(Flags::KflagReceivedAtLeastOneMessage, has_received_message);
    }

    /*
     *  Track whether we are now expecting a response to a message sent via this exchange (because that
     *  message had the kExpectResponse flag set in its sendFlags).
     */
    fn set_response_expected(&mut self, response_expected: bool) {
        self.base_mut().m_flags.set(Flags::KflagResponseExpected, response_expected);
        self.set_waiting_for_response_or_ack(response_expected);
    }
}

impl<'a> ReliableMessageContext<'a> for ExchangeContext<'a> {
    fn base(&self) -> &BaseReliableMessageContext {
        &self.m_reliable_message_context
    }

    fn base_mut(&mut self) -> &mut BaseReliableMessageContext {
        &mut self.m_reliable_message_context
    }


    // Set if this exchange is requesting Sleepy End Device active mode
    fn set_requesting_active_mode(&mut self, _active_mode: bool) {}

    /*
     * Get the reliable message manager that corresponds to this reliable
     * message context.
     */
    fn get_reliable_message_mgr(&self) -> Option<SharedReliableMessageMgr> {
        let mgr = unsafe {
            self.m_exchange_mgr?.as_ref().get_reliable_message_mgr()
        };

        Some(mgr)
    }

    fn get_exchange_context(&mut self) -> &mut ExchangeContext<'a> {
        self
    }

    fn get_exchange_context_const(&self) -> &ExchangeContext<'a> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
} // end of mod test
