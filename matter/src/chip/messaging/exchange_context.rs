use crate::{
    chip::{
        system::{
            system_packet_buffer::PacketBufferHandle,
            system_layer::TimerCallbackContext,
            system_clock::{
                Timeout,
            },
        },
        protocols::{
            self, protocols::MessageTypeTrait,
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
                SessionHandle,
            },
        },
    },
    ChipErrorResult,
};

use core::ptr::NonNull;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AccessError {
    Invalid,
    Deny,
}

pub trait Access {
    fn with<R>(&self, f: impl Fn(&exchange_context::ExchangeContext) -> R) -> Result<R, AccessError>;
    fn with_mut<R>(&mut self, f: impl Fn(&mut exchange_context::ExchangeContext) -> R) -> Result<R, AccessError>;
}

pub trait ExchangeContextTrait<'a, 'b> {
    fn is_encryption_required(&self) -> bool;

    fn is_group_exchange_context(&self) -> bool;

    fn get_exchange_id(&self) -> u16;

    fn is_initiator(&self) -> bool;

    fn is_response_expected(&self) -> bool;

    fn use_suggested_response_timeout(&mut self, application_processing_timeout: Timeout);

    fn set_response_timeout(&mut self, timeout: Timeout);

    fn send_message_id_type(&mut self, protocol_id: protocols::Id, msg_type: u8, msg_payload: PacketBufferHandle,
            send_flags: &SendFlags) -> ChipErrorResult;

    fn send_message<MsgType: MessageTypeTrait>(&mut self, msg_type: MsgType, msg_payload: PacketBufferHandle,
        send_flags: &SendFlags) -> ChipErrorResult 
        where
            u8: From<MsgType>
    {
        self.send_message_id_type(<MsgType as MessageTypeTrait>::PROTOCOL_ID, msg_type.into()
                , msg_payload, send_flags)
    }

    fn will_send_message(&mut self);

    fn get_delegaet(&self) -> Option<NonNull<dyn ExchangeDelegate + 'a>>;

    fn set_delegaet(&mut self, delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>);

    fn get_exchange_mgr(&self) -> Option<NonNull<ExchangeManager<'b>>>;

    fn get_session_handle(&self) -> SessionHandle;

    fn has_session_handle(&self) -> bool;

    fn is_send_expected(&self) -> bool;

    fn has_received_at_least_one_message(&self) -> bool;

    fn dump_to_log(&self);

    fn get_reliable_messaeg_context(&self) -> *const impl ReliableMessageContext<'_, '_>;

    fn notify_response_timeout(&mut self, close_if_needed: bool);

    fn close(&mut self);

    fn abort(&mut self);
}

pub mod shared {
    use super::{
        Access,
        AccessError,
        exchange_context::ExchangeContext,
    };
    use crate::{
        chip::{
            chip_lib::{
                core::reference_counted::rc::{DefaultAlloactor, Rc, Weak},
            },
        }
    };

    use core::cell::RefCell;

    const ALLOACTOR_CAP: usize = 10;
    pub type Alloactor<'a, 'b> = DefaultAlloactor<RefCell<ExchangeContext<'a, 'b>>, ALLOACTOR_CAP>;
    pub type SharedExchangeContext<'a, 'b> = Rc<RefCell<ExchangeContext<'a, 'b>>, Alloactor<'a, 'b>>;
    //pub type WeakSharedExchangeContext<'a, 'b> = Weak<RefCell<ExchangeContext<'a, 'b>>, Alloactor<'a, 'b>>;

    pub fn try_new_shared<'a, 'b>(ec: ExchangeContext<'a, 'b>, allocator: * mut Alloactor<'a, 'b>) -> Result<SharedExchangeContext<'a, 'b>, ()> 
        // a rustc bug trigger by generic_const_exprs, this is the workaround suggested by AI
        where
            'a: 'a,
            'b: 'b,
    {
        SharedExchangeContext::try_new_in(RefCell::new(ec), allocator)
    }

    /*
    pub struct WeakExchangeContextHandle<'a, 'b> {
        ec: WeakSharedExchangeContext<'a, 'b>,
    }

    impl Access for WeakExchangeContextHandle<'_, '_> {
        fn with<R>(&self, f: impl Fn(&ExchangeContext) -> R) -> Result<R, AccessError> {
            if let Some(shared_handle) = self.ec.upgrade() {
                if let Ok(handle) = shared_handle.try_borrow() {
                    return Ok(f(&(*handle)));
                } else {
                    return Err(AccessError::Deny);
                }
            } else {
                return Err(AccessError::Invalid);
            }
        }

        fn with_mut<R>(&mut self, f: impl Fn(&mut ExchangeContext) -> R) -> Result<R, AccessError> {
            if let Some(shared_handle) = self.ec.upgrade() {
                if let Ok(mut handle) = shared_handle.try_borrow_mut() {
                    return Ok(f(&mut (*handle)));
                } else {
                    return Err(AccessError::Deny);
                }
            } else {
                return Err(AccessError::Invalid);
            }
        }
    }
    */

    pub struct ExchangeContextHandle<'a, 'b> {
        ec: SharedExchangeContext<'a, 'b>,
    }

    impl Access for ExchangeContextHandle<'_, '_> {
        fn with<R>(&self, f: impl Fn(&ExchangeContext) -> R) -> Result<R, AccessError> {
            if let Ok(handle) = self.ec.try_borrow() {
                return Ok(f(&(*handle)));
            } else {
                return Err(AccessError::Deny);
            }
        }

        fn with_mut<R>(&mut self, f: impl Fn(&mut ExchangeContext) -> R) -> Result<R, AccessError> {
            if let Ok(mut handle) = self.ec.try_borrow_mut() {
                return Ok(f(&mut (*handle)));
            } else {
                return Err(AccessError::Deny);
            }
        }
    }
}

pub mod exchange_context {
    use super::ExchangeContextTrait;
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
                system_layer::{Layer, TimerCallbackContext},
                LayerImpl,
                system_clock::{
                    Timeout,
                },
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
            platform::assert_chip_stack_locked_by_current_thread,
        },
        ChipErrorResult, chip_ok,
        chip_error_invalid_argument,
        chip_error_internal,
        chip_error_incorrect_state,
        chip_error_missing_secure_session,
        chip_core_error, chip_sdk_error,
        verify_or_die,
        verify_or_return_value,
        verify_or_return_error,
        system_stats_increment,
        system_stats_decrement,

        chip_internal_log,
        chip_internal_log_impl,
        chip_log_error,
    };

    #[cfg(feature="chip_exchange_context_detail_logging")]
    use crate::chip_log_detail;

    use core::str::FromStr;
    use core::ptr::{self, NonNull};
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

    pub fn handle_response_timeout(_system_layer: *mut u8, app_state: TimerCallbackContext) {
        let ptr: *mut ExchangeContext = app_state.cast();

        unsafe {
            if let Some(ec) = ptr.as_mut() {
                ec.notify_response_timeout(true);
            }
        }
    }

    pub struct ExchangeContext<'a, 'b> {
        m_response_timeout: Timeout,
        m_delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>,
        m_exchange_mgr: Option<NonNull<ExchangeManager<'b>>>,
        m_dispatch: ExchangeMessageDispatchHandle,
        m_session: ExchangeSessionHolder,
        m_exchange_id: u16,
        m_reliable_message_context: BaseReliableMessageContext,
    }

    impl<'a, 'b> Drop for ExchangeContext<'a, 'b> {
        fn drop(&mut self) {
            //
            // Ensure that DoClose has been called by the time we get here. If not, we have a leak somewhere.
            //
            verify_or_die!(self.base().m_flags.intersects(Flags::KflagClosed));

            // Ideally, in this scenario, the retransmit table should
            // be clear of any outstanding messages for this context and
            // the boolean parameter passed to DoClose() should not matter.
            self.do_close(false);
            self.m_exchange_mgr = None;

            #[cfg(feature="chip_exchange_context_detail_logging")]
            {
                chip_log_detail!(ExchangeManager, "ec-- id: {}", chip_log_value_exchange(self));
            }

            system_stats_decrement!(crate::chip::system::system_stats::Stats::KexchangeMgrNumContext);
        }
    }

    impl<'a, 'b> ExchangeContext<'a, 'b> {
        pub const fn new() -> Self {
            Self {
                m_response_timeout: Timeout::from_secs(0),
                m_delegate: None,
                m_exchange_mgr: None,
                m_dispatch: ExchangeMessageDispatchHandle::new_application_exchange_dispatch(),
                m_session: ExchangeSessionHolder::new(),
                m_exchange_id: 0,
                m_reliable_message_context: BaseReliableMessageContext::new(),
            }
        }

        pub fn new_with(em: Option<NonNull<ExchangeManager<'b>>>, exchange_id: u16, session: SessionHandle, initiator: bool,
            delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>, is_ephemeral_exchange: bool) -> Self
        {
            let mut ec = Self::new();

            ec.m_dispatch = Self::get_message_dispatch(is_ephemeral_exchange, delegate);
            ec.m_session = ExchangeSessionHolder::new_with(ptr::addr_of_mut!(ec) as _);

            ec.m_exchange_mgr = em;
            ec.m_exchange_id = exchange_id;

            let is_allow_mrp = session.with(|s: &Session| s.allows_mrp()).is_ok_and(|b| b);

            if ec.m_session.session_holder.grab(session).is_err() {
                panic!("cannot grab session in exchange context");
            }

            ec.base_mut().m_flags.insert(Flags::KflagInitiator);
            ec.base_mut().m_flags.set(Flags::KflagEphemeralExchange, is_ephemeral_exchange);
            ec.m_delegate = delegate;

            //
            // If we're an initiator and we just created this exchange, we obviously did so to send a message. Let's go ahead and
            // set the flag on this to correctly mark it as so.
            //
            // This only applies to non-ephemeral exchanges. Ephemeral exchanges do not have an intention of sending out a message
            // since they're created expressly for the purposes of sending out a standalone ACK when the message could not be handled
            // through normal means.
            //
            if initiator && !is_ephemeral_exchange {
                ec.will_send_message();
            }

            ec.set_ack_pending(false);

            // Try to use MRP by default, if it is allowed.
            ec.set_auto_request_ack(is_allow_mrp);

            #[cfg(feature="chip_exchange_context_detail_logging")]
            {
                chip_log_detail!(ExchangeManager, "ec++ id: {}", chip_log_value_exchange(&ec));
            }

            system_stats_increment!(crate::chip::system::system_stats::Stats::KexchangeMgrNumContext);

            ec
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

        fn get_message_dispatch(is_ephemeral_exchange: bool, delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>) -> ExchangeMessageDispatchHandle {
            if is_ephemeral_exchange {
                return ExchangeMessageDispatchHandle::new_ephemeral_exchange_dispatch();
            }

            if let Some(ptr) = delegate {
                unsafe {
                    return ptr.as_ref().get_message_dispatch();
                }
            }

            ExchangeMessageDispatchHandle::new_application_exchange_dispatch()
        }

        fn do_close(&mut self, clear_retrans_table: bool) {
            if self.base().m_flags.intersects(Flags::KflagClosed) {
                return;
            }

            self.base_mut().m_flags.insert(Flags::KflagClosed);

            // Clear protocol callbacks
            if let Some(mut delegate) = self.m_delegate.take() {
                unsafe {
                    delegate.as_mut().on_exchange_closing(self);
                }
            }

            // Closure of an exchange context is based on ref counting. The Protocol, when it calls DoClose(), indicates that
            // it is done with the exchange context and the message layer sets all callbacks to NULL and does not send anything
            // received on the exchange context up to higher layers.  At this point, the message layer needs to handle the
            // remaining work to be done on that exchange, (e.g. send all pending acks) before truly cleaning it up.
            let _ = self.flush_acks();

            if clear_retrans_table {
                if let Some(mgr) = self.m_exchange_mgr {
                    let rm_mgr = unsafe {
                        mgr.as_ref().get_reliable_message_mgr().as_mut()
                    };
                    rm_mgr.clear_retrans_table(self);
                } else {
                    chip_log_error!(ExchangeManager, "cannot get mgr in clear retrans table");
                }
            }

            if self.is_response_expected() {
                // Cancel the response timer.
                self.cancel_response_timer();
            }
        }

        fn start_response_timer(&self) -> ChipErrorResult {
            unsafe {
                if let Some(exchange_mgr) = self.m_exchange_mgr &&
                    let Some(session_mgr) = exchange_mgr.as_ref().get_session_manager() &&
                        let Some(system) = session_mgr.system_layer()
                {
                    system.start_timer(self.m_response_timeout, handle_response_timeout, self as *const Self as TimerCallbackContext);
                    return chip_ok!();
                } else {
                    chip_log_error!(ExchangeManager, "cannot get system layer in start timer");
                    return Err(chip_error_internal!());
                }
            }
        }

        fn cancel_response_timer(&self) {
            unsafe {
                if let Some(exchange_mgr) = self.m_exchange_mgr &&
                    let Some(session_mgr) = exchange_mgr.as_ref().get_session_manager() &&
                        let Some(system) = session_mgr.system_layer()
                {
                    system.cancel_timer(handle_response_timeout, self as *const Self as TimerCallbackContext);
                } else {
                    chip_log_error!(ExchangeManager, "cannot get system layer in cancel timer");
                    return;
                }
            }
        }

        fn message_handle(&mut self) {
            if self.base().m_flags.intersects(Flags::KflagClosed) || self.is_response_expected() || self.is_send_expected() {
                return;
            }

            self.close();
        }
    }

    impl<'a, 'b> ExchangeContextTrait<'a, 'b> for ExchangeContext<'a, 'b> {
        fn is_encryption_required(&self) -> bool {
            self.m_dispatch.is_encryption_required()
        }

        fn is_group_exchange_context(&self) -> bool {
            self.m_session.with(|s: &Session| s.is_group_session()).is_ok_and(|b| b)
        }

        fn get_exchange_id(&self) -> u16 {
            self.m_exchange_id
        }

        fn is_initiator(&self) -> bool {
            self.base().m_flags.intersects(Flags::KflagInitiator)
        }

        fn is_response_expected(&self) -> bool {
            self.base().m_flags.intersects(Flags::KflagResponseExpected)
        }

        // Applies a suggested response timeout value based on the session type and the given upper layer processing time for
        // the next message to the exchange. The exchange context must have a valid session when calling this function.
        //
        // This function is an equivalent of SetResponseTimeout(mSession->ComputeRoundTripTimeout(applicationProcessingTimeout))
        fn use_suggested_response_timeout(&mut self, application_processing_timeout: Timeout) {
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
        fn set_response_timeout(&mut self, timeout: Timeout) {
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
        fn send_message_id_type(&mut self, protocol_id: protocols::Id, msg_type: u8, msg_payload: PacketBufferHandle,
            send_flags: &SendFlags) -> ChipErrorResult
        {
            // This is the first point all outgoing messages funnel through.  Ensure
            // that our message sends are all synchronized correctly.
            assert_chip_stack_locked_by_current_thread();

            let is_standalone_ack = 
                (protocol_id == protocols::secure_channel::ID) && msg_type == u8::from(protocols::secure_channel::MsgType::StandaloneAck);

            let exchange_mgr = {
                if let Some(mut mgr_ptr) = self.m_exchange_mgr {
                    unsafe { mgr_ptr.as_mut() }
                } else {
                    return Err(chip_error_internal!());
                }
            };

            verify_or_return_error!(self.m_session.session_holder.is_some(), Err(chip_error_internal!()));

            // should increase ref count
            
            // If session requires MRP, NoAutoRequestAck send flag is not specified and is not a group exchange context, request reliable
            // transmission.
            let reliable_transmission_requested = 
                self.m_session.with(|s: &Session| s.allows_mrp()).is_ok_and(|b| b) && !send_flags.intersects(SendFlags::KnoAutoRequestAck) && !self.is_group_exchange_context();

            let current_message_expect_response = {
                // If a response message is expected...
                if send_flags.intersects(SendFlags::KexpectResponse) && !self.is_group_exchange_context() {
                    // Only one 'response expected' message can be outstanding at a time.
                    if self.is_response_expected() {
                        // TODO: add a test for this case.
                        return Err(chip_error_incorrect_state!());
                    }

                    self.set_response_expected(true);

                    // Arm the response timer if a timeout has been specified.
                    if self.m_response_timeout > Timeout::ZERO {
                        self.start_response_timer().inspect_err(|_| self.set_response_expected(false) )?;

                        true
                    } else { false }
                } else { false }
            };

            {
                // ExchangeContext for group are supposed to always be Initiator
                if self.is_group_exchange_context() && !self.is_initiator() {
                    return Err(chip_error_internal!());
                }

                //
                // It is possible that we might have evicted a session as a side-effect of processing an inbound message on this exchange.
                // We cannot proceed any further sending a message since we don't have an attached session, so let's error out.
                //
                // This should not happen to well-behaved logic attempting to sending messages on exchanges, so let's print out a warning
                // to ensure it alerts someone to fixing their logic...
                //
                // Why we need to check this again?
                if !self.m_session.session_holder.is_some() {
                    chip_log_error!(ExchangeManager, "WARNING: We shouldn't be sending a message on an exchange that has no attached session...");
                    return Err(chip_error_missing_secure_session!());
                }

                let session = self.get_session_handle();
                //match self.m_dispatch.send_message(
            }

            chip_ok!()
        }

        fn will_send_message(&mut self) {
            self.base_mut().m_flags.insert(Flags::KflagWillSendMessage);
        }

        fn get_delegaet(&self) -> Option<NonNull<dyn ExchangeDelegate + 'a>> {
            self.m_delegate
        }

        fn set_delegaet(&mut self, delegate: Option<NonNull<dyn ExchangeDelegate + 'a>>) {
            self.m_delegate = delegate;
        }

        fn get_exchange_mgr(&self) -> Option<NonNull<ExchangeManager<'b>>> {
            self.m_exchange_mgr
        }

        fn get_session_handle(&self) -> SessionHandle {
            if let Some(session) = self.m_session.session_holder.get() {
                session
            } else {
                panic!("cannot get session handle");
            }
        }

        fn has_session_handle(&self) -> bool {
            self.m_session.session_holder.is_some()
        }

        fn is_send_expected(&self) -> bool {
            self.base().m_flags.intersects(Flags::KflagWillSendMessage)
        }

        fn has_received_at_least_one_message(&self) -> bool {
            self.base().m_flags.intersects(Flags::KflagReceivedAtLeastOneMessage)
        }

        fn dump_to_log(&self) {
            chip_log_error!(ExchangeManager, "ExchangeContext: {} delegate={}", chip_log_value_exchange_id(self.get_exchange_id(),
            self.is_initiator()), chip_log_option_non_null(self.m_delegate));
        }

        fn get_reliable_messaeg_context(&self) -> *const impl ReliableMessageContext<'_, '_> {
            self as _
        }

        fn notify_response_timeout(&mut self, _close_if_needed: bool) {
        }

        fn close(&mut self) {
            #[cfg(feature="chip_exchange_context_detail_logging")]
            {
                chip_log_detail!(ExchangeManager, "ec - close[{}]", chip_log_value_exchange(self));
            }

            self.do_close(false);
            // should release()
        }

        fn abort(&mut self) {
            #[cfg(feature="chip_exchange_context_detail_logging")]
            {
                chip_log_detail!(ExchangeManager, "ec - abort[{}]", chip_log_value_exchange(self));
            }

            self.do_close(true);
            // should release()
        }
    }

    impl<'a, 'b> ReliableMessageContext<'a, 'b> for ExchangeContext<'a, 'b> {
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

        fn get_exchange_context(&mut self) -> &mut ExchangeContext<'a, 'b> {
            self
        }

        fn get_exchange_context_const(&self) -> &ExchangeContext<'a, 'b> {
            self
        }
    }


    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            chip::{
                chip_lib::{
                    core::{
                        case_auth_tag::CATValues,
                    },
                },
                messaging::{
                    exchange_mgr::ExchangeManager,
                    reliable_message_protocol_config::ReliableMessageProtocolConfig,
                    exchange_message_dispatch::ExchangeMessageDispatchHandle,
                    exchange_context::{
                        exchange_context::ExchangeContext,
                    },
                    exchange_delegate::ExchangeDelegate,
                },
                transport::{
                    raw::{
                        message_header::PayloadHeader,
                    },
                    secure_session_table::SecureSessionTable,
                    secure_session,
                    session_mgr::SessionManagerTrait,
                    session::{
                        SessionHandle, SharedSession,
                    },
                },
                system::{
                    system_packet_buffer::PacketBufferHandle,
                    system_layer::{Layer, TimerCallbackContext, TimerCompleteCallback},
                    system_clock::{
                        Timeout,
                    },
                },
                FabricIndex, ScopedNodeId,
            },

            ChipErrorResult, chip_ok, ChipError,
            chip_core_error, chip_sdk_error,
        };

        use core::ptr::{NonNull, addr_of, addr_eq, null_mut};

        struct MockSystemLayer {
            pub ec: TimerCallbackContext,
        }

        impl MockSystemLayer {
            pub fn new() -> Self {
                Self {
                    ec: null_mut(),
                }
            }
        }

        impl Layer for MockSystemLayer {

            fn init(&mut self) -> ChipErrorResult {
                self.ec = null_mut();
                chip_ok!()
            }

            fn shutdown(&mut self) {}

            fn is_initialized(&self) -> bool { true }

            fn start_timer(&mut self, _delay: Timeout, _complete: TimerCompleteCallback, app_state: TimerCallbackContext) {
                self.ec = app_state;
            }

            fn cancel_timer(&mut self, complete: TimerCompleteCallback, app_state: TimerCallbackContext) {
                self.ec = null_mut();
            }
        }

        struct MockSessionMgr {
            pub system_layer: MockSystemLayer,
        }

        impl MockSessionMgr {
            pub fn new() -> Self {
                Self {
                    system_layer: MockSystemLayer::new(),
                }
            }
        }

        impl SessionManagerTrait for MockSessionMgr {
            fn fabric_removed(&mut self, _fabric_index: FabricIndex) {}

            fn for_each_matching_session(&mut self, _node: &ScopedNodeId, _f: &mut dyn FnMut(&SharedSession)) {}

            fn for_each_matching_session_const(&self, _node: &ScopedNodeId, _f: &mut dyn FnMut(&SharedSession)) {}

            fn for_each_matching_fabric_index_session(&mut self, _fabric_index: FabricIndex, _f: &mut dyn FnMut(&SharedSession)) {}

            fn for_each_matching_fabric_index_session_const(&self, _fabric_index: FabricIndex, _f: &mut dyn FnMut(&SharedSession)) {}

            fn for_each_matching_session_on_logical_fabric(&mut self, _node: &ScopedNodeId, _f: &mut dyn FnMut(&SharedSession)) -> ChipErrorResult { chip_ok!() }

            fn for_each_matching_session_on_logical_fabric_const(&self, _node: &ScopedNodeId, _f: &mut dyn FnMut(&SharedSession)) -> ChipErrorResult { chip_ok!() }

            fn for_each_matching_fabric_index_session_on_logical_fabric(&mut self, _fabric_index: FabricIndex, _f: &mut dyn FnMut(&SharedSession)) -> ChipErrorResult { chip_ok!() }

            fn for_each_matching_fabric_index_session_on_logical_fabric_const(&self, _fabric_index: FabricIndex, _f: &mut dyn FnMut(&SharedSession)) -> ChipErrorResult { chip_ok!() }

            fn system_layer(&mut self) -> Option<&mut dyn Layer> { Some(&mut self.system_layer as _) }
        }

        struct MockDelegate {
            pub on_exchange_closing_calls: usize,
        }

        impl MockDelegate {
            pub const fn new() -> Self {
                Self {
                    on_exchange_closing_calls: 0,
                }
            }
        }

        impl ExchangeDelegate for MockDelegate {
            fn on_message_received(&mut self, _ec: &mut ExchangeContext, _payload_header: &PayloadHeader, _payload: PacketBufferHandle) -> ChipErrorResult {
                chip_ok!()
            }

            fn on_response_timeout(&mut self, _ec: &mut ExchangeContext) {
            }

            fn on_exchange_closing(&mut self, _ec: &mut ExchangeContext) {
                self.on_exchange_closing_calls += 1;
            }

            fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle {
                ExchangeMessageDispatchHandle::new_application_exchange_dispatch()
            }
        }

        fn get_session_handle(table: &mut SecureSessionTable) -> SessionHandle {
            let cat = CATValues::new();
            let config = ReliableMessageProtocolConfig::new();
            let ss = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 0, 1, 2, cat, 1, 2, &config);
            assert!(ss.is_some());
            let ss = ss.unwrap();
            let sh = SessionHandle::new_with(&ss);

            sh
        }

        #[test]
        fn new() {
            let mgr = ExchangeManager::new();
            let id = 1u16;

            // to create a secure session
            let mut table = SecureSessionTable::new();
            let sh = get_session_handle(&mut table);

            // delegate
            let delegate = MockDelegate::new();

            let mut ec = ExchangeContext::new_with(Some(NonNull::from_ref(&mgr)), id, sh, true, Some(NonNull::from_ref(&delegate)), false);

            assert_eq!(id, ec.get_exchange_id());

            // must close it for safe drop
            ec.do_close(false);
        }

        #[test]
        fn reliable_compare() {
            let mgr = ExchangeManager::new();
            let id = 1u16;

            // to create a secure session
            let mut table = SecureSessionTable::new();
            let sh = get_session_handle(&mut table);

            // delegate
            let delegate = MockDelegate::new();

            let mut ec = ExchangeContext::new_with(Some(NonNull::from_ref(&mgr)), id, sh, true, Some(NonNull::from_ref(&delegate)), false);

            let ep = addr_of!(ec);
            let rp: *const dyn crate::chip::messaging::reliable_message_context::ReliableMessageContext = addr_of!(ec) as _;

            assert!(addr_eq(ep, rp));

            // must close it for safe drop
            ec.do_close(false);
        }

        #[test]
        fn do_clsoe() {
            let mut mgr = ExchangeManager::new();
            let session_mgr = MockSessionMgr::new();
            let _ = mgr.init(NonNull::from_ref(&session_mgr));

            let id = 1u16;

            // to create a secure session
            let mut table = SecureSessionTable::new();
            let sh = get_session_handle(&mut table);

            // delegate
            let delegate = MockDelegate::new();

            let mut ec = ExchangeContext::new_with(Some(NonNull::from_ref(&mgr)), id, sh, true, Some(NonNull::from_ref(&delegate)), false);
            ec.set_response_expected(true);
            assert!(ec.start_response_timer().is_ok());

            assert_eq!(0, delegate.on_exchange_closing_calls);
            assert_eq!(ptr::addr_of!(ec).cast(), session_mgr.system_layer.ec);
            ec.do_close(true);
            assert_eq!(1, delegate.on_exchange_closing_calls);
            assert_eq!(null_mut(), session_mgr.system_layer.ec);
        }

        #[test]
        fn do_clsoe_twice() {
            let mut mgr = ExchangeManager::new();
            let session_mgr = MockSessionMgr::new();
            let _ = mgr.init(NonNull::from_ref(&session_mgr));

            let id = 1u16;

            // to create a secure session
            let mut table = SecureSessionTable::new();
            let sh = get_session_handle(&mut table);

            // delegate
            let delegate = MockDelegate::new();

            let mut ec = ExchangeContext::new_with(Some(NonNull::from_ref(&mgr)), id, sh, true, Some(NonNull::from_ref(&delegate)), false);
            ec.set_response_expected(true);
            assert!(ec.start_response_timer().is_ok());

            assert_eq!(0, delegate.on_exchange_closing_calls);
            assert_eq!(ptr::addr_of!(ec).cast(), session_mgr.system_layer.ec);
            ec.do_close(true);
            assert_eq!(1, delegate.on_exchange_closing_calls);
            assert_eq!(null_mut(), session_mgr.system_layer.ec);

            ec.do_close(true);
            assert_eq!(1, delegate.on_exchange_closing_calls);
        }
    } // end of mod tests
} // end of mod exchange context

