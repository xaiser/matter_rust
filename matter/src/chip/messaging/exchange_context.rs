use crate::{
    chip::{
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
};

use core::ptr::NonNull;
use core::cell::{Ref, RefMut};


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
        self.m_session.with::<Session, bool>(|s| s.is_group_session()).is_ok_and(|b| b)
    }

    pub fn get_exchange_id(&self) -> u16 {
        0
    }

    pub fn is_initiator(&self) -> bool {
        false
    }

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
}
