use crate::chip::transport::PeerAddress;
use crate::chip::system::system_packet_buffer::{PacketBufferHandle, PacketBuffer};
use super::raw::base::{Base,Init,MessageTransportContext,RawTransportDelegate};
use super::raw::tuple::Tuple;
use super::transport_mgr_base::TransportMgrBase;

use core::str::FromStr;
use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_detail;
use crate::chip_log_error;

use crate::ChipErrorResult;
use crate::chip_ok;

use core::ptr;

pub trait TransportMgrDelegate {
    fn on_message_received(&mut self, source: PeerAddress, msg_buf: PacketBufferHandle, ctext: * const MessageTransportContext);
}

struct TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    pub m_session_mgr: * mut SessionMgrType,
}

impl<SessionMgrType> Default for TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    fn default() -> Self {
        Self {
            m_session_mgr: ptr::null_mut(),
        }
    }
}

impl<SessionMgrType> RawTransportDelegate for TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    fn handle_message_received(&self, peer_address: PeerAddress, msg: PacketBufferHandle,
        ctxt: * const MessageTransportContext)
    {
        unsafe {
            let pb: * mut PacketBuffer = msg.get_raw();
            if (*pb).has_chained_buffer() {
                chip_log_error!(Inet, "message from {} dropped due to lower layers not ensuring a single packet buffer", peer_address);
                return;
            }

            if self.m_session_mgr.is_null() == false {
                (*self.m_session_mgr).on_message_received(peer_address, msg, ctxt);
            } else {
                chip_log_error!(Inet, "message from {} is drooped since no handler set", peer_address);
            }
        }
    }
}

pub struct TransportMgr<T, SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    m_transports: Tuple<T>,
    m_receiver: TransportMgrReceiver<SessionMgrType>,
}

macro_rules! impl_for_transport_mgr {
    ($($type:ident),+) => {
        impl<SessionMgrType, $($type,)+> TransportMgr<($($type,)+), SessionMgrType>
            where
                SessionMgrType: TransportMgrDelegate,
                $($type: Init + Base,)+
        {
            #[allow(dead_code)]
            pub fn init(&mut self, ps: ($(<$type as Init>::InitParamType,)+)) -> ChipErrorResult {
                let err = self.m_transports.init(
                    ($(ptr::addr_of_mut!(self.m_receiver) as * mut <$type as Base>::DelegateType,)+), 
                    ps);
                if err.is_success() == false {
                    return Err(err);
                }
                // we don't do anything in the base init method, just give it a null as work around
                // to the second borrow error
                let _ = <Self as TransportMgrBase>::init(self, ptr::null_mut());

                chip_ok!()
            }
        }
    };
}

macro_rules! impl_default_for_transport_mgr {
    ($($type:ident),+) => {
        impl<SessionMgrType, $($type,)+> Default for TransportMgr<($($type,)+), SessionMgrType>
            where
                SessionMgrType: TransportMgrDelegate,
                $($type: Default,)+
        {
            #[allow(dead_code)]
            fn default() -> Self {
                Self {
                    m_transports: Tuple::<($($type,)+)>::default(),
                    m_receiver: TransportMgrReceiver::<SessionMgrType>::default(),
                }
            }
        }
    };
}

macro_rules! impl_transport_mgr_base_for_transport_mgr {
    ($($type:ident),+) => {
        impl<'a, SessionMgrType, $($type,)+> TransportMgrBase<'a> for TransportMgr<($($type,)+), SessionMgrType>
            where
                SessionMgrType: TransportMgrDelegate,
                $($type: Init + Base,)+
        {
            type TransportType = Tuple<($($type,)+)>;
            type TransportMgrDelegateType = SessionMgrType;

            #[allow(dead_code)]
            fn init(&mut self, _t: * mut Self::TransportType) -> ChipErrorResult {
                chip_log_detail!(Inet, "transport mgr initialized");
                chip_ok!()
            }

            #[allow(dead_code)]
            fn send_message(&mut self, address: PeerAddress, msg_buf: PacketBufferHandle) -> ChipErrorResult {
                let err = self.m_transports.send_message(address, msg_buf);
                if err.is_success() == false {
                    return Err(err);
                }
                chip_ok!()
            }

            #[allow(dead_code)]
            fn close(&mut self) {
                self.m_transports.close();
            }

            #[allow(dead_code)]
            fn set_session_manager(&mut self, session_manager: * mut Self::TransportMgrDelegateType) {
                self.m_receiver.m_session_mgr = session_manager;
            }

            #[allow(dead_code)]
            fn get_session_manager(&mut self) -> * mut Self::TransportMgrDelegateType {
                return ptr::addr_of_mut!(self.m_receiver.m_session_mgr) as * mut Self::TransportMgrDelegateType;
            }
        }
    };
}


impl_for_transport_mgr!(Type0);
impl_for_transport_mgr!(Type0,Type1);
impl_for_transport_mgr!(Type0,Type1,Type2);

impl_default_for_transport_mgr!(Type0);
impl_default_for_transport_mgr!(Type0,Type1);
impl_default_for_transport_mgr!(Type0,Type1,Type2);

impl_transport_mgr_base_for_transport_mgr!(Type0);
impl_transport_mgr_base_for_transport_mgr!(Type0,Type1);
impl_transport_mgr_base_for_transport_mgr!(Type0,Type1,Type2);

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  use crate::chip::transport::raw::test::{Test, TestListenParameter};
  use crate::chip::inet::test_end_point::TestEndPointManager;
  use crate::chip::inet::inet_layer::EndPointManager;
  use crate::chip::platform::global::system_layer;
  use crate::chip::system::system_layer::Layer;
  use crate::chip::transport::raw::tuple::Tuple;
  use crate::chip::inet::end_point_basis::DefaultWithMgr;

  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();
  static mut TEST_PARAMS_1: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();
  static mut TEST_PARAMS_2: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();

  pub struct SessionMgrStub
  {}

  impl SessionMgrStub {
      pub const fn const_default() -> Self {
          Self {}
      }
  }

  impl TransportMgrDelegate for SessionMgrStub {
    fn on_message_received(&mut self, _source: PeerAddress, _msg_buf: PacketBufferHandle, _ctext: * const MessageTransportContext)
    {}
  }

  //type TransType = Test<TransportMgrReceiver<SessionMgrStub>>;
  type MgrType = TransportMgr<(Test<TransportMgrReceiver<SessionMgrStub>>,Test<TransportMgrReceiver<SessionMgrStub>>), SessionMgrStub>;
  static mut TRANS_MGR: mem::MaybeUninit<MgrType> = mem::MaybeUninit::uninit();
  static mut SESSION_MGR: SessionMgrStub = SessionMgrStub::const_default();

  fn set_up() {
      unsafe {
          /* reinit system layer */
          let sl = system_layer();
          (*sl).init();

          /* reinit end point manager */
          END_POINT_MANAGER = TestEndPointManager::default();
          END_POINT_MANAGER.init(system_layer());

          /* reinit the test transport */
          TEST_PARAMS_1.write(TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)));
          TEST_PARAMS_2.write(TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)));

          /* reinit the transport manager */
          TRANS_MGR.write(MgrType::default());
          SESSION_MGR = SessionMgrStub::const_default();
      }
  }

  #[test]
  fn init() {
      unsafe {
          set_up();
          let tm = TRANS_MGR.assume_init_mut();
          tm.m_receiver.m_session_mgr = ptr::addr_of_mut!(SESSION_MGR);
          assert_eq!(true, tm.init((TEST_PARAMS_1.assume_init_mut().clone(), TEST_PARAMS_2.assume_init_mut().clone())).is_ok());
      }
  }
}
