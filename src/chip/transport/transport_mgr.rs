use crate::chip::transport::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use super::raw::base::{Base,Init,MessageTransportContext,RawTransportDelegate};
use super::raw::tuple::Tuple;

use crate::ChipErrorResult;
use crate::chip_ok;

use core::ptr;

pub trait TransportMgrDelegate {
    fn on_message_received(&mut self, source: &PeerAddress, msg_buf: PacketBufferHandle, ctext: &MessageTransportContext);
}

pub struct TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    m_session_mgr: * mut SessionMgrType,
}

impl<SessionMgrType> Default for TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    fn default() -> Self {
        Self {
            m_session_mgr: ptr::null_ptr_mut(),
        }
    }
}

impl<SessionMgrType> RawTransportDelegate for TransportMgrReceiver<SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    fn handle_message_received(&self, peer_address: PeerAddress, msg: PacketBufferHandle,
        ctxt: * const MessageTransportContext)
    {}
}

pub struct TransportMgr<T, SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    m_transports: Tuple<T>,
    m_receiver: TransportMgrReceiver<SessionMgrType>,
}

impl<T, SessionMgrType> Default for TransportMgr<T, SessionMgrType>
where
    SessionMgrType: TransportMgrDelegate,
{
    fn default() -> Self {
        Self {
            m_transports: Tuple::<T>::default(),
            m_receiver: TransportMgrReceiver::<SessionMgrType>::default(),
        }
    }
}

/*
impl<SessionMgrType, Type0> TransportMgr<(Type0,), SessionMgrType> 
where
    Type0: Init + Base,
    SessionMgrType: TransportMgrDelegate,
{
    pub fn init(&mut self, p0: <Type0 as Init>::InitParamType) -> ChipErrorResult {
        unsafe {
            let err = self.m_transports.init((ptr::addr_of!(self.m_receiver) as * mut <Type0 as Base>::DelegateType,), (p0,));
            if err.is_success() == false {
                return Err(err);
            }
        }

        chip_ok!()
    }
}
*/

macro_rules! impl_for_transport_mgr {
    ($($type:ident),+) => {
        impl<SessionMgrType, $($type,)+> TransportMgr<($($type,)+), SessionMgrType>
            where
                SessionMgrType: TransportMgrDelegate,
                $($type: Init + Base,)+
        {
            #[allow(dead_code)]
            pub fn init(&mut self, ps: ($(<$type as Init>::InitParamType,)+)) -> ChipErrorResult {
                unsafe {
                    let err = self.m_transports.init(
                        ($(ptr::addr_of_mut!(self.m_receiver) as * mut <$type as Base>::DelegateType,)+), 
                        ps);
                    if err.is_success() == false {
                        return Err(err);
                    }
                }

                chip_ok!()
            }
        }
    };
}

impl_for_transport_mgr!(Type0);
impl_for_transport_mgr!(Type0, Type1);

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
    fn on_message_received(&mut self, _source: &PeerAddress, _msg_buf: PacketBufferHandle, _ctext: &MessageTransportContext)
    {}
  }

  type MgrType = TransportMgr<(Test<TransportMgrReceiver<SessionMgrStub>>,), SessionMgrStub>;
  static mut TRANS_MGR: mem::MaybeUninit<MgrType> = mem::MaybeUninit::uninit();

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
      }
  }

  #[test]
  fn init() {
      /*
      let tm: MgrType;
      let tp: TestListenParameter<MgrType> = TestListenParameter<MgrType>::default();
      assert_eq!(true, tm.init(tp).is_ok());
      */
  }
}
