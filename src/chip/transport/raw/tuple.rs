use super::base::{Init,RawTransportDelegate,Base,MessageTransportContext};
use super::peer_address::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use core::marker::PhantomData;
use crate::ChipError;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_no_message_handler;

struct Tuple<DelegateType, T>
where
    DelegateType: RawTransportDelegate,
{
    m_transports: T,
    phantom: PhantomData<DelegateType>,
}

impl<Type0, DelegateType> Tuple<DelegateType, (Type0,)>
    where
        Type0: Init<DelegateType> + Base<DelegateType>,
        DelegateType: RawTransportDelegate,
{
    pub fn init(&mut self, delegate: * mut DelegateType, p0: <Type0 as Init<DelegateType>>::InitParamType) -> ChipError
    {
        let err = self.m_transports.0.init(p0);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.0.set_delegate(delegate);
        return err;
    }
}

impl<Type0, Type1, DelegateType> Tuple<DelegateType, (Type0,Type1)>
    where
        Type0: Init<DelegateType> + Base<DelegateType>,
        Type1: Init<DelegateType> + Base<DelegateType>,
        DelegateType: RawTransportDelegate,
{
    pub fn init(&mut self, delegate: * mut DelegateType, p0: <Type0 as Init<DelegateType>>::InitParamType, p1: <Type1 as Init<DelegateType>>::InitParamType) -> ChipError
    {
        let err = self.m_transports.0.init(p0);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.0.set_delegate(delegate);
        let err = self.m_transports.1.init(p1);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.1.set_delegate(delegate);
        return err;
    }
}

impl<Type0, Type1, Type2, DelegateType> Tuple<DelegateType, (Type0,Type1,Type2)>
    where
        Type0: Init<DelegateType> + Base<DelegateType>,
        Type1: Init<DelegateType> + Base<DelegateType>,
        Type2: Init<DelegateType> + Base<DelegateType>,
        DelegateType: RawTransportDelegate,
{
    pub fn init(&mut self, delegate: * mut DelegateType, p0: <Type0 as Init<DelegateType>>::InitParamType, p1: <Type1 as Init<DelegateType>>::InitParamType, p2: <Type2 as Init<DelegateType>>::InitParamType) -> ChipError
    {
        let err = self.m_transports.0.init(p0);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.0.set_delegate(delegate);
        let err = self.m_transports.1.init(p1);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.1.set_delegate(delegate);
        let err = self.m_transports.2.init(p2);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.2.set_delegate(delegate);
        return err;
    }
}

impl<Type0, Type1, Type2, Type3, DelegateType> Tuple<DelegateType, (Type0,Type1,Type2,Type3)>
    where
        Type0: Init<DelegateType> + Base<DelegateType>,
        Type1: Init<DelegateType> + Base<DelegateType>,
        Type2: Init<DelegateType> + Base<DelegateType>,
        Type3: Init<DelegateType> + Base<DelegateType>,
        DelegateType: RawTransportDelegate,
{
    pub fn init(&mut self, delegate: * mut DelegateType,
        p0: <Type0 as Init<DelegateType>>::InitParamType,
        p1: <Type1 as Init<DelegateType>>::InitParamType,
        p2: <Type2 as Init<DelegateType>>::InitParamType,
        p3: <Type3 as Init<DelegateType>>::InitParamType) -> ChipError
    {
        let err = self.m_transports.0.init(p0);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.0.set_delegate(delegate);
        let err = self.m_transports.1.init(p1);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.1.set_delegate(delegate);
        let err = self.m_transports.2.init(p2);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.2.set_delegate(delegate);
        let err = self.m_transports.3.init(p3);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.3.set_delegate(delegate);
        return err;
    }
}

macro_rules! impl_base_for_tuple {
    ($delegate:ident; $($index:tt: $type:ident),+) => {
        impl<$($type,)+ $delegate> Base<$delegate> for Tuple<$delegate, ($($type,)+)>
            where
                $($type: Init<$delegate> + Base<$delegate>,)+
                $delegate: RawTransportDelegate,
                {
                    fn set_delegate(&mut self, _delegate: * mut $delegate) { }

                    fn close(&mut self) {
                        $(self.m_transports.$index.close();)+
                    }

                    fn send_message(&mut self, peer_address: PeerAddress, msg_buf: PacketBufferHandle) -> ChipError {
                        $(if self.m_transports.$index.can_send_to_peer(&peer_address) {
                            return self.m_transports.$index.send_message(peer_address, msg_buf);
                        })+
                        chip_error_no_message_handler!()
                    }

                    fn can_send_to_peer(&self, peer_address: &PeerAddress) -> bool {
                        $(if self.m_transports.$index.can_send_to_peer(&peer_address) {
                            return true;
                        })+
                        false
                    }

                    fn handle_message_received(&mut self, _peer_address: PeerAddress, _buffer: PacketBufferHandle, _ctxt: * const MessageTransportContext) {}
                }
    };
}

impl_base_for_tuple!(DelegateType; 0: Type0);
impl_base_for_tuple!(DelegateType; 0: Type0, 1: Type1);
impl_base_for_tuple!(DelegateType; 0: Type0, 1: Type1, 2: Type2);
impl_base_for_tuple!(DelegateType; 0: Type0, 1: Type1, 2: Type2, 3: Type3);

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  use crate::chip::inet::test_end_point::TestEndPointManager;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();
  mod test_one_tuple_init {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::inet::test_end_point::TestEndPointManager;
      use crate::chip::inet::inet_layer::EndPointManager;
      use crate::chip::inet::end_point_basis::DefaultWithMgr;
      use crate::chip::transport::raw::test::{Test, TestListenParameter};
      use crate::chip::inet::ip_address::{IPAddressType,IPAddress};
      use crate::chip::inet::ip_packet_info::IPPacketInfo;
      use std::cell::Cell;
      use crate::chip_no_error;
      static mut TEST_PARAMS: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();

      static mut TEST_TUPLE: Tuple<TestDelegate, (Test<TestDelegate>,)> = Tuple {
          m_transports: (Test::default_const(),),
          phantom: PhantomData,
      };

      const EXPECTED_SEND_PORT: u16 = 87;
      const EXPECTED_SEND_ADDR: IPAddress = IPAddress {
          addr: (1, 2, 3, 4)
      };
      const EXPECTED_SEND_MSG: [u8; 4] = [11, 12, 13, 14];

      #[derive(Default)]
      struct TestDelegate {
          pub check: Cell<bool>,
          pub addr: Cell<PeerAddress>,
      }

      impl RawTransportDelegate for TestDelegate {
          fn handle_message_received(&self, peer_address: PeerAddress, _buffer: PacketBufferHandle, _ctxt: * const MessageTransportContext) {
              self.check.set(true);
              self.addr.set(peer_address);
          }
      }

      fn set_up() {
          unsafe {
              /* reinit system layer */
              let sl = system_layer();
              (*sl).init();

              /* reinit end point manager */
              END_POINT_MANAGER = TestEndPointManager::default();
              END_POINT_MANAGER.init(system_layer());

              /* reinit the test transport */
              TEST_PARAMS.write(TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)));
              TEST_TUPLE.m_transports.0 = Test::default();
          }
      }

      #[test]
      fn init_successfully() {
          set_up();
          let mut delegate = TestDelegate::default();
          unsafe {
              assert_eq!(chip_no_error!(), TEST_TUPLE.init(ptr::addr_of_mut!(delegate), TEST_PARAMS.assume_init_mut().clone()));
          }
      }
  }
}
