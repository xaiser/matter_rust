use super::inet_layer::EndPointManagerImplPool;
use super::inet_layer::EndPointManager;
use super::inet_layer::EndPointProperties;
use super::ip_packet_info::IPPacketInfo;
use super::ip_address::IPAddress;
use super::ip_address::IPAddressType;
use super::end_point_basis::EndPointBasis;
use super::end_point_basis::DefaultWithMgr;
//use super::end_point_basis::EndPointDeletor;
use super::inet_interface::InterfaceId;
use super::inet_config::*;
use crate::chip::chip_lib::core::reference_counted::{RCDeleteDeletor, ReferenceCountered};
use crate::chip::system::LayerImpl as SystemLayer;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_incorrect_state;
use crate::chip_error_inbound_message_too_big;
use crate::inet_error_wrong_address_type;
use crate::chip_inet_error;
use crate::ChipError;
use core::ptr;

pub type TestEndPointManager = EndPointManagerImplPool<TestEndPoint, {TestEndPoint::NUM_END_POINTS}>;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    KReady,
    KBound,
    KListening,
    KClosed,
}

pub type OnMessageReceivedFunct = fn(*mut TestEndPoint, PacketBufferHandle, &IPPacketInfo) -> ();
pub type OnMessageErrorFunct = fn(*mut TestEndPoint, ChipError, &IPPacketInfo) -> ();

type RCCountType = i32;

#[derive(Clone, Copy)]
pub struct TestEndPoint {
    pub m_app_state: * mut u8,
    m_end_point_manager: * mut TestEndPointManager,
    m_state: State,
    m_on_message_received: Option<OnMessageReceivedFunct>,
    m_on_receive_error: Option<OnMessageErrorFunct>,
    m_bound_port: u16,
    m_bound_interface: Option<InterfaceId>,
    m_count: RCCountType,
}

impl DefaultWithMgr for TestEndPoint {
    type EndPointManagerType = TestEndPointManager;
    fn default(mgr: * mut TestEndPointManager) -> Self
    {
        TestEndPoint {
            m_end_point_manager: mgr,
            m_state: State::KReady,
            m_on_message_received: None,
            m_on_receive_error: None,
            m_app_state : ptr::null_mut(),
            m_bound_port: 0,
            m_bound_interface: None,
            m_count: 1,
        }
    }
}

impl TestEndPoint {
    pub fn bind_with_interface(&mut self, addr_type: IPAddressType, addr: &IPAddress, port: u16, intf_id: Option<InterfaceId>) -> ChipError
    {
        if self.m_state != State::KReady && self.m_state != State::KBound {
            return chip_error_incorrect_state!();
        }

        if *addr != IPAddress::ANY && addr.ip_type() != IPAddressType::KAny && addr.ip_type() != addr_type {
            return inet_error_wrong_address_type!();
        }

        // do something

        self.m_state = State::KBound;
        self.m_bound_port = port;
        self.m_bound_interface = intf_id;

        chip_no_error!()
    }

    pub fn bind(&mut self, addr_type: IPAddressType, addr: &IPAddress, port: u16) -> ChipError
    {
        self.bind_with_interface(addr_type, addr, port, None)
    }

    pub fn get_bound_port(&self) -> u16
    {
        return self.m_bound_port;
    }

    pub fn listen(&mut self, on_message_received: Option<OnMessageReceivedFunct>, on_receive_error: Option<OnMessageErrorFunct>, app_state: * mut u8) -> ChipError
    {
        if self.m_state == State::KListening {
            return chip_no_error!();
        }
        if self.m_state != State::KBound {
            return chip_error_incorrect_state!();
        }
        self.m_on_message_received = on_message_received;
        self.m_on_receive_error = on_receive_error;
        self.m_app_state = app_state;

        self.m_state = State::KListening;

        chip_no_error!()
    }

    pub fn send_to_with_interface(&self, addr: &IPAddress, port: u16, msg: &PacketBufferHandle, intf_id: Option<InterfaceId>) -> ChipError
    {
        let mut pkt_info = IPPacketInfo::default();
        pkt_info.dest_address = addr.clone();
        pkt_info.dest_port = port;
        pkt_info.interface = intf_id;
        return self.send_msg(&pkt_info, msg);
    }

    pub fn send_to(&self, addr: &IPAddress, port: u16, msg: &PacketBufferHandle) -> ChipError
    {
        self.send_to_with_interface(addr, port, msg, None)
    }

    pub fn send_msg(&self, _pkt_info: &IPPacketInfo, _msg: &PacketBufferHandle) -> ChipError
    {
        // do something
        chip_no_error!()
    }

    pub fn close(&mut self)
    {
        if self.m_state != State::KClosed {
            self.m_state = State::KClosed;
            // do some close
        }
    }

    pub fn free(&mut self)
    {
        self.close();
        self.release();
    }

    pub fn test_get_msg(&mut self, pkt_info: &IPPacketInfo, msg: PacketBufferHandle) -> ()
    {
        match self.m_on_message_received.as_ref() {
            Some(cb) => {
                (*cb)(self as * mut TestEndPoint, msg, pkt_info);
            },
            None => {
                match self.m_on_receive_error.as_ref() {
                    Some(cb) => {
                        (*cb)(self as * mut TestEndPoint, chip_error_inbound_message_too_big!(), pkt_info);
                    },
                    None => {}
                }
            }
        }
    }

    pub fn test_send_to<F>(&self, addr: &IPAddress, port: u16, msg: &PacketBufferHandle, mock: F) -> ChipError
        where
            F: Fn(&IPAddress,u16,&PacketBufferHandle) -> ChipError + FnMut(&IPAddress,u16,&PacketBufferHandle) -> ChipError
    {
        mock(addr, port, msg)
    }

}

impl EndPointBasis for TestEndPoint { 
    type EndPointManagerType = TestEndPointManager;

    fn get_end_point_manager(&self) -> * mut Self::EndPointManagerType
    {
        self.m_end_point_manager
    }

    fn get_system_layer(&self) -> * mut SystemLayer
    {
        unsafe {
            return (*self.m_end_point_manager).system_layer();
        }
    }
}

impl RCDeleteDeletor<TestEndPoint> for TestEndPoint {
    fn release(obj: * mut TestEndPoint) {
        unsafe {
            (*(*obj).get_end_point_manager()).delete_end_point(obj);
        }
    }
}

impl ReferenceCountered<TestEndPoint, TestEndPoint> for TestEndPoint {
    type CounterType = RCCountType;
    fn increase(&mut self) -> Self::CounterType {
        self.m_count += 1;
        return self.m_count;
    }

    fn decrease(&mut self) -> Self::CounterType {
        self.m_count -= 1;
        return self.m_count;
    }

    fn get_reference_count(&self) -> Self::CounterType {
        return self.m_count;
    }
}

impl EndPointProperties for TestEndPoint {
    const NAME: &'static str = "TEST";
    const NUM_END_POINTS: usize = INET_CONFIG_NUM_TEST_ENDPOINTS;
    const SYSTEM_STATE_KEY: i32 = 0;
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();
  mod inet_manager {
      use super::super::*;
      use super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::chip_lib::support::iterators::Loop;

      fn set_up() {
          unsafe {
              /* reinit system layer */
              let sl = system_layer();
              (*sl).init();

              /* reinit end point manager */
              END_POINT_MANAGER = TestEndPointManager::default();
              END_POINT_MANAGER.init(system_layer());
          }
      }

      #[test]
      fn new_a_test_end_point() {
          set_up();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point();
              assert_eq!(true, ep.is_ok());
          }
      }

      #[test]
      fn new_two_test_end_point() {
          set_up();
          unsafe {
              let ep1 = END_POINT_MANAGER.new_end_point();
              let ep2 = END_POINT_MANAGER.new_end_point();
              assert_eq!(true, ep1.is_ok());
              assert_eq!(true, ep2.is_ok());
          }
      }

      #[test]
      fn new_but_full() {
          set_up();
          unsafe {
              for _i in 0..TestEndPoint::NUM_END_POINTS {
                  let _ep1 = END_POINT_MANAGER.new_end_point();
              }
              let ep_full = END_POINT_MANAGER.new_end_point();
              assert_eq!(false, ep_full.is_ok());
          }
      }

      #[test]
      fn release_one() {
          set_up();
          unsafe {
              let mut ep1: * mut TestEndPoint = ptr::null_mut();
              for _i in 0..TestEndPoint::NUM_END_POINTS {
                  match END_POINT_MANAGER.new_end_point() {
                      Ok(p) => { ep1 = p },
                      Err(_) => {}
                  }
              }
              END_POINT_MANAGER.release_end_point(ep1);
              let last_ep = END_POINT_MANAGER.new_end_point();
              assert_eq!(true, last_ep.is_ok());
          }
      }

      #[test]
      fn release_two() {
          set_up();
          unsafe {
              let mut ep1: * mut TestEndPoint = ptr::null_mut();
              let mut ep2: * mut TestEndPoint = ptr::null_mut();
              for _i in 0..TestEndPoint::NUM_END_POINTS {
                  match END_POINT_MANAGER.new_end_point() {
                      Ok(p) => { 
                          if ep1.is_null() == true {
                              ep1 = p;
                          }
                          else if ep2.is_null() == true {
                              ep2 = p;
                          }
                      },
                      Err(_) => {}
                  }
              }
              END_POINT_MANAGER.release_end_point(ep1);
              END_POINT_MANAGER.release_end_point(ep2);
              let last_ep_1 = END_POINT_MANAGER.new_end_point();
              let last_ep_2 = END_POINT_MANAGER.new_end_point();
              assert_eq!(true, last_ep_1.is_ok());
              assert_eq!(true, last_ep_2.is_ok());
          }
      }

      #[test]
      fn for_each_one() {
          set_up();
          unsafe {
              let mut count: u32 = 0;
              let _ep = END_POINT_MANAGER.new_end_point();
              assert_eq!(Loop::Finish, END_POINT_MANAGER.for_each_end_point(|_p| {
                  count += 1;
                  return Loop::Continue;
              }));
              assert_eq!(1, count);
          }
      }

      #[test]
      fn for_each_two() {
          set_up();
          unsafe {
              let mut count: u32 = 0;
              let _ = END_POINT_MANAGER.new_end_point();
              let _ = END_POINT_MANAGER.new_end_point();
              assert_eq!(Loop::Finish, END_POINT_MANAGER.for_each_end_point(|_p| {
                  count += 1;
                  return Loop::Continue;
              }));
              assert_eq!(2, count);
          }
      }
  }

  mod inet_end_point {
      use super::super::*;
      use super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::system::system_packet_buffer::PacketBuffer;

      fn on_receive(ep: * mut TestEndPoint, msg: PacketBufferHandle, pkt_info: &IPPacketInfo) {
          unsafe {
              let vp: * mut Vec<u32> = (*ep).m_app_state as * mut Vec<u32>;
              let pb = msg.get_raw();
              let buffer = (*pb).start();
              (*vp).push(pkt_info.src_port as u32);
              (*vp).push(pkt_info.dest_port as u32);
              for i in 0..(*pb).data_len() as usize {
                  (*vp).push(*buffer.add(i) as u32);
              }
          }
      }

      fn on_error(ep: * mut TestEndPoint, error: ChipError, pkt_info: &IPPacketInfo) {
          unsafe {
              let vp: * mut Vec<u32> = (*ep).m_app_state as * mut Vec<u32>;
              (*vp).push(pkt_info.src_port as u32);
              (*vp).push(pkt_info.dest_port as u32);
              (*vp).push(error.as_integer() as u32);
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
          }
      }

      #[test]
      fn new_a_test_end_point() {
          set_up();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point().unwrap();
              assert_eq!(State::KReady, (*ep).m_state);
          }
      }

      #[test]
      fn bind() {
          set_up();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point().unwrap();
              assert_eq!(chip_no_error!(), (*ep).bind(IPAddressType::KAny, &IPAddress::ANY.clone(), 888));
          }
      }

      #[test]
      fn bind_fail() {
          set_up();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point().unwrap();
              assert_eq!(inet_error_wrong_address_type!(), (*ep).bind(IPAddressType::KIPv6, &IPAddress::ANY_IPV4.clone(), 888));
          }
      }

      #[test]
      fn test_on_receive() {
          set_up();
          let v: Vec<u32> = Vec::new();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point().unwrap();
              (*ep).bind(IPAddressType::KAny, &IPAddress::ANY.clone(), 888);
              (*ep).listen(Some(on_receive), None, ptr::addr_of!(v) as * mut u8);

              let mut src_pkt_info = IPPacketInfo::default();
              src_pkt_info.dest_port = 888;
              src_pkt_info.src_port = 666;

              let msg = PacketBufferHandle::new_with_data(&[1,2,3], 0, 0).unwrap();

              (*ep).test_get_msg(&src_pkt_info, msg);

              assert_eq!(5, v.len());
              assert_eq!(666, v[0]);
              assert_eq!(888, v[1]);
              assert_eq!(1, v[2]);
              assert_eq!(2, v[3]);
              assert_eq!(3, v[4]);
          }
      }

      #[test]
      fn test_on_msg_error() {
          set_up();
          let v: Vec<u32> = Vec::new();
          unsafe {
              let ep = END_POINT_MANAGER.new_end_point().unwrap();
              (*ep).bind(IPAddressType::KAny, &IPAddress::ANY.clone(), 888);
              (*ep).listen(None, Some(on_error), ptr::addr_of!(v) as * mut u8);

              let mut src_pkt_info = IPPacketInfo::default();
              src_pkt_info.dest_port = 888;
              src_pkt_info.src_port = 666;

              let msg = PacketBufferHandle::new_with_data(&[1,2,3], 0, 0).unwrap();

              (*ep).test_get_msg(&src_pkt_info, msg);

              assert_eq!(3, v.len());
              assert_eq!(666, v[0]);
              assert_eq!(888, v[1]);
              assert_eq!(chip_error_inbound_message_too_big!().as_integer(), v[2]);
          }
      }
  }

}
