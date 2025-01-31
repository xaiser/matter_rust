use super::inet_layer::EndPointManagerImplPool;
use super::inet_layer::EndPointManager;
use super::inet_layer::EndPointProperties;
use super::ip_packet_info::IPPacketInfo;
use super::ip_address::IPAddress;
use super::ip_address::IPAddressType;
use super::end_point_basis::EndPointBasis;
use super::end_point_basis::DefaultWithMgr;
use super::end_point_basis::EndPointDeletor;
use super::inet_interface::InterfaceId;
use super::inet_config::*;
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

type TestEndPointManager = EndPointManagerImplPool<TestEndPoint, {TestEndPoint::NUM_END_POINTS}>;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum State {
    KReady,
    KBound,
    KListening,
    KClosed,
}

pub type OnMessageReceivedFunct = fn(*mut TestEndPoint, &PacketBufferHandle, &IPPacketInfo) -> ();
pub type OnMessageErrorFunct = fn(*mut TestEndPoint, ChipError, &IPPacketInfo) -> ();

#[derive(Clone, Copy)]
pub struct TestEndPoint {
    m_end_point_manager: * mut TestEndPointManager,
    m_state: State,
    m_on_message_received: Option<OnMessageReceivedFunct>,
    m_on_receive_error: Option<OnMessageErrorFunct>,
    m_app_state: * mut u8,
    m_bound_port: u16,
    m_bound_interface: Option<InterfaceId>
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
            m_bound_interface: None
        }
    }
}

impl TestEndPoint {
    /*
    pub fn default(mgr: * mut TestEndPointManager) -> Self {
    }
    */

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
        return 0;
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

    pub fn send_msg(&self, pkt_info: &IPPacketInfo, msg: &PacketBufferHandle) -> ChipError
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
    {}

    pub fn test_get_msg(&mut self, pkt_info: &IPPacketInfo, msg: &PacketBufferHandle) -> ()
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

impl EndPointDeletor<TestEndPoint> for TestEndPoint {
    fn release(obj: &mut TestEndPoint) {
        unsafe {
            (*obj.get_end_point_manager()).delete_end_point(obj);
        }
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
  mod new {
      use super::super::*;
      use super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;

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
      fn new_packet_buffer() {
          set_up();
          assert_eq!(1,1);
      }
  }
}
