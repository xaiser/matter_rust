use super::inet_layer::EndPointManagerImplPool;
use super::inet_layer::EndPointManager;
use super::inet_layer::EndPointProperties;
use super::ip_packet_info::IPPacketInfo;
use super::ip_address::IPAddress;
use super::ip_address::IPAddressType;
use super::end_point_basis::EndPointBasis;
use super::end_point_basis::EndPointDeletor;
use super::inet_interface::InterfaceId;
use super::inet_config::*;
use crate::chip::system::LayerImpl as SystemLayer;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
//use crate::chip::chip_lib::support::object_life_cycle::ObjectLifeCycle;
use crate::chip_no_error;
use crate::ChipError;
use core::ptr;

type TestEndPointManager = EndPointManagerImplPool<TestEndPoint, {TestEndPoint::NUM_END_POINTS}>;

#[repr(u8)]
#[derive(Clone, Copy)]
enum State {
    KReady,
    KBound,
    KListening,
    KClosed,
}

pub type OnMessageReceivedFunct = fn(*mut TestEndPoint, &PacketBufferHandle, *mut IPPacketInfo) -> ();
pub type OnMessageErrorFunct = fn(*mut TestEndPoint, &ChipError, *mut IPPacketInfo) -> ();

#[derive(Clone, Copy)]
pub struct TestEndPoint {
    m_end_point_manager: * mut TestEndPointManager,
    m_state: State,
    m_on_message_received: Option<OnMessageReceivedFunct>,
    m_on_receive_error: Option<OnMessageErrorFunct>
}

impl TestEndPoint {

    pub const fn default() -> Self {
        TestEndPoint {
            m_end_point_manager: ptr::null_mut(),
            m_state: State::KReady,
            m_on_message_received: None,
            m_on_receive_error: None
        }
    }

    pub fn bind_with_interface(&mut self, addr_type: IPAddressType, addr: &IPAddress, port: u16, intf_id: Option<InterfaceId>) -> ChipError
    {
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

    pub fn listen(&mut self, on_message_received: OnMessageReceivedFunct, on_receive_error: OnMessageErrorFunct, app_state: * mut u8) -> ChipError
    {
        chip_no_error!()
    }

    pub fn send_to_with_interface(&self, addr: &IPAddress, port: u16, msg: &PacketBufferHandle, intf_id: Option<InterfaceId>) -> ChipError
    {
        chip_no_error!()
    }

    pub fn send_to(&self, addr: &IPAddress, port: u16, msg: &PacketBufferHandle) -> ChipError
    {
        self.send_to_with_interface(addr, port, msg, None)
    }

    pub fn send_message(&self, pkt_info: * mut IPPacketInfo) -> ChipError
    {
        chip_no_error!()
    }

    pub fn close(&mut self)
    {}

    pub fn free(&mut self)
    {}

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
  static mut test: bool = false;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default(TestEndPoint::default());
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
              END_POINT_MANAGER = TestEndPointManager::default(TestEndPoint::default());
              END_POINT_MANAGER.init(system_layer());
          }
      }

      #[test]
      fn new_packet_buffer() {
          set_up();
          assert_eq!(1,1);
      }

      #[test]
      fn new_packet_buffer_1() {
          set_up();
          assert_eq!(1,1);
      }
  }
}
