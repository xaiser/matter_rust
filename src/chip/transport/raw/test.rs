use super::base::{RawTransportDelegate,Base,MessageTransportContext};
use super::peer_address::PeerAddress;

use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::inet::test_end_point::{TestEndPoint, TestEndPointManager};
use crate::chip::inet::ip_address::{IPAddressType,IPAddress};
use crate::chip::inet::inet_interface::InterfaceId;
use crate::chip::inet::inet_layer::EndPointManager;
use crate::chip::inet::end_point_basis::DefaultWithMgr;
use crate::ChipError;
use crate::chip_no_error;

use core::str::FromStr;
use crate::chip_log_detail;
use crate::chip_log_progress;
use crate::chip_log_error;
use crate::chip_internal_log;
use crate::chip_internal_log_impl;

use crate::success_or_exit;

use core::ptr;

#[derive(PartialEq)]
enum State
{
    KNotReady,
    KInitialized,
}

#[derive(Copy)]
pub struct TestListenParameter<ManagerType>
where
    ManagerType: EndPointManager<EndPointType=TestEndPoint>,
{
    m_end_point_manager: * mut ManagerType,
    m_address_type: IPAddressType,
    m_listen_port: u16,
    m_interface_id: InterfaceId,
}

impl<ManagerType> Clone for TestListenParameter<ManagerType> 
where
    ManagerType: EndPointManager<EndPointType=TestEndPoint>,
{
    fn clone(&self) -> Self {
        TestListenParameter {
            m_end_point_manager: self.m_end_point_manager,
            m_address_type: self.m_address_type.clone(),
            m_listen_port: self.m_listen_port,
            m_interface_id: self.m_interface_id.clone(),
        }
    }
}

impl<ManagerType> DefaultWithMgr for TestListenParameter<ManagerType>
where
    ManagerType: EndPointManager<EndPointType=TestEndPoint>,
{
    type EndPointManagerType = ManagerType;
    fn default(mgr: * mut Self::EndPointManagerType) -> Self {
        TestListenParameter {
            m_end_point_manager: mgr,
            m_address_type: IPAddressType::KIPv6,
            m_listen_port: 888,
            m_interface_id: InterfaceId::default(),
        }
    }
}

impl<ManagerType> TestListenParameter<ManagerType>
where
    ManagerType: EndPointManager<EndPointType=TestEndPoint>,
{
    pub fn get_end_point_manager(&self) -> * mut ManagerType {
        self.m_end_point_manager
    }

    pub fn get_address_type(&self) -> IPAddressType {
        self.m_address_type.clone()
    }

    pub fn set_address_type(self, addr_type: IPAddressType) -> Self {
        TestListenParameter {
            m_end_point_manager: self.m_end_point_manager,
            m_address_type: addr_type,
            m_listen_port: self.m_listen_port,
            m_interface_id: self.m_interface_id,
        }
    }

    pub fn get_listen_port(&self) -> u16 {
        self.m_listen_port
    }

    pub fn set_listen_port(self, port: u16) -> Self {
        TestListenParameter {
            m_end_point_manager: self.m_end_point_manager,
            m_address_type: self.m_address_type,
            m_listen_port: port,
            m_interface_id: self.m_interface_id,
        }
    }

    pub fn get_interface_id(&self) -> InterfaceId {
        self.m_interface_id.clone()
    }

    pub fn set_interface_id(self, id: InterfaceId) -> Self {
        TestListenParameter {
            m_end_point_manager: self.m_end_point_manager,
            m_address_type: self.m_address_type,
            m_listen_port: self.m_listen_port,
            m_interface_id: id,
        }
    }
}

pub struct Test<DelegateType: RawTransportDelegate>
{
    m_delegate: * mut DelegateType,
    m_test_end_point: * mut TestEndPoint,
    m_test_end_point_type: IPAddressType,
    m_state: State,
}

impl<DelegateType> Default for Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    fn default() -> Self {
        Test{
            m_delegate: ptr::null_mut(),
            m_test_end_point: ptr::null_mut(),
            m_test_end_point_type: IPAddressType::KIPv6,
            m_state: State::KNotReady,
        }
    }
}

impl<DelegateType> Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    pub fn init(&mut self, params: TestListenParameter<TestEndPointManager>) -> ChipError {
        // exit closure
        let exit = |err: ChipError, end_point: &mut * mut TestEndPoint| -> ChipError {
            if err.is_success() == false {
                chip_log_progress!(Inet, "fail to init test transport {}", err.format());
                if end_point.is_null() == false {
                    unsafe {
                        (*(*end_point)).free();
                    }
                    *end_point = ptr::null_mut();
                }
            }
            return err;
        };

        if self.m_state != State::KNotReady {
            self.close();
        }

        unsafe {
            // create a new end point
            match (*(params.get_end_point_manager())).new_end_point() {
                Ok(point) => {
                    self.m_test_end_point = point;
                },
                Err(err) => {
                    return err;
                }
            }
            chip_log_detail!(Inet, "Test:: bind&listen port={}", params.get_listen_port());
            // bind to address and port
            let err = (*self.m_test_end_point).bind(params.get_address_type(), &IPAddress::ANY.clone(), params.get_listen_port());
            success_or_exit!(err, return exit(err, &mut self.m_test_end_point));

            // setup listen callback
            let err = (*self.m_test_end_point).listen(
                // OK callback
                Some(|ep, buffer, pkt_info| {
                let test: * mut Self = (*ep).m_app_state as _;
                let peer_address = PeerAddress::udp_addr_port_interface(pkt_info.src_address.clone(), pkt_info.src_port, pkt_info.interface.unwrap_or(InterfaceId::default()));

                (*test).handle_message_received(peer_address, buffer, ptr::null());
            }),
            // Fail callback
            Some(|ep, err, pkt_info| {
                chip_log_error!(Inet, "Failed to recieve Test message {}", err.format());
            }), self as * mut Self as _);
            success_or_exit!(err, return exit(err, &mut self.m_test_end_point));

            chip_log_detail!(Inet, "Test::Inet bound to port={}", (*self.m_test_end_point).get_bound_port());
        }

        self.m_test_end_point_type = params.get_address_type();

        self.m_state = State::KInitialized;

        return chip_no_error!();
    }
}

/*
fn OnTestReceive(ep: * mut TestEndPoint, msg: PacketBufferHandle, pkt_info: &IPPacketInfo) {
    let err = chip_no_error!();
    let test: * mut Test = (*ep).m_app_state.cast::<* mut Test>();
}
*/

impl<DelegateType> Base<DelegateType> for Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    fn set_deletgate(&mut self, delegate: * mut DelegateType)
    {
        self.m_delegate = delegate;
    }

    fn send_message(&mut self, _peer_address: &PeerAddress, _msg_buf: PacketBufferHandle) -> ChipError {
        return chip_no_error!();
    }

    fn can_send_to_peer(&mut self, _peer_address: &PeerAddress) -> bool {
        return true;
    }

    fn close(&mut self) { 
        if self.m_test_end_point.is_null() == false {
            unsafe {
                (*self.m_test_end_point).close();
                (*self.m_test_end_point).free();
            }
            self.m_test_end_point = ptr::null_mut();
        }
        self.m_state = State::KNotReady;
    }

    fn handle_message_received(&mut self, peer_address: PeerAddress, buffer: PacketBufferHandle, ctxt: * const MessageTransportContext) {
        unsafe {
            (*self.m_delegate).handle_message_received(peer_address, buffer, ctxt)
        }
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  use crate::chip::inet::test_end_point::TestEndPointManager;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();

  mod test_listen_parameter {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::inet::test_end_point::TestEndPointManager;
      use core::ptr;

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
      fn new_with_end_point_manager() {
          set_up();
          let p = TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER));
          assert_eq!(p.get_end_point_manager(), ptr::addr_of_mut!(END_POINT_MANAGER));
      }

      #[test]
      fn new_with_other_setting() {
          set_up();
          let p = TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)).set_listen_port(11);
          assert_eq!(p.get_end_point_manager(), ptr::addr_of_mut!(END_POINT_MANAGER));
          assert_eq!(p.get_listen_port(), 11);
      }
  }

  mod test_transport {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::inet::test_end_point::TestEndPointManager;
      use std::cell::Cell;
      static mut TEST_PARAMS: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();

      #[derive(Default)]
      struct TestDelegate {
          pub check: Cell<bool>,
          pub addr: Cell<PeerAddress>,
      }

      impl RawTransportDelegate for TestDelegate {
          fn handle_message_received(&self, peer_address: PeerAddress, buffer: PacketBufferHandle, ctxt: * const MessageTransportContext) {
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

              TEST_PARAMS.write(TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)));
          }
      }

      #[test]
      fn init() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_no_error!());
          }
      }

      #[test]
      fn init_2() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_no_error!());
          }
      }
  }
}
