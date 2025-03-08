use super::base::{RawTransportDelegate,Base,MessageTransportContext,Init};
use super::peer_address::{PeerAddress, Type};

use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use crate::chip::inet::test_end_point::{TestEndPoint, TestEndPointManager};
use crate::chip::inet::ip_address::{IPAddressType,IPAddress};
use crate::chip::inet::inet_interface::InterfaceId;
use crate::chip::inet::inet_layer::EndPointManager;
use crate::chip::inet::end_point_basis::DefaultWithMgr;
use crate::chip::inet::ip_packet_info::IPPacketInfo;
use crate::chip::inet::inet_fault_injection::{InetFaultInjectionID, get_manager};
use crate::chip::chip_lib::support::fault_injection::fault_injection::{Manager, Identifier};
use crate::ChipError;

use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_invalid_argument;
use crate::chip_error_incorrect_state;

use core::str::FromStr;
use crate::chip_log_detail;
use crate::chip_log_progress;
use crate::chip_log_error;
use crate::chip_internal_log;
use crate::chip_internal_log_impl;

use crate::success_or_exit;
use crate::verify_or_die;
use crate::verify_or_return_error;
use crate::verify_or_return_value;

use core::ptr;

#[derive(PartialEq,Debug)]
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
    pub const fn default_const() -> Self {
        Test{
            m_delegate: ptr::null_mut(),
            m_test_end_point: ptr::null_mut(),
            m_test_end_point_type: IPAddressType::KIPv6,
            m_state: State::KNotReady,
        }
    }
}

impl<DelegateType> Init<DelegateType> for Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    type InitParamType = TestListenParameter<TestEndPointManager>;

    fn init(&mut self, params: Self::InitParamType) -> ChipError {
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
            Some(|_ep, err, _pkt_info| {
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


impl<DelegateType> Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    fn get_gound_port(&self) -> u16 {
        verify_or_die!(self.m_test_end_point.is_null() == false);
        unsafe {
            return (*self.m_test_end_point).get_bound_port();
        }
    }
}

impl<DelegateType> Base<DelegateType> for Test<DelegateType>
where
    DelegateType: RawTransportDelegate
{
    fn set_delegate(&mut self, delegate: * mut DelegateType)
    {
        self.m_delegate = delegate;
    }

    fn send_message(&mut self, peer_address: PeerAddress, msg_buf: PacketBufferHandle) -> ChipError {
        verify_or_return_error!(peer_address.get_transport_type() == Type::KUdp, chip_error_invalid_argument!());
        verify_or_return_error!(self.m_state == State::KInitialized, chip_error_incorrect_state!());
        verify_or_return_error!(self.m_test_end_point.is_null() == false, chip_error_incorrect_state!());

        let mut addr_info = IPPacketInfo::default();

        addr_info.dest_address = peer_address.get_address();
        addr_info.dest_port = peer_address.get_port();
        addr_info.interface = Some(peer_address.get_interface());

        unsafe {
            return (*self.m_test_end_point).send_msg(addr_info, msg_buf);
        }
    }

    fn can_send_to_peer(&self, peer_address: &PeerAddress) -> bool {
        return (self.m_state == State::KInitialized) &&
            (peer_address.get_transport_type() == Type::KUdp) &&
            (peer_address.get_address().ip_type() == self.m_test_end_point_type);
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

  mod test_transport_init {
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

              TEST_PARAMS.write(TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER)));

              let _ = get_manager().reset_configurations_all();
          }
      }

      fn tear_down() {
      }

      #[test]
      fn init() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          //let mut delegate = TestDelegate::default();
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_no_error!());
          }
          assert_eq!(the_test.m_state, State::KInitialized);
      }

      #[test]
      fn init_2() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_no_error!());
          }
      }

      #[test]
      fn init_fail_at_bind() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          // fail at checked = 1
          let _ = get_manager().fail_at_fault(InetFaultInjectionID::KFaultBind as Identifier, 0, 1);
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_error_incorrect_state!());
          }
      }

      #[test]
      fn init_fail_at_listen() {
          set_up();
          let mut the_test: Test<TestDelegate> = Test::default();
          // fail at checked = 1
          let _ = get_manager().fail_at_fault(InetFaultInjectionID::KFaultListen as Identifier, 0, 1);
          unsafe {
              assert_eq!(the_test.init(TEST_PARAMS.assume_init_mut().clone()), chip_error_incorrect_state!());
          }
      }
  }

  mod test_transport_send {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::inet::test_end_point::TestEndPointManager;
      use std::cell::Cell;
      static mut TEST_PARAMS: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();
      static mut TEST_TRANS: Test<TestDelegate> = Test {
          m_delegate: ptr::null_mut(),
          m_test_end_point: ptr::null_mut(),
          m_test_end_point_type: IPAddressType::KIPv6,
          m_state: State::KNotReady
      };
      /*
      static mut TEST_TRANS_DELEGATE: TestDelegate = TestDelegate {
          check: Cell::new(false),
          addr: Cell::new(PeerAddress {
            m_transport_type: Type::KUndefined,
            m_remote_id: 0 ,
            m_ip_address: IPAddress::default(),
            m_interface: InterfaceId {},
            m_port: 0,
          }),
      };
      */

      const EXPECTED_SEND_PORT: u16 = 87;
      const EXPECTED_SEND_ADDR: IPAddress = IPAddress {
          addr: (1, 2, 3, 4)
      };
      const EXPECTED_SEND_MSG: [u8; 4] = [11, 12, 13, 14];

      fn on_send_checked(info: IPPacketInfo, mut buffer: PacketBufferHandle) -> ChipError {
          assert_eq!(info.dest_address, EXPECTED_SEND_ADDR);
          assert_eq!(info.dest_port, EXPECTED_SEND_PORT);
          assert_eq!(buffer.is_null(), false);
          if let Some(msg) = buffer.pop_head() {
              let buf = msg.get_raw();
              unsafe {
                  assert_eq!(4, (*buf).data_len());
                  let buffer_ptr = (*buf).start();
                  let expected_data_ptr = EXPECTED_SEND_MSG.as_ptr();
                  for i in 0..4 {
                      assert_eq!(ptr::read(buffer_ptr.add(i)), ptr::read(expected_data_ptr.add(i)));
                  }
              }
          } else {
              assert_eq!(1,2);
          }
          return chip_no_error!();
      }

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
              TEST_TRANS = Test::default();
              TEST_TRANS.init(TEST_PARAMS.assume_init_mut().clone());
          }
      }

      #[test]
      fn send_successfully() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              let pa = PeerAddress::udp_addr_port_interface(EXPECTED_SEND_ADDR.clone(),
              EXPECTED_SEND_PORT,
              InterfaceId::default());

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4],0,8).unwrap();

              assert_eq!(TEST_TRANS.send_message(pa, msg), chip_no_error!());
          }
      }

      #[test]
      fn send_with_uninit() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              /* rset the transport */
              TEST_TRANS = Test::default();

              let pa = PeerAddress::udp_addr_port_interface(EXPECTED_SEND_ADDR.clone(),
              EXPECTED_SEND_PORT,
              InterfaceId::default());

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4],0,8).unwrap();

              assert_eq!(TEST_TRANS.send_message(pa, msg), chip_error_incorrect_state!());
          }
      }

      #[test]
      fn send_with_wrong_transport_type() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              let pa = PeerAddress::udp_addr_port_interface(EXPECTED_SEND_ADDR.clone(),
              EXPECTED_SEND_PORT,
              InterfaceId::default()).set_transport_type(Type::KTcp);

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4],0,8).unwrap();

              assert_eq!(TEST_TRANS.send_message(pa, msg), chip_error_invalid_argument!());
          }
      }

      #[test]
      #[should_panic]
      fn send_with_wrong_address_ip() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              let pa = PeerAddress::udp_addr_port_interface(IPAddress::ANY.clone(),
              EXPECTED_SEND_PORT,
              InterfaceId::default());

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4],0,8).unwrap();

              TEST_TRANS.send_message(pa, msg);
          }
      }

      #[test]
      #[should_panic]
      fn send_with_wrong_address_port() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              let pa = PeerAddress::udp_addr_port_interface(EXPECTED_SEND_ADDR.clone(),
              EXPECTED_SEND_PORT + 1,
              InterfaceId::default());

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4],0,8).unwrap();

              TEST_TRANS.send_message(pa, msg);
          }
      }

      #[test]
      #[should_panic]
      fn send_with_wrong_data() {
          set_up();
          unsafe {
              /* set up send check stub */
              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_send_to(on_send_checked);

              let pa = PeerAddress::udp_addr_port_interface(EXPECTED_SEND_ADDR.clone(),
              EXPECTED_SEND_PORT,
              InterfaceId::default());

              let fake_msg: [u8; 4] = [1; 4];

              let msg = PacketBufferHandle::new_with_data(&fake_msg[0..4],0,8).unwrap();

              TEST_TRANS.send_message(pa, msg);
          }
      }
  } // mod test_transport_send
  mod test_transport_receive {
      use super::*;
      use super::super::*;
      use std::*;
      use crate::chip::platform::global::system_layer;
      use crate::chip::system::system_layer::Layer;
      use crate::chip::inet::test_end_point::TestEndPointManager;
      use std::cell::Cell;
      use std::cell::UnsafeCell;
      static mut TEST_PARAMS: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> = mem::MaybeUninit::uninit();
      static mut TEST_TRANS: Test<TestDelegate> = Test {
          m_delegate: ptr::null_mut(),
          m_test_end_point: ptr::null_mut(),
          m_test_end_point_type: IPAddressType::KIPv6,
          m_state: State::KNotReady
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
          pub data: UnsafeCell<Vec<u32>>,
      }

      impl RawTransportDelegate for TestDelegate {
          fn handle_message_received(&self, peer_address: PeerAddress, buffer: PacketBufferHandle, _ctxt: * const MessageTransportContext) {
              self.check.set(true);
              self.addr.set(peer_address);

              unsafe {
                  let pb = buffer.get_raw();
                  let data_buffer = (*pb).start();

                  for i in 0..(*pb).data_len() as usize {
                      (*self.data.get()).push(*data_buffer.add(i) as u32);
                  }
              }
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
              TEST_TRANS = Test::default();
              TEST_TRANS.init(TEST_PARAMS.assume_init_mut().clone());
          }
      }

      #[test]
      fn receive_successfully() {
          set_up();
          unsafe {
              let mut d = TestDelegate::default();
              TEST_TRANS.set_delegate(ptr::addr_of_mut!(d));

              let mut src_pkt_info = IPPacketInfo::default();
              src_pkt_info.src_port = EXPECTED_SEND_PORT;
              src_pkt_info.src_address = EXPECTED_SEND_ADDR.clone();

              let msg = PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4], 0, 0).unwrap();

              let ep = TEST_TRANS.m_test_end_point;
              (*ep).test_get_msg(&src_pkt_info, msg);

              assert_eq!(d.check.get(), true);
              assert_eq!(d.addr.get().get_address(), EXPECTED_SEND_ADDR.clone());
              assert_eq!(d.addr.get().get_port(), EXPECTED_SEND_PORT);
              unsafe {
                  for i in 0..4 {
                      assert_eq!((*d.data.get())[i], EXPECTED_SEND_MSG[i].into());
                  }
              }
          }
      }
  } // test_transport_receive
}
