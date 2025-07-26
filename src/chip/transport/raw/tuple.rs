use super::base::{Base, Init, MessageTransportContext, RawTransportDelegate};
use super::peer_address::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;

use crate::chip_core_error;
use crate::chip_error_no_message_handler;
use crate::chip_sdk_error;
use crate::ChipError;

pub struct Tuple<T> {
    m_transports: T,
}

macro_rules! impl_init_for_tuple {
    ($($index:tt; $type:ident),+) => {
        impl<$($type,)+> Tuple<($($type,)+)>
            where
                $($type: Init + Base,)+
        {
            #[allow(dead_code)]
            pub fn init(&mut self, delegates: ($(* mut <$type as Base>::DelegateType,)+), ps: ($(<$type as Init>::InitParamType,)+)) -> ChipError {
                #[allow(unused_mut)]
                let mut err: ChipError;
                $(err = self.m_transports.$index.init(ps.$index);
                  if err.is_success() == false { return err; }
                  self.m_transports.$index.set_delegate(delegates.$index);)+
                return err;
            }
        }
    };
}

macro_rules! impl_default_for_tuple {
    ($($type:ident),+) => {
        impl<$($type,)+> Default for Tuple<($($type,)+)>
            where
                //$($type: Default + Init + Base,)+
                $($type: Default,)+
        {
            #[allow(dead_code)]
            fn default() -> Self {
                Self {
                    m_transports: ($($type::default(),)+),
                }
            }
        }
    };
}

impl_init_for_tuple!(0; Type0);
impl_init_for_tuple!(0; Type0,1; Type1);
impl_init_for_tuple!(0; Type0,1; Type1,2; Type2);
impl_init_for_tuple!(0; Type0,1; Type1,2; Type2,3; Type3);
impl_init_for_tuple!(0; Type0,1; Type1,2; Type2,3; Type3,4; Type4);

impl_default_for_tuple!(Type0);
impl_default_for_tuple!(Type0, Type1);
impl_default_for_tuple!(Type0, Type1, Type2);
impl_default_for_tuple!(Type0, Type1, Type2, Type3);
impl_default_for_tuple!(Type0, Type1, Type2, Type3, Type4);

pub struct DummyDelegate;

impl RawTransportDelegate for DummyDelegate {
    fn handle_message_received(
        &self,
        _peer_address: PeerAddress,
        _msg: PacketBufferHandle,
        _ctxt: *const MessageTransportContext,
    ) {
    }
}

macro_rules! impl_base_for_tuple {
    ($($index:tt; $type:ident),+) => {
        impl<$($type,)+> Base for Tuple<($($type,)+)>
            where
                $($type: Init + Base,)+
                {
                    type DelegateType = DummyDelegate;

                    #[allow(dead_code)]
                    fn close(&mut self) {
                        $(self.m_transports.$index.close();)+
                    }

                    #[allow(dead_code)]
                    fn send_message(&mut self, peer_address: PeerAddress, msg_buf: PacketBufferHandle) -> ChipError {
                        $(if self.m_transports.$index.can_send_to_peer(&peer_address) {
                            return self.m_transports.$index.send_message(peer_address, msg_buf);
                        })+
                        chip_error_no_message_handler!()
                    }

                    #[allow(dead_code)]
                    fn can_send_to_peer(&self, peer_address: &PeerAddress) -> bool {
                        $(if self.m_transports.$index.can_send_to_peer(&peer_address) {
                            return true;
                        })+
                        false
                    }

                    #[allow(dead_code)]
                    fn handle_message_received(&mut self, _peer_address: PeerAddress, _buffer: PacketBufferHandle, _ctxt: * const MessageTransportContext) {}
                }
    };
}

impl_base_for_tuple!(0; Type0);
impl_base_for_tuple!(0; Type0,1; Type1);
impl_base_for_tuple!(0; Type0,1; Type1,2; Type2);
impl_base_for_tuple!(0; Type0,1; Type1,2; Type2,3; Type3);
impl_base_for_tuple!(0; Type0,1; Type1,2; Type2,3; Type3,4; Type4);

#[cfg(test)]
mod test {
    use super::*;
    use crate::chip::inet::test_end_point::TestEndPointManager;
    use std::*;
    static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();
    mod test_one_tuple_init {
        use super::super::*;
        use super::*;
        use crate::chip::inet::end_point_basis::DefaultWithMgr;
        use crate::chip::inet::inet_layer::EndPointManager;
        use crate::chip::inet::ip_address::{IPAddress, IPAddressType};
        use crate::chip::inet::ip_packet_info::IPPacketInfo;
        use crate::chip::inet::test_end_point::TestEndPointManager;
        use crate::chip::platform::global::system_layer;
        use crate::chip::system::system_layer::Layer;
        use crate::chip::transport::raw::test::{Test, TestListenParameter};
        use crate::chip_error_incorrect_state;
        use crate::chip_no_error;
        use std::cell::Cell;
        use std::*;

        use crate::chip::chip_lib::support::fault_injection::fault_injection::{
            Identifier, Manager,
        };
        use crate::chip::inet::inet_fault_injection::{get_manager, InetFaultInjectionID};
        static mut TEST_PARAMS: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> =
            mem::MaybeUninit::uninit();

        static mut TEST_TUPLE: Tuple<(Test<TestDelegate>,)> = Tuple {
            m_transports: (Test::default_const(),),
        };

        #[derive(Default)]
        struct TestDelegate {
            pub check: Cell<bool>,
            pub addr: Cell<PeerAddress>,
        }

        impl RawTransportDelegate for TestDelegate {
            fn handle_message_received(
                &self,
                peer_address: PeerAddress,
                _buffer: PacketBufferHandle,
                _ctxt: *const MessageTransportContext,
            ) {
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
                TEST_PARAMS.write(TestListenParameter::default(ptr::addr_of_mut!(
                    END_POINT_MANAGER
                )));
                TEST_TUPLE.m_transports.0 = Test::default();

                let _ = get_manager().reset_configurations_all();
            }
        }

        #[test]
        fn init_successfully() {
            set_up();
            let mut delegate = TestDelegate::default();
            unsafe {
                assert_eq!(
                    chip_no_error!(),
                    TEST_TUPLE.init(
                        (ptr::addr_of_mut!(delegate),),
                        (TEST_PARAMS.assume_init_mut().clone(),)
                    )
                );
            }
        }

        #[test]
        fn init_fail() {
            set_up();
            let mut delegate = TestDelegate::default();
            // fail at checked = 1
            let _ =
                get_manager().fail_at_fault(InetFaultInjectionID::KFaultBind as Identifier, 0, 1);
            unsafe {
                assert_eq!(
                    chip_error_incorrect_state!(),
                    TEST_TUPLE.init(
                        (ptr::addr_of_mut!(delegate),),
                        (TEST_PARAMS.assume_init_mut().clone(),)
                    )
                );
            }
        }
    }

    mod test_more_tuple_init {
        use super::super::*;
        use super::*;
        use crate::chip::inet::end_point_basis::DefaultWithMgr;
        use crate::chip::inet::inet_layer::EndPointManager;
        use crate::chip::inet::ip_address::{IPAddress, IPAddressType};
        use crate::chip::inet::ip_packet_info::IPPacketInfo;
        use crate::chip::inet::test_end_point::TestEndPointManager;
        use crate::chip::platform::global::system_layer;
        use crate::chip::system::system_layer::Layer;
        use crate::chip::transport::raw::test::{Test, TestListenParameter};
        use crate::chip_error_incorrect_state;
        use crate::chip_no_error;
        use std::cell::Cell;
        use std::*;

        use crate::chip::chip_lib::support::fault_injection::fault_injection::{
            Identifier, Manager,
        };
        use crate::chip::inet::inet_fault_injection::{get_manager, InetFaultInjectionID};
        static mut TEST_PARAMS_1: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> =
            mem::MaybeUninit::uninit();
        static mut TEST_PARAMS_2: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> =
            mem::MaybeUninit::uninit();

        static mut TEST_TUPLE: Tuple<(Test<TestDelegate>, Test<TestDelegate>)> = Tuple {
            m_transports: (Test::default_const(), Test::default_const()),
        };

        #[derive(Default)]
        struct TestDelegate {
            pub check: Cell<bool>,
            pub addr: Cell<PeerAddress>,
        }

        impl RawTransportDelegate for TestDelegate {
            fn handle_message_received(
                &self,
                peer_address: PeerAddress,
                _buffer: PacketBufferHandle,
                _ctxt: *const MessageTransportContext,
            ) {
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
                TEST_PARAMS_1.write(TestListenParameter::default(ptr::addr_of_mut!(
                    END_POINT_MANAGER
                )));
                TEST_PARAMS_2.write(TestListenParameter::default(ptr::addr_of_mut!(
                    END_POINT_MANAGER
                )));
                /*
                TEST_TUPLE.m_transports.0 = Test::default();
                TEST_TUPLE.m_transports.1 = Test::default();
                */

                let _ = get_manager().reset_configurations_all();
            }
        }

        #[test]
        fn init_successfully() {
            set_up();
            let mut delegate = TestDelegate::default();
            unsafe {
                assert_eq!(
                    chip_no_error!(),
                    TEST_TUPLE.init(
                        (ptr::addr_of_mut!(delegate), ptr::addr_of_mut!(delegate)),
                        (
                            TEST_PARAMS_1.assume_init_mut().clone(),
                            TEST_PARAMS_2.assume_init_mut().clone()
                        )
                    )
                );
            }
        }

        #[test]
        fn init_fail() {
            set_up();
            let mut delegate = TestDelegate::default();
            // fail at checked = 1
            let _ =
                get_manager().fail_at_fault(InetFaultInjectionID::KFaultBind as Identifier, 0, 1);
            unsafe {
                assert_eq!(
                    chip_error_incorrect_state!(),
                    TEST_TUPLE.init(
                        (ptr::addr_of_mut!(delegate), ptr::addr_of_mut!(delegate)),
                        (
                            TEST_PARAMS_1.assume_init_mut().clone(),
                            TEST_PARAMS_2.assume_init_mut().clone()
                        )
                    )
                );
            }
        }

        #[test]
        fn init_fail_on_second_transport() {
            set_up();
            let mut delegate = TestDelegate::default();
            // fail at checked = 2
            let _ =
                get_manager().fail_at_fault(InetFaultInjectionID::KFaultBind as Identifier, 0, 2);
            unsafe {
                assert_eq!(
                    chip_error_incorrect_state!(),
                    TEST_TUPLE.init(
                        (ptr::addr_of_mut!(delegate), ptr::addr_of_mut!(delegate)),
                        (
                            TEST_PARAMS_1.assume_init_mut().clone(),
                            TEST_PARAMS_2.assume_init_mut().clone()
                        )
                    )
                );
            }
        }
    }

    mod test_base_functions {
        use super::super::*;
        use super::*;
        use crate::chip::inet::end_point_basis::DefaultWithMgr;
        use crate::chip::inet::inet_interface::InterfaceId;
        use crate::chip::inet::inet_layer::EndPointManager;
        use crate::chip::inet::ip_address::{IPAddress, IPAddressType};
        use crate::chip::inet::ip_packet_info::IPPacketInfo;
        use crate::chip::inet::test_end_point::TestEndPointManager;
        use crate::chip::platform::global::system_layer;
        use crate::chip::system::system_layer::Layer;
        use crate::chip::transport::raw::test::{Test, TestListenParameter};
        use crate::chip_error_incorrect_state;
        use crate::chip_no_error;
        use std::cell::Cell;
        use std::*;

        use crate::chip::chip_lib::support::fault_injection::fault_injection::{
            Identifier, Manager,
        };
        use crate::chip::inet::inet_fault_injection::{get_manager, InetFaultInjectionID};
        static mut TEST_PARAMS_IPV4: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> =
            mem::MaybeUninit::uninit();
        static mut TEST_PARAMS_IPV6: mem::MaybeUninit<TestListenParameter<TestEndPointManager>> =
            mem::MaybeUninit::uninit();

        static mut TEST_TUPLE: Tuple<(Test<TestDelegate>, Test<TestDelegate>)> = Tuple {
            m_transports: (Test::default_const(), Test::default_const()),
        };

        const EXPECTED_SEND_PORT: u16 = 87;
        const EXPECTED_SEND_MSG: [u8; 4] = [11, 12, 13, 14];

        #[derive(Default)]
        struct TestDelegate {
            pub check: Cell<bool>,
            pub addr: Cell<PeerAddress>,
        }

        impl RawTransportDelegate for TestDelegate {
            fn handle_message_received(
                &self,
                peer_address: PeerAddress,
                _buffer: PacketBufferHandle,
                _ctxt: *const MessageTransportContext,
            ) {
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
                TEST_PARAMS_IPV4.write(
                    TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER))
                        .set_address_type(IPAddressType::KIPv4),
                );
                TEST_PARAMS_IPV6.write(
                    TestListenParameter::default(ptr::addr_of_mut!(END_POINT_MANAGER))
                        .set_address_type(IPAddressType::KIPv6),
                );

                /* since we reset end point manager, we have to manually reset these as well */
                TEST_TUPLE.m_transports.0 = Test::default();
                TEST_TUPLE.m_transports.1 = Test::default();

                let _ = get_manager().reset_configurations_all();
            }
        }

        #[test]
        fn send_by_first() {
            set_up();
            let mut delegate = TestDelegate::default();
            unsafe {
                TEST_TUPLE.init(
                    (ptr::addr_of_mut!(delegate), ptr::addr_of_mut!(delegate)),
                    (
                        TEST_PARAMS_IPV4.assume_init_mut().clone(),
                        TEST_PARAMS_IPV6.assume_init_mut().clone(),
                    ),
                );

                let pa = PeerAddress::udp_addr_port_interface(
                    IPAddress::ANY_IPV4.clone(),
                    EXPECTED_SEND_PORT,
                    InterfaceId::default(),
                );

                let msg =
                    PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4], 0, 8).unwrap();

                assert_eq!(TEST_TUPLE.send_message(pa, msg), chip_no_error!());
            }
        }

        #[test]
        fn send_by_second() {
            set_up();
            let mut delegate = TestDelegate::default();
            unsafe {
                TEST_TUPLE.init(
                    (ptr::addr_of_mut!(delegate), ptr::addr_of_mut!(delegate)),
                    (
                        TEST_PARAMS_IPV4.assume_init_mut().clone(),
                        TEST_PARAMS_IPV6.assume_init_mut().clone(),
                    ),
                );

                let pa = PeerAddress::udp_addr_port_interface(
                    IPAddress { addr: (1, 2, 3, 4) },
                    EXPECTED_SEND_PORT,
                    InterfaceId::default(),
                );

                let msg =
                    PacketBufferHandle::new_with_data(&EXPECTED_SEND_MSG[0..4], 0, 8).unwrap();

                assert_eq!(TEST_TUPLE.send_message(pa, msg), chip_no_error!());
            }
        }
    }
}
