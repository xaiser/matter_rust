use crate::{
    chip::{
        chip_lib::{
            support::{
                intrusive_list::{
                    linked_list::{self, Link},
                    adapter,
                },
                SyncCell,
            },
        },
        tracing::{
            backend::BackendSubscriber,
        },
        platform::assert_chip_stack_locked_by_current_thread,
    },
};

pub type Adapter = adapter::linked_list::a_ref::DefaultAdapter<'static, BackendSubscriber>;
pub type BackendList = linked_list::LinkedList<Adapter>;

static TRACNING_BACKENDS: SyncCell<BackendList> = SyncCell::new(BackendList::new(
            Adapter::new()));

macro_rules! get_list {
    () => {
        {
            unsafe {
                if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                    list
                } else {
                    return;
                }
            }
        }
    };
}

pub fn register(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    let list = {
        unsafe {
            if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                list
            } else {
                return;
            }
        }
    };
    let mut b = list.front();

    while !b.is_null() {
        if b.get().is_some_and(|v| core::ptr::eq(v, backend)) {
            return;
        }
        b.move_next();
    }

    let _ = list.push_back(backend);
}

pub fn unregister(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    let list = {
        unsafe {
            if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                list
            } else {
                return;
            }
        }
    };

    let mut b = list.front_mut();

    while !b.is_null() {
        if b.get().is_some_and(|v| core::ptr::eq(v, backend)) {
            let _ = b.remove();
            break;
        }
        b.move_next();
    }
}

#[cfg(feature = "matter_tracing_enabled")]
pub mod internal {
    use super::*;
    use crate::{
        chip::{
            tracing::{
                MessageReceivedInfo,
                MessageSendInfo,
                NodeLookupInfo,
                NodeDiscoveredInfo,
                NodeDiscoveryFailedInfo,
                event::{LableGroup, TracingEvent, MsgTracingEvent, AddrResolveTracingEvent},
                metric_event::MetricEvent,
            },
        },
    };

    pub struct Scoped {
        pub label: &'static str,
        pub group: &'static str,
    }

    impl Scoped {
        pub fn new(label: &'static str, group: &'static str) -> Self {
            let s = Self {
                label,
                group,
            };
            
            begin(label, group);

            s
        }
    }


    impl Drop for Scoped {
        fn drop(&mut self) {
            end(self.label, self.group);
        }
    }

    pub fn begin(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::begin(label, group));
            }
            b.move_next();
        }
    }

    pub fn end(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::end(label, group));
            }
            b.move_next();
        }
    }

    pub fn instant(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::instant(label, group));
            }
            b.move_next();
        }
    }

    pub fn counter(label: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::counter(label));
            }
            b.move_next();
        }
    }

    pub fn log_message_send<'a>(info: MessageSendInfo<'a>) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_msg(MsgTracingEvent::send_info(info));
            }
            b.move_next();
        }
    }

    pub fn log_message_received<'a>(info: MessageReceivedInfo<'a>) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_msg(MsgTracingEvent::received_info(info));
            }
            b.move_next();
        }
    }

    pub fn log_node_lookup<'a>(info: NodeLookupInfo<'a>) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_addr_resolve(AddrResolveTracingEvent::node_lookup_info(info.clone()));
            }
            b.move_next();
        }
    }

    pub fn log_node_discovered<'a>(info: NodeDiscoveredInfo<'a>) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_addr_resolve(AddrResolveTracingEvent::node_discovered_info(info.clone()));
            }
            b.move_next();
        }
    }

    pub fn log_node_discovery_failed<'a>(info: NodeDiscoveryFailedInfo<'a>) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_addr_resolve(AddrResolveTracingEvent::node_discovery_failed_info(info.clone()));
            }
            b.move_next();
        }
    }

    pub fn log_metric_event(event: MetricEvent) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send_metric(event);
            }
            b.move_next();
        }
    }
} // end of internal

#[cfg(not(feature = "matter_tracing_enabled"))]
pub mod internal {
    pub struct Scoped;
    pub fn begin(_label: &str, _group: &str) { }
    pub fn end(_label: &str, _group: &str) { }
    pub fn instant(_label: &str, _group: &str) { }
    pub fn counter(_label: &str) { }
}

pub use internal::*;

#[cfg(all(test, feature = "matter_tracing_enabled"))]
mod tests {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                address_resolve::address_resolve::{
                    NodeLookupRequest, ResolveResult,
                },
                core::node_id::KUNDEFINED_NODE_ID,
            },
            tracing::{
                backend::BackendSubscriber,
                event::{TracingEvent, MsgTracingEvent, AddrResolveTracingEvent},
                OutgoingMessageType, IncomingMessageType,
                MessageSendInfo, MessageReceivedInfo,
                DiscoveryInfoType, NodeLookupInfo, NodeDiscoveredInfo, NodeDiscoveryFailedInfo,
            },
            transport::{
                raw::{
                    message_header::{PayloadHeader, PacketHeader},
                    peer_address::PeerAddress,
                },
                session::{Session, SessionHandle, new_session_alloactor},
            },
            PeerId,
        },
        ChipError,
        chip_sdk_error,
        chip_core_error,
        chip_error_message_counter_exhausted,
        matter_log_message_send,
        matter_log_message_received,
        matter_log_node_lookup,
        matter_log_node_discovered,
        matter_log_node_discovery_failed,
        matter_trace_begin,
        matter_trace_end,
        matter_trace_instant,
        matter_trace_counter,
    };
    use std::sync::{LazyLock, Mutex};

    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    enum MsgType {
        MsgOut(OutgoingMessageType),
        MsgIn(IncomingMessageType),
    }

    #[derive(PartialEq, Eq, Debug, Clone)]
    enum AddrResolveType {
        Lookup(u32),
        Discovered(DiscoveryInfoType),
        Failed(PeerId),
    }

    static TRACE_EVENTS: LazyLock<Mutex<Vec<TracingEvent>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static TRACE_EVENTS_2: LazyLock<Mutex<Vec<TracingEvent>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static MSG_TRACE_EVENTS: LazyLock<Mutex<Vec<MsgType>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static ADDR_TRACE_EVENTS: LazyLock<Mutex<Vec<AddrResolveType>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static BACKEND: SyncCell<BackendSubscriber> = SyncCell::new(BackendSubscriber::new("test_backend", add_event, Some(add_msg_event), Some(add_addr_resolve_event), None));
    static BACKEND_2: SyncCell<BackendSubscriber> = SyncCell::new(BackendSubscriber::new("test_backend_2", add_event_2, None, None, None));

    fn add_event(event: TracingEvent) {
        TRACE_EVENTS.lock().unwrap().push(event);
    }

    fn add_event_2(event: TracingEvent) {
        TRACE_EVENTS_2.lock().unwrap().push(event);
    }

    fn add_msg_event(event: MsgTracingEvent) {
        match event {
            MsgTracingEvent::SendInfo(i) => {
                MSG_TRACE_EVENTS.lock().unwrap().push(MsgType::MsgOut(i.message_type));
            },
            MsgTracingEvent::ReceivedInfo(i) => {
                MSG_TRACE_EVENTS.lock().unwrap().push(MsgType::MsgIn(i.message_type));
            },
        }
    }

    fn add_addr_resolve_event(event: AddrResolveTracingEvent) {
        match event {
            AddrResolveTracingEvent::NodeLookupInfo(info) => {
                ADDR_TRACE_EVENTS.lock().unwrap().push(AddrResolveType::Lookup(info.request as * const NodeLookupRequest as u32));
            },
            AddrResolveTracingEvent::NodeDiscoveredInfo(info) => {
                ADDR_TRACE_EVENTS.lock().unwrap().push(AddrResolveType::Discovered(info.info_type));
            },
            AddrResolveTracingEvent::NodeDiscoveryFailedInfo(info) => {
                ADDR_TRACE_EVENTS.lock().unwrap().push(AddrResolveType::Failed(info.peer_id.clone()));
            },
        }
    }

    /*
    fn get_event(index: usize) -> Option<&'static TracingEvent> {
        TRACE_EVENTS.lock().unwrap().get(index)
    }
    */

    fn setup() {
        unsafe {
            register(BACKEND.as_ptr().as_ref().unwrap());
            register(BACKEND_2.as_ptr().as_ref().unwrap());
        }
    }

    fn tear_down() {
        unsafe {
            unregister(BACKEND.as_ptr().as_ref().unwrap());
            unregister(BACKEND_2.as_ptr().as_ref().unwrap());
        }
        TRACE_EVENTS.lock().unwrap().clear();
        TRACE_EVENTS_2.lock().unwrap().clear();
        MSG_TRACE_EVENTS.lock().unwrap().clear();
        ADDR_TRACE_EVENTS.lock().unwrap().clear();
        let list = get_list!();
        list.clear();
    }

    #[test]
    fn send_begin_successfull() {
        setup();
        begin("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_begin_macro_successfull() {
        setup();
        matter_trace_begin!("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_end_successfull() {
        setup();
        end("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_end_macro_successfull() {
        setup();
        matter_trace_end!("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_instant_successfull() {
        setup();
        instant("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_instant().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_instant().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_instant_macro_successfull() {
        setup();
        matter_trace_instant!("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_instant().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_instant().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_counter_successfull() {
        setup();
        counter("1");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_counter().is_some_and(|s| s == "1")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_counter().is_some_and(|s| s == "1")
        ));
        tear_down();
    }

    #[test]
    fn send_counter_macro_successfull() {
        setup();
        matter_trace_counter!("1");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_counter().is_some_and(|s| s == "1")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_counter().is_some_and(|s| s == "1")
        ));
        tear_down();
    }

    #[test]
    fn send_begin_end_successfull() {
        setup();
        begin("1", "2");
        end("3", "4");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "3" && lg.group == "4")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS_2.lock().unwrap().get(1).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "3" && lg.group == "4")
        ));
        tear_down();
    }

    #[test]
    fn send_log_message_send_successfully() {
        setup();
        let payload_header = PayloadHeader::default();
        let packet_header = PacketHeader::default();
        let payload = [0];
        let info = MessageSendInfo::new(OutgoingMessageType::KgroupMessage, &payload_header, &packet_header, &payload[..]);

        log_message_send(info);

        matter_log_message_send!(OutgoingMessageType::KsecureSession, &payload_header, &packet_header, &payload[..]);

        assert!(MSG_TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|s| 
                *s == MsgType::MsgOut(OutgoingMessageType::KgroupMessage))
        );
        assert!(MSG_TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|s| 
                *s == MsgType::MsgOut(OutgoingMessageType::KsecureSession))
        );

        tear_down();
    }

    #[test]
    fn send_log_message_received_successfully() {
        setup();
        let payload_header = PayloadHeader::default();
        let packet_header = PacketHeader::default();
        let peer_address = PeerAddress::default();
        let mut session_pool = new_session_alloactor();
        let session = SessionHandle::try_new_handle(Session::new_unauthenticated(), core::ptr::addr_of_mut!(session_pool)).unwrap();
        let payload = [0];
        let info = MessageReceivedInfo::new(IncomingMessageType::KgroupMessage, &payload_header, &packet_header, &session, &peer_address, &payload[..]);

        log_message_received(info);

        matter_log_message_received!(IncomingMessageType::KsecureUnicast, &payload_header, &packet_header, &session, &peer_address, &payload[..]);

        assert!(MSG_TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|s| 
                *s == MsgType::MsgIn(IncomingMessageType::KgroupMessage))
        );
        assert!(MSG_TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|s| 
                *s == MsgType::MsgIn(IncomingMessageType::KsecureUnicast))
        );

        tear_down();
    }

    #[test]
    fn send_node_lookup_successfully() {
        setup();
        let request = NodeLookupRequest;
        let request_2 = NodeLookupRequest;
        let info = NodeLookupInfo::new(&request);

        log_node_lookup(info);

        matter_log_node_lookup!(&request_2);

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                *e == AddrResolveType::Lookup(core::ptr::addr_of!(request) as u32))
        );

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|e| 
                *e == AddrResolveType::Lookup(core::ptr::addr_of!(request_2) as u32))
        );

        tear_down();
    }

    #[test]
    fn send_node_discovered_successfully() {
        setup();
        let result = ResolveResult;
        let result_2 = ResolveResult;
        let peer_id = PeerId::new();
        let info = NodeDiscoveredInfo::new(DiscoveryInfoType::KintermediateResult, &peer_id, &result);

        log_node_discovered(info);

        matter_log_node_discovered!(DiscoveryInfoType::KresolutionDone, &peer_id, &result_2);

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                *e == AddrResolveType::Discovered(DiscoveryInfoType::KintermediateResult)));

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|e| 
                *e == AddrResolveType::Discovered(DiscoveryInfoType::KresolutionDone)));

        tear_down();
    }

    #[test]
    fn send_node_discovery_failed_successfully() {
        setup();
        let peer_id = PeerId::new();
        let peer_id_2 = PeerId::new().set_node_id(1);
        let info = NodeDiscoveryFailedInfo::new(&peer_id, chip_error_message_counter_exhausted!());

        log_node_discovery_failed(info);

        matter_log_node_discovery_failed!(&peer_id_2, chip_error_message_counter_exhausted!());

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                *e == AddrResolveType::Failed(peer_id.clone())));

        assert!(ADDR_TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|e| 
                *e == AddrResolveType::Failed(peer_id_2.clone())));

        tear_down();
    }
} // end of tests
