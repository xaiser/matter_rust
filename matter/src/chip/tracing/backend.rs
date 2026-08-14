use crate::{
    chip::{
        transport::{
            tracing_structs::{MessageSendInfo, MessageReceivedInfo},
        },
        chip_lib::{
            address_resolve::{
                tracing_structs::{NodeLookupInfo, NodeDiscoveredInfo, NodeDiscoveryFailedInfo},
            },
            support::{
                intrusive_list::{
                    linked_list::Link,
                },
            },
        },
        tracing::{
            event::{
                TracingEvent,
                MsgTracingEvent,
                AddrResolveTracingEvent,
            },
            metric_event::MetricEvent,
        },
    },
};

pub trait BackendOps {
    // Guaranteed to be called before registering
    fn open(&self) {}
    // Guaranteed to be called after un-registering.
    fn close(&self) {}

    // Begin a trace for the specified scope.
    //
    // Scope WILL be completed by a corresponding TraceEnd call.
    fn trace_begin(&self, _label: &str, _group: &str) {}

    // Tracing end assumes completing a previously started scope with TraceBegin
    // and nesting is assumed.
    //
    // Expect scopes like:
    //    TraceBegin("foo", "A")
    //      TraceBegin("bar", "A")
    //
    //      // NOT VALID HERE: TraceEnd("foo", "A")
    //
    //      TraceEnd("bar", "A")  // ends "BAR"
    //    TraceEnd("foo", "A")    // ends "FOO"
    fn trace_end(&self, _label: &str, _group: &str) {}

    // Trace a zero-sized event
    fn trace_instant(&self, _label: &str, _gorup: &str) {}

    fn trace_count(&self, _label: &str) {}

    fn log_message_send(&self, _info: &MessageSendInfo) {
        self.trace_instant("MessageSent", "Messaging");
    }

    fn log_message_received(&self, _info: &MessageReceivedInfo) {
        self.trace_instant("MessageReceived", "Messaging");
    }

    fn log_node_lookup(&self, _info: &NodeLookupInfo) {
        self.trace_instant("Lookup", "DNSSD");
    }

    fn log_node_discovered(&self, _info: &NodeDiscoveredInfo) {
        self.trace_instant("Node Discovered", "DNSSD");
    }

    fn log_node_discovery_failed(&self, _info: &NodeDiscoveryFailedInfo) {
        self.trace_instant("Discovery Failed", "DNSSD");
    }

    fn log_metric_event(&self, _event: &MetricEvent) {
        self.trace_instant("Metric Event", "Metric");
    }
}

// In order to keep the order, must add repr(c)
#[repr(C)]
pub struct BackendSubscriber {
    #[allow(dead_code)]
    link: Link,
    name: &'static str,
    channel: fn(event: TracingEvent),
    message_channel: Option<fn(event: MsgTracingEvent)>,
    address_solve_channel: Option<fn(event: AddrResolveTracingEvent)>,
    metric_channel: Option<fn(event: MetricEvent)>,
}

impl BackendSubscriber {
    pub const fn new(name: &'static str, channel: fn(event: TracingEvent), message_channel: Option<fn(event: MsgTracingEvent)>,
        address_solve_channel: Option<fn(event: AddrResolveTracingEvent)>, metric_channel: Option<fn(event: MetricEvent)>) -> Self {
        Self {
            link: Link::new(),
            name,
            channel,
            message_channel,
            address_solve_channel,
            metric_channel,
        }
    }

    pub fn send(&self, event: TracingEvent) {
        (self.channel)(event);
    }

    pub fn send_msg(&self, event: MsgTracingEvent) {
        if let Some(c) = self.message_channel {
            (c)(event);
        }
    }

    pub fn send_addr_resolve(&self, event: AddrResolveTracingEvent) {
        if let Some(c) = self.address_solve_channel {
            (c)(event);
        }
    }

    pub fn send_metric(&self, event: MetricEvent) {
        if let Some(c) = self.metric_channel {
            (c)(event);
        }
    }

    /*
    pub const fn name(&self) -> &str {
        self.name
    }
    */
}
