use crate::{
    chip::{
        transport::{
            tracing_structs::{MessageSendInfo, MessageReceivedInfo},
        },
        chip_lib::{
            address_resolve::{
                tracing_structs::{NodeLookupInfo, NodeDiscoveredInfo, NodeDiscoveryFailedInfo},
            },
        },
        tracing::{
            event::Event,
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

pub struct BackendSubscriber {
    name: &'static str,
    channel: fn(event: Event),
}

impl BackendSubscriber {
}
