
/*
use crate::chip::{
    chip_lib::address_resolve::tracing_structs::{NodeLookupInfo, NodeDiscoveredInfo, NodeDiscoveryFailedInfo},
    transport::tracing_structs::{MessageSendInfo, MessageReceivedInfo},
};
*/
use crate::chip::tracing::{NodeLookupInfo, NodeDiscoveredInfo, NodeDiscoveryFailedInfo, 
    MessageSendInfo, MessageReceivedInfo};

#[derive(Debug, Clone, Copy)]
pub struct LableGroup<'a> {
    pub label: &'a str,
    pub group: &'a str
}

impl<'a> LableGroup<'a> {
    pub const fn new(label: &'a str, group: &'a str) -> Self {
        Self {
            label,
            group,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    Begin(LableGroup<'a>),
    End(LableGroup<'a>),
    Instant(LableGroup<'a>),
    Count(&'a str),
}

impl<'a> Event<'a> {
    pub const fn begin(l: &'a str, g: &'a str) -> Self {
        Event::Begin(LableGroup::new(l, g))
    }

    pub const fn end(l: &'a str, g: &'a str) -> Self {
        Event::End(LableGroup::new(l, g))
    }

    pub const fn instant(l: &'a str, g: &'a str) -> Self {
        Event::Instant(LableGroup::new(l, g))
    }

    pub const fn count(l: &'a str) -> Self {
        Event::Count(l)
    }

    pub fn get_begin(&self) -> Option<LableGroup<'a>> {
        match self {
            Event::<'a>::Begin(lg) => Some(lg.clone()),
            _ => None,
        }
    }

    pub fn get_end(&self) -> Option<LableGroup<'a>> {
        match self {
            Event::<'a>::End(lg) => Some(lg.clone()),
            _ => None,
        }
    }

    pub fn get_instant(&self) -> Option<LableGroup<'a>> {
        match self {
            Event::<'a>::Instant(lg) => Some(lg.clone()),
            _ => None,
        }
    }

    pub fn get_count(&self) -> Option<&'a str> {
        match self {
            Event::<'a>::Count(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum MessageEvent<'a> {
    SendInfo(MessageSendInfo<'a>),
    ReceivedInfo(MessageReceivedInfo<'a>),
}

impl<'a> MessageEvent<'a> {
    pub const fn send_info(i: MessageSendInfo<'a>) -> Self {
        MessageEvent::SendInfo(i)
    }

    pub const fn received_info(r: MessageReceivedInfo<'a>) -> Self {
        MessageEvent::ReceivedInfo(r)
    }

    pub fn get_send_info(&self) -> Option<MessageSendInfo<'a>> {
        match self {
            MessageEvent::<'a>::SendInfo(i) => Some(i.clone()),
            _ => None,
        }
    }

    pub fn get_received_info(&self) -> Option<MessageReceivedInfo<'a>> {
        match self {
            MessageEvent::<'a>::ReceivedInfo(r) => Some(r.clone()),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum AddressResolveEvent<'a> {
    NodeLookupInfo(NodeLookupInfo<'a>),
    NodeDiscoveredInfo(NodeDiscoveredInfo<'a>),
    NodeDiscoveryFailedInfo(NodeDiscoveryFailedInfo<'a>),
}

impl<'a> AddressResolveEvent<'a> {
    pub const fn node_lookup_info(i: NodeLookupInfo<'a>) -> Self {
        AddressResolveEvent::NodeLookupInfo(i)
    }

    pub const fn node_discovered_info(i: NodeDiscoveredInfo<'a>) -> Self {
        AddressResolveEvent::NodeDiscoveredInfo(i)
    }

    pub const fn node_discovery_failed_info(i: NodeDiscoveryFailedInfo<'a>) -> Self {
        AddressResolveEvent::NodeDiscoveryFailedInfo(i)
    }

    pub fn get_node_lookup_info(&self) -> Option<NodeLookupInfo<'a>> {
        match self {
            AddressResolveEvent::NodeLookupInfo(i) => Some(i.clone()),
            _ => None,
        }
    }

    pub fn get_node_discovered_info(&self) -> Option<NodeDiscoveredInfo<'a>> {
        match self {
            AddressResolveEvent::NodeDiscoveredInfo(i) => Some(i.clone()),
            _ => None,
        }
    }

    pub fn get_node_discovery_failed_info(&self) -> Option<NodeDiscoveryFailedInfo<'a>> {
        match self {
            AddressResolveEvent::NodeDiscoveryFailedInfo(i) => Some(i.clone()),
            _ => None,
        }
    }
}

pub type TracingEvent = Event<'static>;
pub type MsgTracingEvent<'a> = MessageEvent<'a>;
pub type AddrResolveTracingEvent<'a> = AddressResolveEvent<'a>;
