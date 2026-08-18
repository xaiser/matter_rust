#[cfg(feature = "matter_tracing_enabled")]
pub mod macros;

#[cfg(not(feature = "matter_tracing_enabled"))]
pub mod macros_disabled;

pub mod backend;
pub mod metric_event;
pub mod metric_keys;
pub mod event;
pub mod registry;

pub use registry as internal;
pub use registry::Scoped;

// re-export trace structs
pub use crate::chip::chip_lib::address_resolve::tracing_structs::{
    NodeLookupInfo,
    DiscoveryInfoType,
    NodeDiscoveredInfo,
    NodeDiscoveryFailedInfo,
};

pub use crate::chip::transport::tracing_structs::{
    OutgoingMessageType,
    MessageSendInfo,
    IncomingMessageType,
    MessageReceivedInfo,
};
//pub use registry::init_tracing_service;
