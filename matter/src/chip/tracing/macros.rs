#[macro_export]
macro_rules! matter_trace_begin {
    ($label: expr, $group: expr) => {
        crate::chip::tracing::internal::begin($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_end {
    ($label: expr, $group: expr) => {
        crate::chip::tracing::internal::end($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_instant {
    ($label: expr, $group: expr) => {
        crate::chip::tracing::internal::instant($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_counter {
    ($label: expr) => {
        crate::chip::tracing::internal::counter($label);
    };
}

#[macro_export]
macro_rules! matter_trace_scope {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_0: () = ();
        let _matter_tracing_scoped_auto_0 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_scope_1 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_1: () = ();
        let _matter_tracing_scoped_auto_1 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_scope_2 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_2: () = ();
        let _matter_tracing_scoped_auto_2 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_scope_3 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_3: () = ();
        let _matter_tracing_scoped_auto_3 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[macro_export]
macro_rules! matter_trace_scope_4 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_4: () = ();
        let _matter_tracing_scoped_auto_4 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[macro_export]
macro_rules! matter_log_message_send {
    ($($info: expr),*) => {
        let matter_log_message_send_trace_data = crate::chip::tracing::MessageSendInfo::new($($info),*);
        crate::chip::tracing::internal::log_message_send(matter_log_message_send_trace_data);
    };
}

#[macro_export]
macro_rules! matter_log_message_received {
    ($($info: expr),*) => {
        let matter_log_message_received_trace_data = crate::chip::tracing::MessageReceivedInfo::new($($info),*);
        crate::chip::tracing::internal::log_message_received(matter_log_message_received_trace_data);
    };
}

#[macro_export]
macro_rules! matter_log_node_lookup {
    ($($info: expr),*) => {
        let matter_log_node_lookup_trace_data = crate::chip::tracing::NodeLookupInfo::new($($info),*);
        crate::chip::tracing::internal::log_node_lookup(matter_log_node_lookup_trace_data);
    };
}

#[macro_export]
macro_rules! matter_log_node_discovered {
    ($($info: expr),*) => {
        let matter_log_node_discovered_trace_data = crate::chip::tracing::NodeDiscoveredInfo::new($($info),*);
        crate::chip::tracing::internal::log_node_discovered(matter_log_node_discovered_trace_data);
    };
}

#[macro_export]
macro_rules! matter_log_node_discovery_failed {
    ($($info: expr),*) => {
        let matter_log_node_discovery_failed_trace_data = crate::chip::tracing::NodeDiscoveryFailedInfo::new($($info),*);
        crate::chip::tracing::internal::log_node_discovery_failed(matter_log_node_discovery_failed_trace_data);
    };
}
