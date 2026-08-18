#[macro_export]
macro_rules! matter_trace_begin {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_end {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_instant {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_counter {
    ($label: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_scope {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_scope_1 {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_scope_2 {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_scope_3 {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_trace_scope_4 {
    ($label: expr, $group: expr) => { };
}

#[macro_export]
macro_rules! matter_log_message_send {
    ($($info: expr),*) => { };
}

#[macro_export]
macro_rules! matter_log_message_received {
    ($($info: expr),*) => { };
}

#[macro_export]
macro_rules! matter_log_node_lookup {
    ($($info: expr),*) => { };
}

#[macro_export]
macro_rules! matter_log_node_discovered {
    ($($info: expr),*) => { };
}

#[macro_export]
macro_rules! matter_log_node_discovery_failed {
    ($($info: expr),*) => { };
}
