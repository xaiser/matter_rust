#[cfg(feature = "matter_tracing_enabled")]
#[macro_export]
macro_rules! matter_trace_scope {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_0: () = ();
        let _matter_tracing_scoped_auto_0 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[cfg(feature = "matter_tracing_enabled")]
#[macro_export]
macro_rules! matter_trace_scope_1 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_1: () = ();
        let _matter_tracing_scoped_auto_1 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[cfg(feature = "matter_tracing_enabled")]
#[macro_export]
macro_rules! matter_trace_scope_2 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_2: () = ();
        let _matter_tracing_scoped_auto_2 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[cfg(feature = "matter_tracing_enabled")]
#[macro_export]
macro_rules! matter_trace_scope_3 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_3: () = ();
        let _matter_tracing_scoped_auto_3 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[cfg(feature = "matter_tracing_enabled")]
#[macro_export]
macro_rules! matter_trace_scope_4 {
    ($label: expr, $group: expr) => {
        const _MATTER_TRACING_GUARD_DEFINE_SCOPE_4: () = ();
        let _matter_tracing_scoped_auto_4 = crate::chip::tracing::Scoped::new($label, $group);
    };
}

#[cfg(not(feature = "matter_tracing_enabled"))]
#[macro_export]
macro_rules! matter_trace_scope {
    ($label: expr, $group: expr) => { };
}

#[cfg(not(feature = "matter_tracing_enabled"))]
#[macro_export]
macro_rules! matter_trace_scope_1 {
    ($label: expr, $group: expr) => { };
}

#[cfg(not(feature = "matter_tracing_enabled"))]
#[macro_export]
macro_rules! matter_trace_scope_2 {
    ($label: expr, $group: expr) => { };
}

#[cfg(not(feature = "matter_tracing_enabled"))]
#[macro_export]
macro_rules! matter_trace_scope_3 {
    ($label: expr, $group: expr) => { };
}

#[cfg(not(feature = "matter_tracing_enabled"))]
#[macro_export]
macro_rules! matter_trace_scope_4 {
    ($label: expr, $group: expr) => { };
}
