pub enum Stats {
    KsystemLayerNumPacketBufs,
    KsystemLayerNumTimers,
    KinetLayerNumTCPEps,
    KinetLayerNumUDPEps,
    KexchangeMgrNumContexts,
    KexchangeMgrNumUMHandlers,
    KplatformMgrNumEvents,
    KnumEntries
}

#[macro_export]
macro_rules! system_stats_increment {
    ($entry:expr) => {
    };
}
