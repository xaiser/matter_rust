use crate::chip::chip_lib::support::fault_injection::Manager;

pub enum InetFaultInjectionID {
    KFaultTest,
    KFaultNumItems,
}

pub fn get_manager() -> &'static Manager {
}


