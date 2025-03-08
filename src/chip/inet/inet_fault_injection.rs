use crate::chip::chip_lib::support::fault_injection::fault_injection::{Manager,Record};

static mut S_FAULT_RECORD_ARRAY: [Record; InetFaultInjectionID::KFaultNumItems as usize] = [Record::const_default(); InetFaultInjectionID::KFaultNumItems as usize];
static mut S_INET_FAULT_MANAGER: Manager = Manager::const_default();
static S_INET_FAULT_MANAGER_NAME: &str = "Inet";
static S_FAULT_NAMES: [&str; InetFaultInjectionID::KFaultNumItems as usize] = [ "bind", "listen", "send" ];

pub enum InetFaultInjectionID {
    KFaultBind,
    KFaultListen,
    KFaultSend,
    KFaultNumItems,
}

pub fn get_manager() -> &'static mut Manager {
    unsafe {
        if 0 == S_INET_FAULT_MANAGER.get_num_faults() {
            let _ = S_INET_FAULT_MANAGER.init(InetFaultInjectionID::KFaultNumItems as usize, 
                &mut S_FAULT_RECORD_ARRAY,
                &S_INET_FAULT_MANAGER_NAME, &S_FAULT_NAMES);
        }
        return &mut S_INET_FAULT_MANAGER;
    }
}

#[cfg(feature = "chip_with_inet_fault_injection")]
#[macro_export]
macro_rules! inet_fault_inject {
    ($fault_id:expr $(, $action:stmt)*) => {
        fault_inject!(crate::chip::inet::inet_fault_injection::get_manager(), $fault_id $(, $action)*);
    };
}

#[cfg(not(feature = "chip_with_inet_fault_injection"))]
#[macro_export]
macro_rules! inet_fault_inject {
    ($fault_id:expr $(, $action:stmt)*) => {
    };
}
