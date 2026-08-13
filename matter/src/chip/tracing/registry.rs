use crate::{
    chip::{
        chip_lib::{
            support::{
                intrusive_list::{
                    linked_list::{self, Link},
                    adapter,
                },
                SyncCell,
            },
        },
        tracing::{
            backend::BackendSubscriber,
        },
        platform::assert_chip_stack_locked_by_current_thread,
    },
};

//use static_cell::StaticCell;
use core::cell::RefCell;

pub type Adapter = adapter::linked_list::a_ref::DefaultAdapter<'static, BackendSubscriber>;
pub type BackendList = linked_list::LinkedList<Adapter>;

static TRACNING_BACKENDS: SyncCell<BackendList> = SyncCell::new(BackendList::new(
            Adapter::new()));

macro_rules! get_list {
    () => {
        {
            unsafe {
                if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                    list
                } else {
                    return;
                }
            }
        }
    };
}

pub fn register(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    let list = {
        unsafe {
            if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                list
            } else {
                return;
            }
        }
    };
    let mut b = list.front();

    while !b.is_null() {
        if b.get().is_some_and(|v| core::ptr::eq(v, backend)) {
            return;
        }
        b.move_next();
    }

    let _ = list.push_back(backend);
}

pub fn unregister(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    let list = {
        unsafe {
            if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                list
            } else {
                return;
            }
        }
    };

    let mut b = list.front_mut();

    while !b.is_null() {
        if b.get().is_some_and(|v| core::ptr::eq(v, backend)) {
            let _ = b.remove();
            break;
        }
        b.move_next();
    }
}

#[cfg(feature = "matter_tracing_enabled")]
pub mod internal {
    use super::*;
    use crate::{
        chip::{
            tracing::{
                event::{LableGroup, TracingEvent},
            },
        },
    };

    pub fn begin(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::begin(label, group));
            }
            b.move_next();
        }
    }

    pub fn end(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::end(label, group));
            }
            b.move_next();
        }
    }

    pub fn instant(label: &'static str, group: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::instant(label, group));
            }
            b.move_next();
        }
    }

    pub fn count(label: &'static str) {
        let list = get_list!();

        let mut b = list.front();

        while !b.is_null() {
            if let Some(bs) = b.get() {
                bs.send(TracingEvent::count(label));
            }
            b.move_next();
        }
    }
} // end of internal

#[cfg(not(feature = "matter_tracing_enabled"))]
pub mod internal {
    pub fn begin(_label: &str, _group: &str) { }
    pub fn end(_label: &str, _group: &str) { }
    pub fn instant(_label: &str, _group: &str) { }
    pub fn count(_label: &str) { }
}

pub use internal::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chip::{
            tracing::{
                backend::BackendSubscriber,
                event::TracingEvent,
            },
        },
    };
    use std::sync::{LazyLock, Mutex};

    static TRACE_EVENTS: LazyLock<Mutex<Vec<TracingEvent>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static BACKEND: SyncCell<BackendSubscriber> = SyncCell::new(BackendSubscriber::new("test_backend", add_event));

    fn add_event(event: TracingEvent) {
        TRACE_EVENTS.lock().unwrap().push(event);
    }

    /*
    fn get_event(index: usize) -> Option<&'static TracingEvent> {
        TRACE_EVENTS.lock().unwrap().get(index)
    }
    */

    fn setup() {
        unsafe {
            register(BACKEND.as_ptr().as_ref().unwrap());
        }
    }

    fn tear_down() {
        unsafe {
            unregister(BACKEND.as_ptr().as_ref().unwrap());
        }
        TRACE_EVENTS.lock().unwrap().clear();
        let list = get_list!();
        list.clear();
    }

    #[test]
    fn send_begin_successfull() {
        setup();
        begin("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_end_successfull() {
        setup();
        end("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_instant_successfull() {
        setup();
        instant("1", "2");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_instant().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        tear_down();
    }

    #[test]
    fn send_count_successfull() {
        setup();
        count("1");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_count().is_some_and(|s| s == "1")
        ));
        tear_down();
    }

    #[test]
    fn send_begin_end_successfull() {
        setup();
        begin("1", "2");
        end("3", "4");
        assert!(TRACE_EVENTS.lock().unwrap().get(0).is_some_and(|e| 
                e.get_begin().is_some_and(|lg| lg.label == "1" && lg.group == "2")
        ));
        assert!(TRACE_EVENTS.lock().unwrap().get(1).is_some_and(|e| 
                e.get_end().is_some_and(|lg| lg.label == "3" && lg.group == "4")
        ));
        tear_down();
    }
} // end of tests
