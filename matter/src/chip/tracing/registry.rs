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
            backend::{BackendSubscriber, BackendOps},
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

fn is_in_list(backend: &BackendSubscriber, list: &BackendList) -> bool {
    false
}

pub fn register(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    /*
    if let Some(list) = TRACNING_BACKENDS.get() {
        if !is_in_list(backend, list) {
            list.push_back(backend);
        }
    }
    */
    let list = {
        unsafe {
            if let Some(list) = TRACNING_BACKENDS.as_ptr().as_mut() {
                list
            } else {
                return;
            }
        }
    };
    if !is_in_list(backend, list) {
        list.push_back(backend);
    }
}

/*
pub fn unregister(backend: &'static BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    if let Some(list) = TRACNING_BACKENDS.get() {
        if is_in_list(backend, list) {
            //list.remove(backend);
        }
    }
}
*/
