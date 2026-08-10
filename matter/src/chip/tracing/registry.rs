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

use static_cell::StaticCell;

pub type Adapter = adapter::linked_list::a_ref::DefaultAdapter<'static, BackendSubscriber>;
pub type BackendList = linked_list::LinkedList<Adapter>;

static TRACNING_BACKENDS: SyncCell<Option<&'static BackendList>> = SyncCell::new(None);

fn is_in_list(backend: &BackendSubscriber, list: &'static BackendList) -> bool {
    false
}

pub fn init_tracing_service(list: &'static BackendList) {
    TRACNING_BACKENDS.set(Some(list))
}

pub fn register(backend: &BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    if let Some(list) = TRACNING_BACKENDS.get() {
        if !is_in_list(backend, list) {
            list.push_back(backend);
        }
    }
}

pub fn unregister(backend: &BackendSubscriber) {
    assert_chip_stack_locked_by_current_thread();
    if let Some(list) = TRACNING_BACKENDS.get() {
        if is_in_list(backend, list) {
            list.remove(backend);
        }
    }
}
