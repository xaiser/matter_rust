use crate::{
    chip::{
        chip_lib::{
            support::{
                intrusive_list::{
                    linked_list::{self, Link},
                    adapter,
                },
            },
        },
        tracing::{
            backend::{BackendSubscriber, BackendOps},
        },
    },
};

type Adapter = adapter::linked_list::a_ref::DefaultAdapter<'static, BackendSubscriber>;
type BackendList = linked_list::LinkedList<Adapter>;

static g_tracning_backends: BackendList = BackendList::new(Adapter::new());

/*
pub fn register<P: BackendOps>(backedn: &Backend<P>);

pub fn unregister<P: BackendOps>(backedn: &Backend<P>);
*/
