use super::{
    link_ops::LinkOps,
    pointer_ops::PointerOps,
};

pub unsafe trait Adapter {
    type LinkOps: LinkOps;
    type PointerOps: PointerOps;

    unsafe fn get_value(&self, link: <Self::LinkOps as LinkOps>::LinkPtr) -> * const <Self::PointerOps as PointerOps>::Value;

    unsafe fn get_link(&self, value: * const <Self::PointerOps as PointerOps>::Value) -> <Self::LinkOps as LinkOps>::LinkPtr;

    fn link_ops(&self) -> &Self::LinkOps;

    fn link_ops_mut(&mut self) -> &mut Self::LinkOps;

    fn pointer_ops(&self) -> &Self::PointerOps;
}

#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $container:path, $($fields:expr)+) => {
        #[allow(clippy::cast_ptr_alignment)]
        {
            ($ptr as *const _ as *const u8).sub($crate::offset_of!($container, $($fields)+))
                as *const $container
        }
    };
}
mod linked_list {
    mod rc {
        /// A simple implement which the link must be the first element of the struct and the name must be
        /// "link". Also, the pointer must be Rc.
        use super::super::super::{
            linked_list::Link,
            link_ops::DefaultLinkOps,
            pointer_ops::PointerOps,
        };
        pub struct DefaultAdapter<PointerOpsType>
            where
                PointerOpsType: PointerOps,
        {
            link_ops: <Link as DefaultLinkOps>::Ops,
            pointer_ops: PointerOpsType,
        }
    }
}
