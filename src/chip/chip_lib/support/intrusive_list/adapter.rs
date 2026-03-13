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

    fn links_ops_mut(&mut self) -> &mut Self::LinkOps;

    fn pointer_ops(&self) -> &Self::PointerOps;
}
