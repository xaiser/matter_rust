pub unsafe trait LinkOps {
    type LinkPtr: Copy + Eq;

    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool;

    unsafe fn release_link(&mut self, ptr: Self::LinkPtr);
}

pub trait DefaultLinkOps {
    type Ops: LinkOps + Default;

    const NEW: Self::Ops;
}
