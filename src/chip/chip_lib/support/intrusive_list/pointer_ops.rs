pub trait PointerOps {
    type Value: ?Sized;
    type Pointer;

    unsafe fn from_raw(&self, value: * const Self::Value) -> Self::Pointer;

    fn into_raw(&self, ptr: Self::Pointer) -> * const Self::Value;
}

