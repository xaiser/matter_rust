use core::mem::ManuallyDrop;
use core::ops::Deref;

pub trait PointerOps {
    type Value: ?Sized;
    type Pointer;

    unsafe fn from_raw(&self, value: * const Self::Value) -> Self::Pointer;

    fn into_raw(&self, ptr: Self::Pointer) -> * const Self::Value;
}

#[inline]
pub(crate) unsafe fn clone_pointer_from_raw<T: PointerOps>(
    pointer_ops: &T,
    ptr: *const T::Value,
) -> T::Pointer
where
    T::Pointer: Clone,
{
    /// Guard which converts an pointer back into its raw version
    /// when it gets dropped. This makes sure we also perform a full
    /// `from_raw` and `into_raw` round trip - even in the case of panics.
    struct PointerGuard<'a, T: PointerOps> {
        pointer: ManuallyDrop<T::Pointer>,
        pointer_ops: &'a T,
    }

    impl<'a, T: PointerOps> Drop for PointerGuard<'a, T> {
        #[inline]
        fn drop(&mut self) {
            // Prevent shared pointers from being released by converting them
            // back into the raw pointers
            // SAFETY: `pointer` is never dropped. `ManuallyDrop::take` is not stable until 1.42.0.
            let _ = self
                .pointer_ops
                .into_raw(unsafe { core::ptr::read(&*self.pointer) });
        }
    }

    let holder = PointerGuard {
        pointer: ManuallyDrop::new(pointer_ops.from_raw(ptr)),
        pointer_ops,
    };
    holder.pointer.deref().clone()
}

