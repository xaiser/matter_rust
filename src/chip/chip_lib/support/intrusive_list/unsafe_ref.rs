use core::ptr::NonNull;

pub struct UnsafeRef<T: ?Sized> {
    ptr: NonNull<T>,
}

impl<T: ?Sized> UnsafeRef<T> {
    pub unsafe fn from_raw(val: * const T) -> Self {
        UnsafeRef {
            ptr: NonNull::new_unchecked(val as * mut _)
        }
    }

    pub fn into_raw(ptr: Self) -> * mut T {
        ptr.ptr.as_ptr()
    }
}
