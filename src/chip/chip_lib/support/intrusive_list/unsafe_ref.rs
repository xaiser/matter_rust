use core::ptr::NonNull;
use core::borrow::Borrow;
use core::ops::Deref;

pub struct UnsafeRef<T: ?Sized> {
    ptr: NonNull<T>,
}

impl<T: ?Sized> UnsafeRef<T> {
    pub unsafe fn from_raw(val: * const T) -> Self {
        unsafe {
            UnsafeRef {
                    ptr: NonNull::new_unchecked(val as * mut _)
            }
        }
    }

    pub fn into_raw(ptr: Self) -> * mut T {
        ptr.ptr.as_ptr()
    }
}

impl<T: ?Sized> Clone for UnsafeRef<T> {
    #[inline]
    fn clone(&self) -> UnsafeRef<T> {
        UnsafeRef { ptr: self.ptr }
    }
}

impl<T: ?Sized> Deref for UnsafeRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T: ?Sized> AsRef<T> for UnsafeRef<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> Borrow<T> for UnsafeRef<T> {
    #[inline]
    fn borrow(&self) -> &T {
        self.as_ref()
    }
}
