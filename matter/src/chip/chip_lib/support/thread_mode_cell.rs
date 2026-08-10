//! A cell-like API for static intenior mutagblility scenarios. This is only safe on single-core
//! system.

use core::cell::Cell;

#[inline(always)]
fn in_thread_mode() -> bool {
    // TODO: implement this
    true
}

pub struct ThreadModeCell<T: ?Sized> {
    inner: Cell<T>,
}

impl<T> ThreadModeCell<T> {
    pub const fn new(initial_value: T) -> Self {
        Self {
            inner: Cell::new(initial_value),
        }
    }

    pub fn set(&self, value: T) {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.set(value);
    }

    pub fn swap(&self, other: &Self) {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.swap(&other.inner);
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    pub fn replace(&self, val: T) -> T {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.replace(val)
    }
}

impl<T: Copy> ThreadModeCell<T> {
    pub fn get(&self) -> T {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.get()
    }

    pub fn update(&self, f: impl FnOnce(T) -> T) {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.update(f)
    }
}

impl<T:?Sized> ThreadModeCell<T> {
    pub const fn as_ptr(&self) -> * mut T {
        self.inner.as_ptr()
    }
}

impl<T: Default> ThreadModeCell<T> {
    pub fn take(&self) -> T {
        assert!(in_thread_mode(), "ThreadModeCell can only be accessed in thread mode");
        self.inner.take()
    }
}

unsafe impl<T> Sync for ThreadModeCell<T> {}

unsafe impl<T> Send for ThreadModeCell<T> where T: Send {}

impl<T: Copy> Clone for ThreadModeCell<T> {
    #[inline]
    fn clone(&self) -> ThreadModeCell<T> {
        ThreadModeCell::new(self.get())
    }
}

impl<T: Default> Default for ThreadModeCell<T> {
    #[inline]
    fn default() -> ThreadModeCell<T> {
        ThreadModeCell::new(Default::default())
    }
}

impl<T: PartialOrd + Copy> PartialOrd for ThreadModeCell<T> {
    #[inline]
    fn partial_cmp(&self, other: &ThreadModeCell<T>) -> Option<core::cmp::Ordering> {
        self.get().partial_cmp(&other.get())
    }
}

impl<T: PartialEq + Copy> PartialEq for ThreadModeCell<T> {
    #[inline]
    fn eq(&self, other: &ThreadModeCell<T>) -> bool {
        self.get() == other.get()
    }
}

impl<T: Eq + Copy> Eq for ThreadModeCell<T> {}

impl<T: Ord + Copy> Ord for ThreadModeCell<T> {
    #[inline]
    fn cmp(&self, other: &ThreadModeCell<T>) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl<T> From<T> for ThreadModeCell<T> {
    fn from(t: T) -> ThreadModeCell<T> {
        ThreadModeCell::new(t)
    }
}
