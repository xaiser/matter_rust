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
pub mod linked_list {
    pub mod rc {
        /// A simple implement which the link must be the first element of the struct and the name must be
        /// "link". Also, the pointer must be Rc.
        use super::super::super::{
            linked_list::Link,
            link_ops::{LinkOps, DefaultLinkOps},
            pointer_ops::{PointerOps, RcPointerOps},
        };
        use crate::chip::chip_lib::core::reference_counted::rc::{Allocator, Rc};

        #[derive(Copy, Clone)]
        pub struct DefaultAdapter<T, A>
        where
            A: Allocator<T>,
        {
            link_ops: <Link as DefaultLinkOps>::Ops,
            pointer_ops: RcPointerOps<T, A>,
        }

        #[allow(dead_code)]
        impl<T, A: Allocator<T>> DefaultAdapter<T, A> {
            pub const NEW: Self = DefaultAdapter {
                link_ops: <Link as DefaultLinkOps>::NEW,
                pointer_ops: RcPointerOps::<T, A>::new(),
            };

            #[inline]
            pub const fn new() -> Self {
                Self::NEW
            }

            #[inline]
            pub const fn new_in(alloc: * mut A) -> Self {
                Self {
                    link_ops: <Link as DefaultLinkOps>::NEW,
                    pointer_ops: RcPointerOps::<T, A>::new_in(alloc),
                }
            }
        }

        #[allow(dead_code)]
        unsafe impl<T, A: Allocator<T>> super::super::Adapter for DefaultAdapter<T, A> {
            type LinkOps = <Link as DefaultLinkOps>::Ops;
            type PointerOps = RcPointerOps<T, A>;

            #[inline]
            unsafe fn get_value(&self, link: <Self::LinkOps as LinkOps>::LinkPtr) -> * const <Self::PointerOps as PointerOps>::Value {
                // the assumption is the link is always the first element in the value. So just
                // convert the pointer directly
                link.as_ptr() as * const T
            }

            #[inline]
            unsafe fn get_link(&self, value: * const <Self::PointerOps as PointerOps>::Value) -> <Self::LinkOps as LinkOps>::LinkPtr {
                // the assumption is the link is always the first element in the value. So just
                // convert the pointer directly

                core::ptr::NonNull::new_unchecked(value as * mut _)
            }

            #[inline]
            fn link_ops(&self) -> &Self::LinkOps {
                &self.link_ops
            }

            #[inline]
            fn link_ops_mut(&mut self) -> &mut Self::LinkOps {
                &mut self.link_ops
            }

            #[inline]
            fn pointer_ops(&self) -> &Self::PointerOps {
                &self.pointer_ops
            }
        }
    }

    pub mod unsafe_ref {
        /// A simple implement which the link must be the first element of the struct and the name must be
        /// "link". Also, the pointer must be unsafe_ref.
        use super::super::super::{
            linked_list::Link,
            link_ops::{LinkOps, DefaultLinkOps},
            pointer_ops::{PointerOps, DefaultPointerOps},
            unsafe_ref::UnsafeRef,
        };

        #[derive(Copy, Clone)]
        pub struct DefaultAdapter<T>
        {
            link_ops: <Link as DefaultLinkOps>::Ops,
            pointer_ops: DefaultPointerOps<UnsafeRef<T>>,
        }
    }
}
