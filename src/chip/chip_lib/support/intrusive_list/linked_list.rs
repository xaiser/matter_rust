use core::{
    cell::Cell,
    ptr::NonNull,
    num::NonZero,
    fmt,
};
use super::{
    pointer_ops::PointerOps,
    adapter::Adapter,
    link_ops::{self, DefaultLinkOps},
};


pub unsafe trait LinkedListOps: link_ops::LinkOps {
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>);
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>);
}

#[repr(align(2))]
pub struct Link {
    next: Cell<Option<NonNull<Link>>>,
    prev: Cell<Option<NonNull<Link>>>,
}

const UNLINKED_MARKER: Option<NonNull<Link>> = Some(NonNull::without_provenance(NonZero::new(1).unwrap()));

impl Link {
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(UNLINKED_MARKER),
            prev: Cell::new(UNLINKED_MARKER),
        }
    }

    #[inline]
    pub fn is_linked(&self) -> bool {
        self.next.get() != UNLINKED_MARKER
    }
}

impl DefaultLinkOps for Link {
    type Ops = LinkOps;

    const NEW: Self::Ops = LinkOps;
}

#[derive(Clone, Copy, Default)]
pub struct LinkOps;

unsafe impl link_ops::LinkOps for LinkOps {
    type LinkPtr = NonNull<Link>;

    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        if ptr.as_ref().is_linked() {
            false
        } else {
            ptr.as_ref().next.set(None);
            true
        }
    }

    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref().next.set(UNLINKED_MARKER)
    }
}

unsafe impl LinkedListOps for LinkOps {
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().next.get()
    }

    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().prev.get()
    }

    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        ptr.as_ref().next.set(next)
    }

    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        ptr.as_ref().prev.set(prev)
    }
}

impl Clone for Link {
    #[inline]
    fn clone(&self) -> Link {
        Link::new()
    }
}

impl Default for Link {
    #[inline]
    fn default() -> Link {
        Link::new()
    }
}

impl fmt::Debug for Link {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // There isn't anything sensible to print here except whether the link
        // is currently in a list.
        if self.is_linked() {
            write!(f, "linked")
        } else {
            write!(f, "unlinked")
        }
    }
}

/// A cursor which provides read-only access to a `LinkedList`.
pub struct Cursor<'a, A: Adapter> 
where
    A::LinkOps: LinkedListOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: &'a LinkedList<A>,
}

impl<'a, A: Adapter> Clone for Cursor<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn clone(&self) -> Cursor<'a, A> {
        Cursor {
            current: self.current,
            list: self.list,
        }
    }
}

impl<'a, A: Adapter> Cursor<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    pub fn is_null(&self) -> bool {
        self.current.is_none()
    }

    /// Returns a reference to the object that the cursor is currently
    /// pointing to.
    ///
    /// This returns `None` if the cursor is currently pointing to the null
    /// object.
    pub fn get(&self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        unsafe {
            Some(&*self.list.adapter.get_value(self.current?))
        }
    }

    /// Clones and returns the pointer that points to the element that the
    /// cursor is referencing.
    ///
    /// This returns `None` if the cursor is currently pointing to the null
    /// object.
    #[inline]
    pub fn clone_pointer(&self) -> Option<<A::PointerOps as PointerOps>::Pointer>
    where
        <A::PointerOps as PointerOps>::Pointer: Clone,
    {
        unsafe {
            let value = self.list.adapter.get_value(self.current?);

            Some(self.list.adapter.pointer_ops().from_raw(value))

                not in this way
        }
    }

    /*
    /// Moves the cursor to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `LinkedList`. If it is pointing to the
    /// last element of the `LinkedList` then this will move it to the
    /// null object.
    #[inline]
    pub fn move_next(&mut self) {
    }

    /// Moves the cursor to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
    }

    /// Returns a cursor pointing to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `LinkedList`. If it is pointing to the last
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
    }

    /// Returns a cursor pointing to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
    }
    */
}

pub struct LinkedList<A: Adapter>
where
    A::LinkOps: LinkedListOps
{
    head: Option<NonNull<<A::LinkOps as link_ops::LinkOps>::LinkPtr>>,
    tail: Option<NonNull<<A::LinkOps as link_ops::LinkOps>::LinkPtr>>,
    adapter: A,
}
