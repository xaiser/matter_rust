use core::{
    cell::Cell,
    ptr::NonNull,
    num::NonZero,
    fmt,
};
use super::{
    pointer_ops::{self, PointerOps},
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


#[inline]
unsafe fn link_between<T: LinkedListOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    prev: Option<T::LinkPtr>,
    next: Option<T::LinkPtr>,
) {
    if let Some(p) = prev {
        link_ops.set_next(p, Some(ptr));
    }
    if let Some(n) = next {
        link_ops.set_prev(n, Some(ptr));
    }

    link_ops.set_next(ptr, next);
    link_ops.set_prev(ptr, prev);
}

#[inline]
unsafe fn link_after<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, prev: T::LinkPtr) {
    link_between(link_ops, ptr, Some(prev), link_ops.next(prev));
}

#[inline]
unsafe fn link_before<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, next: T::LinkPtr) {
    link_between(link_ops, ptr, link_ops.prev(next), Some(next));
}

#[inline]
unsafe fn replace_with<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, new: T::LinkPtr) {
    link_between(link_ops, new, link_ops.prev(ptr), link_ops.next(ptr));

    link_ops.release_link(ptr);
}

#[inline]
unsafe fn remove<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr) {
    let prev = link_ops.prev(ptr);
    let next = link_ops.next(ptr);

    if let Some(p) = prev {
        link_ops.set_next(p, next);
    }
    if let Some(n) = next {
        link_ops.set_prev(n, prev);
    }

    link_ops.release_link(ptr);
}

#[inline]
unsafe fn splice<T: LinkedListOps>(
    link_ops: &mut T,
    start: T::LinkPtr,
    end: T::LinkPtr,
    prev: Option<T::LinkPtr>,
    next: Option<T::LinkPtr>,
) {
    link_ops.set_prev(start, prev);
    link_ops.set_next(end, next);
    if let Some(prev) = prev {
        link_ops.set_next(prev, Some(start));
    }
    if let Some(next) = next {
        link_ops.set_prev(next, Some(end));
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

            Some(pointer_ops::clone_pointer_from_raw(self.list.adapter.pointer_ops(), value))
        }
    }

    /// Moves the cursor to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `LinkedList`. If it is pointing to the
    /// last element of the `LinkedList` then this will move it to the
    /// null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(cursor) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().next(cursor) };
        } else {
            self.current = self.list.head;
        }
    }

    /// Moves the cursor to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(cursor) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().prev(cursor) };
        } else {
            self.current = self.list.tail;
        }
    }

    /// Returns a cursor pointing to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `LinkedList`. If it is pointing to the last
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.clone();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.clone();
        prev.move_prev();
        prev
    }
}

/// A cursor which provides mutable access to a `LinkedList`.
pub struct CursorMut<'a, A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: &'a mut LinkedList<A>,
}

impl<'a, A: Adapter> CursorMut<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    /// Checks if the cursor is currently pointing to the null object.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.current.is_none()
    }

    /// Returns a reference to the object that the cursor is currently
    /// pointing to.
    ///
    /// This returns None if the cursor is currently pointing to the null
    /// object.
    #[inline]
    pub fn get(&self) -> Option<&<A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.list.adapter.get_value(self.current?) })
    }

    /// Returns a read-only cursor pointing to the current element.
    ///
    /// The lifetime of the returned `Cursor` is bound to that of the
    /// `CursorMut`, which means it cannot outlive the `CursorMut` and that the
    /// `CursorMut` is frozen for the lifetime of the `Cursor`.
    #[inline]
    pub fn as_cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: self.current,
            list: self.list,
        }
    }

    /// Moves the cursor to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `LinkedList`. If it is pointing to the
    /// last element of the `LinkedList` then this will move it to the
    /// null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(cursor) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().next(cursor) };
        } else {
            self.current = self.list.head;
        }
    }

    /// Moves the cursor to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(cursor) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().prev(cursor) };
        } else {
            self.current = self.list.tail;
        }
    }

    ///Returns a cursor pointing to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `LinkedList`. If it is pointing to the last
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.as_cursor();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.as_cursor();
        prev.move_prev();
        prev
    }

    /// Removes the current element from the `LinkedList`.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// moved to point to the next element in the `LinkedList`.
    ///
    /// If the cursor is currently pointing to the null object then no element
    /// is removed and `None` is returned.
    #[inline]
    pub fn remove(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        let cursor = self.current?;

        unsafe {
            if self.list.adapter.link_ops().prev(cursor).is_none() {
                self.list.head = self.list.adapter.link_ops().next(cursor);
            }

            if self.list.adapter.link_ops().next(cursor).is_none() {
                self.list.tail = self.list.adapter.link_ops().prev(cursor);
            }

            let next = self.list.adapter.link_ops().next(cursor);
            let raw_pointer = self.list.adapter.get_value(cursor);

            remove(self.list.adapter.link_ops_mut(), cursor);

            self.current = next;
            Some(self.list.adapter.pointer_ops().from_raw(raw_pointer))
        }
    }

    /// Removes the current element from the `LinkedList` and inserts another
    /// object in its place.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// modified to point to the newly added element.
    ///
    /// If the cursor is currently pointing to the null object then an error is
    /// returned containing the given `val` parameter.
    ///
    /// Return err if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn replace_with(
        &mut self,
        val: <A::PointerOps as PointerOps>::Pointer,
    ) -> Result<<A::PointerOps as PointerOps>::Pointer, <A::PointerOps as PointerOps>::Pointer>
    {
        if let Some(cursor) = self.current {
            let new = self.list.node_from_value(val).ok_or(val)?;

            if self.current == self.list.head {
                self.list.head = Some(new);
            }
            if self.current == self.list.tail {
                self.list.tail = Some(new);
            }
            unsafe {
                let raw_pointer = self.list.adapter.get_value(cursor);
                replace_with(self.list.adapter.link_ops_mut(), cursor, new);
                self.current = Some(new);
                Ok(self.list.adapter.pointer_ops().from_raw(raw_pointer))
            }
        } else {
            Err(val)
        }
    }

    /*
    /// Inserts a new element into the `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the front of the `LinkedList`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_after(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
    }

    /// Inserts a new element into the `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the end of the `LinkedList`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_before(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
    }

    /// Inserts the elements from the given `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the start of the `LinkedList`.
    #[inline]
    pub fn splice_after(&mut self, mut list: LinkedList<A>) {
    }

    /// Moves all element from the given `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the end of the `LinkedList`.
    #[inline]
    pub fn splice_before(&mut self, mut list: LinkedList<A>) {
    }

    /// Splits the list into two after the current element. This will return a
    /// new list consisting of everything after the cursor, with the original
    /// list retaining everything before.
    ///
    /// If the cursor is pointing at the null object then the entire contents
    /// of the `LinkedList` are moved.
    #[inline]
    pub fn split_after(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
    }

    /// Splits the list into two before the current element. This will return a
    /// new list consisting of everything before the cursor, with the original
    /// list retaining everything after.
    ///
    /// If the cursor is pointing at the null object then the entire contents
    /// of the `LinkedList` are moved.
    #[inline]
    pub fn split_before(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
    }

    /// Consumes `CursorMut` and returns a reference to the object that
    /// the cursor is currently pointing to. Unlike [get](Self::get),
    /// the returned reference's lifetime is tied to `LinkedList`'s lifetime.
    ///
    /// This returns None if the cursor is currently pointing to the null object.
    #[inline]
    pub fn into_ref(self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
    }
    */
}

pub struct LinkedList<A: Adapter>
where
    A::LinkOps: LinkedListOps
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    adapter: A,
}

impl<A: Adapter> LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn node_from_value(
        &mut self,
        val: <A::PointerOps as PointerOps>::Pointer,
    ) -> Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr> {
        use link_ops::LinkOps;

        unsafe {
            let raw = self.adapter.pointer_ops().into_raw(val);
            let link = self.adapter.get_link(raw);

            if !self.adapter.link_ops_mut().acquire_link(link) {
                // convert the node back into a pointer
                self.adapter.pointer_ops().from_raw(raw);

                //panic!("attempted to insert an object that is already linked");
                return None;
            }

            Some(link)
        }
    }
}
