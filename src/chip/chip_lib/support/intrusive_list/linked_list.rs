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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    ) -> Result<<A::PointerOps as PointerOps>::Pointer, Option<<A::PointerOps as PointerOps>::Pointer>>
    {
        if let Some(cursor) = self.current {
            let new = self.list.node_from_value(val).ok_or(None)?;

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
            Err(Some(val))
        }
    }

    /// Inserts a new element into the `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the front of the `LinkedList`.
    ///
    ///
    /// Return error if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_after(&mut self, val: <A::PointerOps as PointerOps>::Pointer) -> Result<(), ()> {
        unsafe {
            let new = self.list.node_from_value(val).ok_or(())?;
            
            if let Some(cursor) = self.current {
                link_after(self.list.adapter.link_ops_mut(), new, cursor);
            } else {
                link_between(self.list.adapter.link_ops_mut(), new, None, self.list.head);
                self.list.head = Some(new);
            }

            if self.current == self.list.tail {
                self.list.tail = Some(new);
            }
        }

        Ok(())
    }

    /// Inserts a new element into the `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the end of the `LinkedList`.
    ///
    ///
    /// Return error if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_before(&mut self, val: <A::PointerOps as PointerOps>::Pointer) -> Result<(), ()> {
        unsafe {
            let new = self.list.node_from_value(val).ok_or(())?;
            
            if let Some(cursor) = self.current {
                link_before(self.list.adapter.link_ops_mut(), new, cursor);
            } else {
                link_between(self.list.adapter.link_ops_mut(), new, self.list.tail, None);
                self.list.tail = Some(new);
            }

            if self.current == self.list.head {
                self.list.head = Some(new);
            }
        }

        Ok(())
    }

    /// Inserts the elements from the given `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the start of the `LinkedList`.
    #[inline]
    pub fn splice_after(&mut self, mut list: LinkedList<A>) {
        if !list.is_empty() {
            unsafe {
                let head = list.head.unwrap_unchecked();
                let tail = list.tail.unwrap_unchecked();

                if let Some(cursor) = self.current {
                    let next = self.list.adapter.link_ops().next(cursor);
                    splice(self.list.adapter.link_ops_mut(), head, tail, Some(cursor), next);
                } else {
                    splice(self.list.adapter.link_ops_mut(), head, tail, None, self.list.head);
                    self.list.head = list.head;
                }
                if self.current == self.list.tail {
                    self.list.tail = list.tail;
                }
                list.head = None;
                list.tail = None;
            }
        }
    }

    /// Moves all element from the given `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the end of the `LinkedList`.
    #[inline]
    pub fn splice_before(&mut self, mut list: LinkedList<A>) {
        if !list.is_empty() {
            unsafe {
                let head = list.head.unwrap_unchecked();
                let tail = list.tail.unwrap_unchecked();

                if let Some(cursor) = self.current {
                    let prev = self.list.adapter.link_ops().prev(cursor);
                    splice(self.list.adapter.link_ops_mut(), head, tail, prev, Some(cursor));
                } else {
                    splice(self.list.adapter.link_ops_mut(), head, tail, self.list.tail, None);
                    self.list.tail = list.tail;
                }
                if self.current == self.list.head {
                    self.list.head = list.head;
                }
                list.head = None;
                list.tail = None;
            }
        }
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
        if let Some(cursor) = self.current {
            unsafe {
                let mut list = LinkedList {
                    head: self.list.adapter.link_ops().next(cursor),
                    tail: self.list.tail,
                    adapter: self.list.adapter.clone(),
                };
                if let Some(head) = list.head {
                    self.list.adapter.link_ops_mut().set_prev(head, None);
                } else {
                    list.tail = None;
                }
                self.list.adapter.link_ops_mut().set_next(cursor, None);
                self.list.tail = self.current;

                list
            }
        } else {
            let new_list = LinkedList {
                head: self.list.head,
                tail: self.list.tail,
                adapter: self.list.adapter.clone(),
            };
            self.list.head = None;
            self.list.tail = None;
            return new_list;
        }
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
        if let Some(cursor) = self.current {
            unsafe {
                let mut list = LinkedList {
                    head: self.list.head,
                    tail: self.list.adapter.link_ops().prev(cursor),
                    adapter: self.list.adapter.clone(),
                };
                if let Some(tail) = list.tail {
                    self.list.adapter.link_ops_mut().set_next(tail, None);
                } else {
                    list.head = None;
                }
                self.list.adapter.link_ops_mut().set_prev(cursor, None);
                self.list.head = self.current;

                list
            }
        } else {
            let new_list = LinkedList {
                head: self.list.head,
                tail: self.list.tail,
                adapter: self.list.adapter.clone(),
            };
            self.list.head = None;
            self.list.tail = None;
            return new_list;
        }
    }

    /// Consumes `CursorMut` and returns a reference to the object that
    /// the cursor is currently pointing to. Unlike [get](Self::get),
    /// the returned reference's lifetime is tied to `LinkedList`'s lifetime.
    ///
    /// This returns None if the cursor is currently pointing to the null object.
    #[inline]
    pub fn into_ref(self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.list.adapter.get_value(self.current?) })
    }
}

pub struct LinkedList<A: Adapter>
where
    A::LinkOps: LinkedListOps
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    adapter: A,
}

#[allow(dead_code)]
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

    /// Creates an empty `LinkedList`.
    //#[cfg(not(feature = "nightly"))]
    #[inline]
    pub const fn new(adapter: A) -> LinkedList<A> {
        LinkedList {
            head: None,
            tail: None,
            adapter,
        }
    }

    /// Creates an empty `LinkedList`.
    /*
    #[cfg(feature = "nightly")]
    #[inline]
    pub const fn new(adapter: A) -> LinkedList<A> {
        LinkedList {
            head: None,
            tail: None,
            adapter,
        }
    }
    */

    /// Returns `true` if the `LinkedList` is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Returns a null `Cursor` for this list.
    #[inline]
    pub fn cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: None,
            list: self,
        }
    }

    /// Returns a null `CursorMut` for this list.
    #[inline]
    pub fn cursor_mut(&mut self) -> CursorMut<'_, A> {
        CursorMut {
            current: None,
            list: self,
        }
    }

    /// Creates a `Cursor` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this list.
    #[inline]
    pub unsafe fn cursor_from_ptr(
        &self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> Cursor<'_, A> {
        Cursor {
            current: Some(self.adapter.get_link(ptr)),
            list: self,
        }
    }

    /// Creates a `CursorMut` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this list.
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        &mut self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> CursorMut<'_, A> {
        CursorMut {
            current: Some(self.adapter.get_link(ptr)),
            list: self,
        }
    }

    /// Returns a `Cursor` pointing to the first element of the list. If the
    /// list is empty then a null cursor is returned.
    #[inline]
    pub fn front(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_next();
        cursor
    }

    /// Returns a `CursorMut` pointing to the first element of the list. If the
    /// the list is empty then a null cursor is returned.
    #[inline]
    pub fn front_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_next();
        cursor
    }

    /// Returns a `Cursor` pointing to the last element of the list. If the list
    /// is empty then a null cursor is returned.
    #[inline]
    pub fn back(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_prev();
        cursor
    }

    /// Returns a `CursorMut` pointing to the last element of the list. If the
    /// list is empty then a null cursor is returned.
    #[inline]
    pub fn back_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_prev();
        cursor
    }

    /// Removes all elements from the `LinkedList`.
    ///
    /// This will unlink all object currently in the list, which requires
    /// iterating through all elements in the `LinkedList`. Each element is
    /// converted back to an owned pointer and then dropped.
    #[inline]
    pub fn clear(&mut self) {
        use link_ops::LinkOps;

        let mut current = self.head;
        self.head = None;
        self.tail = None;
        while let Some(x) = current {
            unsafe {
                let next = self.adapter.link_ops().next(x);
                self.adapter.link_ops_mut().release_link(x);
                self.adapter
                    .pointer_ops()
                    .from_raw(self.adapter.get_value(x));
                current = next;
            }
        }
    }

    /// Empties the `LinkedList` without unlinking or freeing objects in it.
    ///
    /// Since this does not unlink any objects, any attempts to link these
    /// objects into another `LinkedList` will fail but will not cause any
    /// memory unsafety. To unlink those objects manually, you must call the
    /// `force_unlink` function on them.
    #[inline]
    pub fn fast_clear(&mut self) {
        self.head = None;
        self.tail = None;
    }

    /// Takes all the elements out of the `LinkedList`, leaving it empty.
    /// The taken elements are returned as a new `LinkedList`.
    #[inline]
    pub fn take(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
        let list = LinkedList {
            head: self.head,
            tail: self.tail,
            adapter: self.adapter.clone(),
        };
        self.head = None;
        self.tail = None;
        list
    }

    /// Inserts a new element at the start of the `LinkedList`.
    #[inline]
    pub fn push_front(&mut self, val: <A::PointerOps as PointerOps>::Pointer) -> Result<(), ()> {
        self.cursor_mut().insert_after(val)
    }

    /// Inserts a new element at the end of the `LinkedList`.
    #[inline]
    pub fn push_back(&mut self, val: <A::PointerOps as PointerOps>::Pointer) -> Result<(), ()> {
        self.cursor_mut().insert_before(val)
    }

    /// Removes the first element of the `LinkedList`.
    ///
    /// This returns `None` if the `LinkedList` is empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.front_mut().remove()
    }

    /// Removes the last element of the `LinkedList`.
    ///
    /// This returns `None` if the `LinkedList` is empty.
    #[inline]
    pub fn pop_back(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.back_mut().remove()
    }
}

// Drop all owned pointers if the collection is dropped
impl<A: Adapter> Drop for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn drop(&mut self) {
        self.clear();
    }
}

impl<A: Adapter + Default> Default for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    fn default() -> LinkedList<A> {
        LinkedList::new(A::default())
    }
}

#[cfg(test)]
mod tests {
    use crate::create_object_pool;
    use crate::chip::chip_lib::support::{
        intrusive_list::{
            adapter::{
                self,
                linked_list::rc::DefaultAdapter,
            },
            unsafe_ref::UnsafeRef,
        },
        internal::pool::Statistics,
        pool::{ObjectPool, KInline, BitMapObjectPool},
    };
    use crate::chip::chip_lib::core::reference_counted::rc::{RcInner, Rc};
    use super::*;
    use core::ptr;

    const POOL_SIZE: usize = 10;
    type TestRcInner = RcInner<TestNode>;
    type TestPool = BitMapObjectPool<TestRcInner, POOL_SIZE>;
    type TestAlloc = TestPool;

    struct TestNode {
        pub link: Link,
        pub value: u8,
    }

    impl TestNode {
        pub fn new_with(value: u8) -> Self {
            Self {
                link: Link::new(),
                value,
            }
        }
    }

    type TestRc = Rc<TestNode, TestPool>;
    type TestLinkedList = LinkedList<DefaultAdapter<TestNode, TestPool>>;

    fn make_node(value: u8, pool: * mut TestPool) -> TestRc {
        TestRc::try_new_in(TestNode::new_with(value), pool).unwrap()
    }

    #[test]
    fn new_linked_list() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        assert!(linked_list.is_empty());
    }

    #[test]
    fn linked_list_push_front_one_node_and_pop() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        assert!(linked_list.front().get().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_front().is_none());
    }

    #[test]
    fn linked_list_push_front_two_node_and_pop() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        assert!(linked_list.front().get().is_some_and(|v| v.value == 1));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        assert!(linked_list.front().get().is_some_and(|v| v.value == 2));
        assert!(linked_list.back().get().is_some_and(|v| v.value == 1));

        // pop
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 2));
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_front().is_none());
    }

    #[test]
    fn linked_list_push_back_one_node_and_pop() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        assert!(linked_list.back().get().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_back().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_back().is_none());
    }

    #[test]
    fn linked_list_push_back_two_node_and_pop() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        assert!(linked_list.back().get().is_some_and(|v| v.value == 1));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        assert!(linked_list.back().get().is_some_and(|v| v.value == 2));
        assert!(linked_list.front().get().is_some_and(|v| v.value == 1));

        // pop
        assert!(linked_list.pop_back().is_some_and(|v| v.value == 2));
        assert!(linked_list.pop_back().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_back().is_none());
    }

    #[test]
    fn linked_list_push_front_two_node_and_push_back_and_pop() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        assert!(linked_list.front().get().is_some_and(|v| v.value == 1));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        assert!(linked_list.front().get().is_some_and(|v| v.value == 2));
        assert!(linked_list.back().get().is_some_and(|v| v.value == 1));

        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        assert!(linked_list.back().get().is_some_and(|v| v.value == 3));

        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        assert!(linked_list.back().get().is_some_and(|v| v.value == 4));

        // pop
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 2));
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 1));
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 3));
        assert!(linked_list.pop_front().is_some_and(|v| v.value == 4));
        assert!(linked_list.pop_front().is_none());
    }

    #[test]
    fn linked_list_clear() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());

        assert!(!linked_list.is_empty());

        linked_list.clear();

        assert!(linked_list.is_empty());
    }

    #[test]
    fn linked_list_take_and_no_use() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());

        let list_2 = linked_list.take();
        
        assert!(linked_list.is_empty());
        assert!(!list_2.is_empty());
    }

    #[test]
    fn clone_pointer() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());

        // check the cloned value
        assert!(linked_list.front().clone_pointer().is_some_and(|p| p.value == 1));
        // chech the original value
        assert!(linked_list.front().get().is_some_and(|p| p.value == 1));
    }

    #[test]
    fn move_next_prev() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_front(node).is_ok());

        let mut c = linked_list.front();
        c.move_next();
        assert!(c.get().is_some_and(|p| p.value == 1));
        assert!(c.peek_prev().get().is_some_and(|p| p.value == 2));
        c.move_prev();
        assert!(c.get().is_some_and(|p| p.value == 2));
        assert!(c.peek_next().get().is_some_and(|p| p.value == 1));

        // go to null
        c.move_prev();
        assert!(c.is_null());

        // go back to tail
        c.move_prev();
        assert!(c.get().is_some_and(|p| p.value == 1));

        // go to null
        c.move_next();
        assert!(c.is_null());

        // go to head
        c.move_next();
        assert!(c.get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn remove_middle_node() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_next();
        assert!(c.get().is_some_and(|p| p.value == 2));
        let middle = c.remove();
        assert!(middle.is_some_and(|p| p.value == 2));
        assert!(c.get().is_some_and(|p| p.value == 3));
        let prev = c.peek_prev();
        assert!(prev.get().is_some_and(|p| p.value == 1));
    }

    #[test]
    fn remove_all() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        assert!(c.remove().is_some_and(|p| p.value == 1));
        assert!(c.remove().is_some_and(|p| p.value == 2));
        assert!(c.remove().is_some_and(|p| p.value == 3));
        assert!(c.remove().is_none());
    }

    #[test]
    fn replace_front() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.replace_with(node).is_ok_and(|p| p.value == 1));
        assert!(c.get().is_some_and(|p| p.value == 4));
        assert!(c.peek_next().get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn replace_back() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.back_mut();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.replace_with(node).is_ok_and(|p| p.value == 3));
        assert!(c.get().is_some_and(|p| p.value == 4));
        assert!(c.peek_next().is_null());
    }

    #[test]
    fn replace_middle() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_next();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.replace_with(node).is_ok_and(|p| p.value == 2));
        assert!(c.get().is_some_and(|p| p.value == 4));
        assert!(c.peek_next().get().is_some_and(|p| p.value == 3));
    }

    #[test]
    fn replace_empty() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_prev();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.replace_with(node).is_err_and(|e| e.is_some_and(|p| p.value == 4)));
    }

    #[test]
    fn replace_failed() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        let node_copy = node.clone();
        assert!(linked_list.push_back(node).is_ok());

        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let mut c = linked_list_1.front_mut();
        assert!(c.replace_with(node_copy).is_err_and(|e| e.is_none()));
    }

    #[test]
    fn insert_after_middle() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_next();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.insert_after(node).is_ok());
        assert!(c.get().is_some_and(|p| p.value == 2));
        c.move_next();
        assert!(c.get().is_some_and(|p| p.value == 4));
        assert!(c.peek_next().get().is_some_and(|p| p.value == 3));
    }

    #[test]
    fn insert_after_null() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_prev();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.insert_after(node).is_ok());
        let cc = linked_list.front();
        assert!(cc.get().is_some_and(|p| p.value == 4));
        assert!(cc.peek_next().get().is_some_and(|p| p.value == 1));
    }

    #[test]
    fn insert_before_middle() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_next();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.insert_before(node).is_ok());
        assert!(c.get().is_some_and(|p| p.value == 2));
        c.move_prev();
        assert!(c.get().is_some_and(|p| p.value == 4));
        assert!(c.peek_next().get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn insert_before_null() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list.push_back(node).is_ok());

        let mut c = linked_list.front_mut();
        c.move_prev();
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(c.insert_before(node).is_ok());
        let cc = linked_list.back();
        assert!(cc.get().is_some_and(|p| p.value == 4));
        assert!(cc.peek_prev().get().is_some_and(|p| p.value == 3));
    }

    #[test]
    fn splice_after_front() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut linked_list_2 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();

        c1.splice_after(linked_list_2);
        c1.move_next();
        assert!(c1.get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn splice_after_middle() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut linked_list_2 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());
        let node = make_node(5, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        c1.move_next();

        c1.splice_after(linked_list_2);
        assert!(c1.get().is_some_and(|p| p.value == 2));
        c1.move_next();
        assert!(c1.get().is_some_and(|p| p.value == 4));
    }

    #[test]
    fn splice_before_front() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut linked_list_2 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();

        c1.splice_before(linked_list_2);
        let c1 = linked_list_1.front_mut();

        assert!(c1.get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn splice_before_middle() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut linked_list_2 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(4, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());
        let node = make_node(5, ptr::addr_of_mut!(pool));
        assert!(linked_list_2.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        c1.move_next();

        c1.splice_before(linked_list_2);
        assert!(c1.get().is_some_and(|p| p.value == 2));
        c1.move_prev();
        assert!(c1.get().is_some_and(|p| p.value == 5));
    }

    #[test]
    fn split_after() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        let linked_list_2 = c1.split_after();
        assert!(c1.get().is_some_and(|p| p.value == 1));
        assert!(linked_list_2.front().get().is_some_and(|p| p.value == 2));
    }

    #[test]
    fn split_single_node() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        let linked_list_2 = c1.split_after();
        assert!(c1.get().is_some_and(|p| p.value == 1));
        assert!(linked_list_2.is_empty());
    }

    #[test]
    fn split_single_node_null() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        c1.move_next();
        let linked_list_2 = c1.split_after();
        assert!(linked_list_2.front().get().is_some_and(|p| p.value == 1));
        assert!(linked_list_1.is_empty());
    }

    #[test]
    fn split_before() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(2, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());
        let node = make_node(3, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.back_mut();
        let linked_list_2 = c1.split_before();
        assert!(c1.get().is_some_and(|p| p.value == 3));
        assert!(linked_list_2.front().get().is_some_and(|p| p.value == 1));
    }

    #[test]
    fn split_before_single_node() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        let linked_list_2 = c1.split_before();
        assert!(c1.get().is_some_and(|p| p.value == 1));
        assert!(linked_list_2.is_empty());
    }

    #[test]
    fn split_before_single_node_null() {
        let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
        let mut linked_list_1 = TestLinkedList::new(DefaultAdapter::new_in(ptr::addr_of_mut!(pool)));
        let node = make_node(1, ptr::addr_of_mut!(pool));
        assert!(linked_list_1.push_back(node).is_ok());

        let mut c1 = linked_list_1.front_mut();
        c1.move_next();
        let linked_list_2 = c1.split_before();
        assert!(linked_list_2.front().get().is_some_and(|p| p.value == 1));
        assert!(linked_list_1.is_empty());
    }

    #[test]
    fn linked_list_push_front_one_node_and_pop_unsafe_ref() {
        //type UnsafeRefTestLinkedList = LinkedList<DefaultAdapter<TestNode, TestPool>>;
        type UnsafeRefTestLinkedList = LinkedList<adapter::linked_list::unsafe_ref::DefaultAdapter<TestNode>>;
        let mut pool = create_object_pool!(TestNode, POOL_SIZE);
        let mut linked_list = UnsafeRefTestLinkedList::new(adapter::linked_list::unsafe_ref::DefaultAdapter::new());
        unsafe {
            let node = UnsafeRef::from_raw(pool.allocate(TestNode::new_with(1)));
            assert!(linked_list.push_front(node).is_ok());
            assert!(linked_list.front().get().is_some_and(|v| v.value == 1));
            assert!(linked_list.pop_front().is_some_and(|v| v.value == 1));
            assert!(linked_list.pop_front().is_none());
        }
    }
} // end of tests
