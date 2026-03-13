use crate::verify_or_die;

pub trait RCDeleteDeletor<SubType> {
    fn release(obj: *mut SubType);
}

pub trait ReferenceCountered<SubType, Deletor>
where
    Deletor: RCDeleteDeletor<SubType>,
{
    type CounterType;

    fn retain(&mut self) -> *mut SubType
    where
        <Self as ReferenceCountered<SubType, Deletor>>::CounterType: PartialOrd<i32>,
    {
        verify_or_die!(self.get_reference_count() > 0);
        //verify_or_die!(self.get_reference_count() < Self::CounterType::MAX);
        let _ = self.increase();

        return self as *mut Self as *mut SubType;
    }

    fn release(&mut self)
    where
        <Self as ReferenceCountered<SubType, Deletor>>::CounterType: PartialOrd<i32>,
    {
        verify_or_die!(self.get_reference_count() != 0);
        if self.decrease() == 0 {
            Deletor::release(self as *mut Self as *mut SubType);
        }
    }

    fn increase(&mut self) -> Self::CounterType;

    fn decrease(&mut self) -> Self::CounterType;

    fn get_reference_count(&self) -> Self::CounterType;
}

pub mod rc {
    /* a version copied from std::alloc::rc with a Deleter */
    use core::ptr::{self, NonNull};
    use core::marker::PhantomData;
    use core::cell::Cell;
    use core::num::NonZeroUsize;
    use core::ops::Deref;

    pub trait Allocator<T> {
        fn allocate(&mut self, init_value: RcInner<T>) -> Result<* mut RcInner<T>, ()>;

        fn deallocate(&mut self, obj: &mut RcInner<T>);
    }

    trait RcInnerPtr {
        fn weak_ref(&self) -> &Cell<usize>;
        fn strong_ref(&self) -> &Cell<usize>;

        #[inline]
        fn strong(&self) -> usize {
            self.strong_ref().get()
        }

        #[inline]
        fn inc_strong(&self) {
            let strong = self.strong();

            let strong = strong.wrapping_add(1);
            self.strong_ref().set(strong);

            // TODO: maybe only run this in debug build
            if strong == 0 {
                panic!("rc inc strong wrong");
            }
        }

        #[inline]
        fn dec_strong(&self) {
            self.strong_ref().set(self.strong() - 1)
        }

        #[inline]
        fn weak(&self) -> usize {
            self.weak_ref().get()
        }

        #[inline]
        fn inc_weak(&self) {
            let weak = self.weak();

            let weak = weak.wrapping_add(1);
            self.weak_ref().set(weak);

            //TODO: maybe only run this in debug build
            if weak == 0 {
                panic!("rc inc weak wrong");
            }
        }

        #[inline]
        fn dec_weak(&self) {
            self.weak_ref().set(self.weak() - 1)
        }

    }

    pub struct Weak<T, A: Allocator<T>> {
        ptr: NonNull<RcInner<T>>,
        alloc: * mut A,
    }

    impl<T, A: Allocator<T>> Weak<T, A> {
        pub const fn new() -> Weak<T, A> {
            Weak { ptr: NonNull::without_provenance(NonZeroUsize::MAX), alloc: ptr::null_mut() }
        }

        pub fn as_ptr(&self) -> * const T {
            let ptr: * mut RcInner<T> = NonNull::as_ptr(self.ptr);

            if is_dangling(ptr) {
                ptr as * const T
            } else {
                unsafe { &raw mut (*ptr).value }
            }
        }

        pub fn upgrade(&self) -> Option<Rc<T, A>> {
            let inner = self.inner()?;

            if inner.strong() == 0 {
                None
            } else {
                unsafe {
                    inner.inc_strong();
                    Some(Rc::from_inner_in(self.ptr, self.alloc))
                }
            }
        }

        pub fn strong_count(&self) -> usize {
            if let Some(inner) = self.inner() { inner.strong() } else { 0 }
        }

        pub fn weak_count(&self) -> usize {
            if let Some(inner) = self.inner() { inner.weak() } else { 0 }
        }

        pub fn ptr_eq(&self, other: &Self) -> bool {
            ptr::addr_eq(self.ptr.as_ptr(), other.ptr.as_ptr())
        }

        #[inline]
        fn inner(&self) -> Option<WeakInner<'_>> {
            if is_dangling(self.ptr.as_ptr()) {
                None
            } else {
                Some( unsafe {
                    let ptr = self.ptr.as_ptr();
                    WeakInner { strong: &(*ptr).strong, weak: &(*ptr).weak }
                })
            }
        }
    }

    impl<T, A: Allocator<T>> Drop for Weak<T, A> {
        fn drop(&mut self) {
            let inner = if let Some(inner) = self.inner() { inner } else { return };

            inner.dec_weak();

            if inner.weak() == 0 {
                unsafe {
                    if let Some(a) = self.alloc.as_mut() {
                        a.deallocate(self.ptr.as_mut());
                    }
                }
            }
        }
    }

    impl<T, A: Allocator<T>> Clone for Weak<T, A> {
        fn clone(&self) -> Self {
            if let Some(inner) = self.inner() {
                inner.inc_weak()
            }

            Weak { ptr: self.ptr, alloc: self.alloc }
        }
    }

    impl<T, A: Allocator<T>> Default for Weak<T, A> {
        fn default() -> Self {
            Weak::new()
        }
    }


    pub(crate) fn is_dangling<T>(ptr: *const T) -> bool {
        (ptr.cast::<()>()).addr() == usize::MAX
    }

    struct WeakInner<'a> {
        weak: &'a Cell<usize>,
        strong: &'a Cell<usize>,
    }

    impl<'a> RcInnerPtr for WeakInner<'a> {
        #[inline(always)]
        fn weak_ref(&self) -> &Cell<usize> {
            self.weak
        }
        #[inline(always)]
        fn strong_ref(&self) -> &Cell<usize> {
            self.strong
        }
    }

    #[repr(C, align(2))]
    pub struct RcInner<T> {
        strong: Cell<usize>,
        weak: Cell<usize>,
        value: T,
    }

    impl<T> RcInnerPtr for RcInner<T> {
        #[inline(always)]
        fn weak_ref(&self) -> &Cell<usize> {
            &self.weak
        }
        #[inline(always)]
        fn strong_ref(&self) -> &Cell<usize> {
            &self.strong
        }
    }

    pub struct Rc<T, A: Allocator<T>> {
        ptr: NonNull<RcInner<T>>,
        alloc: * mut A,
        _phantom: PhantomData<Cell<RcInner<T>>>,
    }

    impl<T, A: Allocator<T>> Rc<T, A> {
        #[inline]
        unsafe fn from_inner_in(ptr: NonNull<RcInner<T>>, alloc: * mut A) -> Self {
            Self { ptr, alloc, _phantom: PhantomData}
        }

        #[inline]
        unsafe fn from_ptr_in(ptr: * mut RcInner<T>, alloc: * mut A) -> Self {
            Self { ptr: NonNull::new_unchecked(ptr), alloc, _phantom: PhantomData }
        }

        #[inline(always)]
        fn inner(&self) -> &RcInner<T> {
            unsafe { self.ptr.as_ref() }
        }

        #[inline(never)]
        unsafe fn drop_slow(&mut self) {
            let _weak = Weak { ptr: self.ptr, alloc: self.alloc };

            unsafe {
                ptr::drop_in_place(&mut (*self.ptr.as_ptr()).value);
            }
        }

        /*
        pub fn new_in(value: T, alloc: * mut A) -> Rc<T, A> {
           // currently, we dont' have a reliable way to handle the error
        }
        */

        pub fn try_new_in(value: T, alloc: * mut A) -> Result<Rc<T, A>, ()> {
            unsafe {
                if let Some(a) = alloc.as_mut() {
                    let obj = a.allocate(RcInner { strong: Cell::new(1), weak: Cell::new(1), value })?;
                        return Ok(Self::from_ptr_in(obj, alloc));
                }
            }
            Err(())
        }

        pub fn as_ptr(this: &Self) -> * const T {
            let ptr: * mut RcInner<T> = NonNull::as_ptr(this.ptr);

            unsafe { &raw mut (*ptr).value }
        }

        pub fn downgrade(this: &Self) -> Weak<T, A> {
            this.inner().inc_weak();

            Weak{ ptr: this.ptr, alloc: this.alloc }
        }

        pub fn weak_count(this: &Self) -> usize {
            this.inner().weak() - 1
        }

        pub fn strong_count(this: &Self) -> usize {
            this.inner().strong()
        }

        #[inline]
        pub fn is_unique(this: &Self) -> bool {
            Rc::weak_count(this) == 0 && Rc::strong_count(this) == 1
        }

        #[inline]
        pub fn get_mut(this: &mut Self) -> Option<&mut T> {
            if Rc::is_unique(this) { unsafe { Some(Rc::get_mut_unchecked(this)) } } else { None }
        }

        #[inline]
        pub unsafe fn get_mut_unchecked(this: &mut Self) -> &mut T {
            unsafe { &mut (*this.ptr.as_ptr()).value }
        }

        #[inline]
        pub fn ptr_eq(this: &Self, other: &Self) -> bool {
            ptr::addr_eq(this.ptr.as_ptr(), other.ptr.as_ptr())
        }
    }

    impl<T, A: Allocator<T>> Deref for Rc<T, A> {
        type Target = T;

        #[inline(always)]
        fn deref(&self) -> &T {
            &self.inner().value
        }
    }

    impl<T, A: Allocator<T>> Drop for Rc<T, A> {
        #[inline]
        fn drop(&mut self) {
            unsafe {
                self.inner().dec_strong();
                if self.inner().strong() == 0 {
                    self.drop_slow();
                }
            }
        }
    }

    impl<T, A: Allocator<T>> Clone for Rc<T, A> {
        #[inline]
        fn clone(&self) -> Self {
            unsafe {
                self.inner().inc_strong();
                Self::from_inner_in(self.ptr, self.alloc)
            }
        }
    }

    impl<T, A: Allocator<T>> AsRef<T> for Rc<T, A> {
        fn as_ref(&self) -> &T {
            &**self
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::create_object_pool;
        use crate::chip::chip_lib::support::{
            internal::pool::Statistics,
            pool::{ObjectPool, KInline, BitMapObjectPool},
        };
        use super::*;

        struct StubDeleter {
        }

        struct StubElement {
            pub value: u8,
        }

        impl StubElement {
            pub fn new(value: u8) -> Self {
                Self {
                    value
                }
            }
        }

        const POOL_SIZE: usize = 1;

        type TestRcInner = RcInner<StubElement>;
        type TestPool = BitMapObjectPool<TestRcInner, POOL_SIZE>;
        type TestRc = Rc<StubElement, TestPool>;
        type TestWeak = Weak<StubElement, TestPool>;

        #[test]
        fn new_rc_successfully() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(0), &mut pool);

            assert!(e.is_ok());
            let e = e.unwrap();

            assert_eq!(1, TestRc::strong_count(&e));
            assert_eq!(0, TestRc::weak_count(&e));
            assert!(TestRc::is_unique(&e));
        }

        #[test]
        fn rc_as_ptr() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();
            unsafe {
                assert_eq!((*TestRc::as_ptr(&e)).value, 1);
            }
        }

        #[test]
        fn get_mut() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let mut e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();
            unsafe {
                if let Some(the_e) = TestRc::get_mut(&mut e) {
                    assert_eq!(1, the_e.value);
                } else {
                    assert!(false);
                }
            }
        }

        #[test]
        fn rc_clone() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e1 = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();
            let e2 = e1.clone();

            assert!(TestRc::ptr_eq(&e1, &e2));
            assert_eq!(2, TestRc::strong_count(&e1));
            assert_eq!(2, TestRc::strong_count(&e2));
            assert_eq!(0, TestRc::weak_count(&e1));
            assert_eq!(0, TestRc::weak_count(&e2));
        }

        #[test]
        fn get_weak_scuccessfully() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();

            let we = TestRc::downgrade(&e);

            assert_eq!(1, TestRc::weak_count(&e));
            assert_eq!(1, TestRc::strong_count(&e));
            assert_eq!(2, TestWeak::weak_count(&we));
            assert_eq!(1, TestWeak::strong_count(&we));
        }

        #[test]
        fn weak_clone() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();

            let we1 = TestRc::downgrade(&e);
            let we2 = we1.clone();

            assert!(we1.ptr_eq(&we2));

            assert_eq!(2, TestRc::weak_count(&e));
            assert_eq!(1, TestRc::strong_count(&e));
            assert_eq!(3, TestWeak::weak_count(&we1));
            assert_eq!(1, TestWeak::strong_count(&we1));
            assert_eq!(3, TestWeak::weak_count(&we2));
            assert_eq!(1, TestWeak::strong_count(&we2));
        }

        #[test]
        fn weak_upgrade_successfully() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();

            let we = TestRc::downgrade(&e);

            if let Some(e2) = we.upgrade() {
                assert!(TestRc::ptr_eq(&e, &e2));
                assert_eq!(2, TestRc::strong_count(&e));
                assert_eq!(1, TestRc::weak_count(&e));
            } else {
                assert!(false);
            }
        }

        #[test]
        fn weak_existed_after_rc_drop() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();

            let we = TestRc::downgrade(&e);

            drop(e);

            assert_eq!(0, TestWeak::strong_count(&we));
            assert_eq!(1, TestWeak::weak_count(&we));
            assert!(we.upgrade().is_none());
        }

        #[test]
        fn drop_both_rc_weak_successfully() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            assert_eq!(0, pool.allocated());

            let e = TestRc::try_new_in(StubElement::new(1), &mut pool).unwrap();
            assert_eq!(1, pool.allocated());

            let we = TestRc::downgrade(&e);

            drop(e);

            assert_eq!(0, TestWeak::strong_count(&we));
            assert_eq!(1, TestWeak::weak_count(&we));
            assert!(we.upgrade().is_none());
            assert_eq!(1, pool.allocated());

            drop(we);

            assert_eq!(0, pool.allocated());
        }
    } // end of mod tests
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    type TheCountType = i32;

    struct TestSubType {
        pub m_count: TheCountType,
    }

    impl RCDeleteDeletor<TestSubType> for TestSubType {
        fn release(obj: *mut TestSubType) {
            unsafe {
                (*obj).m_count = 0;
            }
        }
    }

    impl ReferenceCountered<TestSubType, TestSubType> for TestSubType {
        type CounterType = TheCountType;
        fn increase(&mut self) -> Self::CounterType {
            self.m_count += 1;
            return self.m_count;
        }

        fn decrease(&mut self) -> Self::CounterType {
            self.m_count -= 1;
            return self.m_count;
        }

        fn get_reference_count(&self) -> Self::CounterType {
            return self.m_count;
        }
    }

    #[test]
    fn new_one() {
        let a: TestSubType = TestSubType { m_count: 1 };
        assert_eq!(1, a.m_count);
    }

    #[test]
    fn retain_one() {
        let mut a: TestSubType = TestSubType { m_count: 1 };
        let b = a.retain();

        unsafe {
            assert_eq!(2, (*b).m_count);
        }
    }

    #[test]
    fn retain_two() {
        let mut a: TestSubType = TestSubType { m_count: 1 };
        let _b = a.retain();
        let b = a.retain();

        unsafe {
            assert_eq!(3, (*b).m_count);
        }
    }

    #[test]
    #[should_panic]
    fn release_two() {
        let mut a: TestSubType = TestSubType { m_count: 1 };
        a.release();
        a.release();
    }

    #[test]
    fn retain_and_release() {
        let mut a: TestSubType = TestSubType { m_count: 1 };
        let b = a.retain();
        a.release();
        unsafe {
            assert_eq!(1, (*b).m_count);
        }
    }
}
