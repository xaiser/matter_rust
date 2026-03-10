use crate::verify_or_die;

pub trait RCDeleteDeletor<SubType> {
    fn release(obj: *mut SubType);
}

pub trait ReferenceCountered<SubType, Deletor>
where
    //Deletor: FnOnce(* mut SubType) -> () + FnMut(* mut SubType) -> (),
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

mod v1 {
    /* a version copied from std::alloc::rc with a Deleter */
    use crate::chip::{
        chip_lib::support::pool::{KInline, ObjectPool},
    };
    use core::ptr::{self, NonNull};
    use core::marker::PhantomData;
    use core::cell::Cell;
    use core::num::NonZeroUsize;
    use core::ops::Deref;

    pub trait Deleter<T> {
        fn release(obj: &mut RcInner<T>);
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

    pub struct Weak<T, D: Deleter<T>> {
        ptr: NonNull<RcInner<T>>,
        _phantomD: PhantomData<D>,
    }

    impl<T, D: Deleter<T>> Weak<T, D> {
        pub const fn new() -> Weak<T, D> {
            Weak { ptr: NonNull::without_provenance(NonZeroUsize::MAX), _phantomD: PhantomData }
        }

        pub fn as_ptr(&self) -> * const T {
            let ptr: * mut RcInner<T> = NonNull::as_ptr(self.ptr);

            if is_dangling(ptr) {
                ptr as * const T
            } else {
                unsafe { &raw mut (*ptr).value }
            }
        }

        pub fn upgrade(&self) -> Option<Rc<T, D>> {
            let inner = self.inner()?;

            if inner.strong() == 0 {
                None
            } else {
                unsafe {
                    inner.inc_strong();
                    Some(Rc::from_inner(self.ptr))
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

    impl<T, D: Deleter<T>> Drop for Weak<T, D> {
        fn drop(&mut self) {
            let inner = if let Some(inner) = self.inner() { inner } else { return };

            inner.dec_weak();

            if inner.weak() == 0 {
                unsafe {
                    <D as Deleter<T>>::release(self.ptr.as_mut());
                }
            }
        }
    }

    impl<T, D: Deleter<T>> Clone for Weak<T, D> {
        fn clone(&self) -> Self {
            if let Some(inner) = self.inner() {
                inner.inc_weak()
            }

            Weak { ptr: self.ptr, _phantomD: PhantomData }
        }
    }

    impl<T, D: Deleter<T>> Default for Weak<T, D> {
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
    struct RcInner<T> {
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

    pub struct Rc<T, D: Deleter<T>> {
        ptr: NonNull<RcInner<T>>,
        _phantom: PhantomData<Cell<RcInner<T>>>,
        _phantomD: PhantomData<D>,
    }

    impl<T, D: Deleter<T>> Rc<T, D> {
        #[inline]
        unsafe fn from_inner(ptr: NonNull<RcInner<T>>) -> Self {
            Self { ptr, _phantom: PhantomData, _phantomD: PhantomData }
        }

        #[inline]
        unsafe fn from_ptr(ptr: * mut RcInner<T>) -> Self {
            Self { ptr: NonNull::new_unchecked(ptr), _phantom: PhantomData, _phantomD: PhantomData }
        }

        #[inline(always)]
        fn inner(&self) -> &RcInner<T> {
            unsafe { self.ptr.as_ref() }
        }

        #[inline(never)]
        unsafe fn drop_slow(&mut self) {
            let _weak = Weak { ptr: self.ptr, _phantomD: PhantomData::<D> };

            unsafe {
                ptr::drop_in_place(&mut (*self.ptr.as_ptr()).value);
            }
        }

        pub fn new_from_object_pool<M, A: ObjectPool<RcInner<T>, M>>(value: T, alloac: &mut A) -> Rc<T, D> {
            let obj = alloac.create_object(RcInner {strong: Cell::new(1), weak: Cell::new(1), value});
            unsafe {
                Self::from_ptr(obj)
            }
        }

        pub fn try_new_from_object_pool<M, A: ObjectPool<RcInner<T>, M>>(value: T, alloac: &mut A) -> Result<Rc<T, D>, ()> {
            let obj = alloac.create_object(RcInner {strong: Cell::new(1), weak: Cell::new(1), value});

            if obj.is_null() {
                return Err(());
            }

            unsafe {
                Ok(Self::from_ptr(obj))
            }
        }

        pub fn as_ptr(this: &Self) -> * const T {
            let ptr: * mut RcInner<T> = NonNull::as_ptr(this.ptr);

            unsafe { &raw mut (*ptr).value }
        }

        pub fn downgrade(this: &Self) -> Weak<T, D> {
            this.inner().inc_weak();

            Weak{ ptr: this.ptr, _phantomD: PhantomData }
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

    impl<T, D: Deleter<T>> Deref for Rc<T, D> {
        type Target = T;

        #[inline(always)]
        fn deref(&self) -> &T {
            &self.inner().value
        }
    }

    impl<T, D: Deleter<T>> Drop for Rc<T, D> {
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

    impl<T, D: Deleter<T>> Clone for Rc<T, D> {
        #[inline]
        fn clone(&self) -> Self {
            unsafe {
                self.inner().inc_strong();
                Self::from_inner(self.ptr)
            }
        }
    }

    impl<T, D: Deleter<T>> AsRef<T> for Rc<T, D> {
        fn as_ref(&self) -> &T {
            &**self
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::create_object_pool;
        use crate::chip::chip_lib::support::pool::{ObjectPool, KInline, BitMapObjectPool};
        use super::*;

        struct StubDeleter {
        }

        struct StubElement {
            pub pool: * mut TestPool,
            pub value: u8,
        }

        impl StubElement {
            pub fn new(value: u8, pool: * mut TestPool) -> Self {
                Self {
                    pool,
                    value
                }
            }
        }

        impl Deleter<StubElement> for StubDeleter { 
            fn release(obj: &mut RcInner<StubElement>) { 
                unsafe {
                    if let Some(pool) = obj.get_mut_unchecked().pool.as_mut() {
                        pool.release_object(obj);
                    }
                }
            }
        }

        const POOL_SIZE: usize = 1;

        type TestRcInner = RcInner<StubElement>;
        type TestRc = Rc<StubElement, StubDeleter>;
        type TestPool = BitMapObjectPool<TestRcInner, POOL_SIZE>;

        #[test]
        fn new_rc_successfully() {
            let mut pool = create_object_pool!(TestRcInner, POOL_SIZE);
            assert!(TestRc::try_new_from_object_pool::<KInline, TestPool>(StubElement::new(0, ptr::addr_of_mut!(pool)), &mut pool).is_ok());
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
