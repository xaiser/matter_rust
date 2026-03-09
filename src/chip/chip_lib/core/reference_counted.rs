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

    pub struct Weak<T> {
        ptr: NonNull<RcInner<T>>,
    }

    impl<T> Weak<T> {
        pub const fn new() -> Weak<T> {
            Weak { ptr: NonNull::without_provenance(NonZeroUsize::MAX) }
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
            <D as Deleter<T>>::release(self.ptr.as_mut())
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

        pub fn downgrade(this: &Self) -> Weak<T> {
            this.inner().inc_weak();

            Weak{ ptr: this.ptr }
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
