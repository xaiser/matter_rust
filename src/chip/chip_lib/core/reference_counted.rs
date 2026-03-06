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
    use core::ptr::{self, NonNull};
    use core::marker::PhantomData;
    use core::cell::Cell;

    pub struct Weak<T> {
        ptr: NonNull<RcInner<T>>,
    }

    #[repr(C, align(2))]
    struct RcInner<T> {
        strong: Cell<usize>,
        weak: Cell<usize>,
        value: T,
    }

    pub struct Rc<T> {
        ptr: NonNull<RcInner<T>>,
        _phantom: PhantomData<Cell<RcInner<T>>>,
    }

    impl<T> Rc<T> {
        #[inline]
        unsafe fn from_inner(ptr: NonNull<RcInner<T>>) -> Self {
            Self { ptr, _phantom: PhantomData }
        }

        #[inline]
        unsafe fn from_ptr(ptr: * mut RcInner<T>) -> Self {
            Self { ptr: NonNull::new_unchecked(ptr), _phantom: PhantomData }
        }

        #[inline(never)]
        unsafe fn drop_slow(&mut self) {
            let _weak = Weak {ptr: self.ptr};

            unsafe {
                ptr::drop_in_place(&mut (*self.ptr.as_ptr()).value);
            }
        }

        pub fn new(value: T) -> Rc<T> {
            unsafe {
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
