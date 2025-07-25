use super::internal::pool::StaticAllocatorBitMap;
use super::internal::pool::Statistics;
use super::internal::pool::K_BIT1;
use super::internal::pool::K_BIT_CHUNK_SIZE;
use super::iterators::Loop;
use crate::verify_or_die;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

pub struct KInline;
pub struct KHeap;

struct Data<ElementType, const N: usize> {
    pub m_memory: [MaybeUninit<ElementType>; N],
    // TODO: add a config to remove this on release build
    //pub m_memory_view_for_debug: [T; N],
}

//pub struct BitMapObjectPool<ElementType, const M: usize, const N: usize> {
pub struct BitMapObjectPool<ElementType, const N: usize>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]:,
{
    m_allocated: usize,
    m_high_water_mark: usize,
    m_capacity: usize,
    m_usage: [AtomicU32; (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE],
    //m_usage: [AtomicU32; M],
    m_data: Data<ElementType, N>,
}

pub trait ObjectPool<ElementType, Mem> {
    fn create_object(&mut self, init_value: ElementType) -> *mut ElementType;
    fn release_object(&mut self, element: *mut ElementType);
    fn releaes_all(&mut self);
    //fn for_each_active_object<F: FnOnce(*mut ElementType) -> Loop>(&mut self, f: F)
    fn for_each_active_object<F>(&mut self, f: F) -> Loop
    where
        F: FnOnce(*mut ElementType) -> Loop + FnMut(*mut ElementType) -> Loop;

    /*
    fn for_each_active_object_const<F>(&mut self, f: F)
        where
            F: Fn(*mut ElementType) -> Loop;
    */
}

impl<ElementType, const N: usize> StaticAllocatorBitMap for BitMapObjectPool<ElementType, N>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]:,
{
    fn capacity(&self) -> usize {
        self.m_capacity
    }
    fn exhausted(&self) -> bool {
        self.m_allocated == self.m_capacity
    }
}

impl<ElementType, const N: usize> Statistics for BitMapObjectPool<ElementType, N>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]:,
{
    fn allocated(&self) -> usize {
        self.m_allocated
    }

    fn high_water_mark(&self) -> usize {
        self.m_high_water_mark
    }

    fn increase_usage(&mut self) {
        self.m_allocated += 1;
        if self.m_allocated > self.m_high_water_mark {
            self.m_high_water_mark = self.m_allocated;
        }
    }

    fn decrease_usage(&mut self) {
        self.m_allocated -= 1;
    }
}

impl<ElementType, const N: usize> BitMapObjectPool<ElementType, N>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]:,
{
    pub const fn new() -> Self {
        let memory: [MaybeUninit<ElementType>; N] = [const { MaybeUninit::uninit() }; N];
        //let _usage: [AtomicU32; (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE];
        //let usage: [AtomicU32; M] = [const {AtomicU32::new(0) }; M];

        /*
        for u in &usage {
            u.store(0, Ordering::Relaxed);
        }
        */

        BitMapObjectPool {
            m_allocated: 0,
            m_high_water_mark: 0,
            m_capacity: N,
            //m_usage: usage,
            m_usage: [const { AtomicU32::new(0) }; (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE],
            m_data: Data { m_memory: memory },
        }
    }

    pub fn index_of(&self, element: *mut ElementType) -> usize {
        let first_element = self.m_data.m_memory[0].as_ptr();
        let diff = unsafe { element.offset_from(first_element) };
        verify_or_die!(diff >= 0);
        let diff = diff as usize;
        //verify_or_die!(diff % mem::size_of::<ElementType>() == 0);
        //let index = diff as usize / mem::size_of::<ElementType>();
        let index = diff;
        verify_or_die!(index < self.capacity());
        return index;
    }

    pub fn deallocate(&mut self, element: *mut ElementType) {
        let index = self.index_of(element);
        let word = index / K_BIT_CHUNK_SIZE;
        let offset = index - (word * K_BIT_CHUNK_SIZE);

        verify_or_die!(index < self.capacity());

        let value = self.m_usage[word].fetch_and(!(K_BIT1 << offset), Ordering::SeqCst);
        verify_or_die!((value & (K_BIT1 << offset)) != 0);
        self.decrease_usage();
    }

    pub fn at(&mut self, index: usize) -> *mut ElementType {
        return self.m_data.m_memory[index].as_mut_ptr();
    }

    pub fn allocate(&mut self, init_value: ElementType) -> *mut ElementType {
        //for word in 0..(self.capacity() / K_BIT_CHUNK_SIZE) {
        for word in (0..).take_while(|word| word * K_BIT_CHUNK_SIZE < self.capacity()) {
            let usage = &self.m_usage[word];
            let mut value = usage.load(Ordering::Relaxed);
            let mut offset: usize = 0;
            while offset < K_BIT_CHUNK_SIZE && offset + word * K_BIT_CHUNK_SIZE < self.capacity() {
                if (value & (K_BIT1 << offset)) == 0 {
                    if usage
                        .compare_exchange(
                            value,
                            value | (K_BIT1 << offset),
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        self.increase_usage();
                        let index = word * K_BIT_CHUNK_SIZE + offset;
                        self.m_data.m_memory[index].write(init_value);
                        return self.at(index);
                    }
                    value = usage.load(Ordering::Relaxed);
                }
                offset += 1;
            }
        }
        ptr::null_mut()
    }
}

impl<ElementType, const N: usize> ObjectPool<ElementType, KInline>
    for BitMapObjectPool<ElementType, N>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]:,
{
    fn create_object(&mut self, init_value: ElementType) -> *mut ElementType {
        return self.allocate(init_value);
    }

    fn release_object(&mut self, element: *mut ElementType) {
        if element.is_null() == true {
            return;
        }

        unsafe {
            ptr::drop_in_place(element);
        }

        self.deallocate(element);
    }

    fn releaes_all(&mut self) {}

    fn for_each_active_object<F>(&mut self, mut f: F) -> Loop
    where
        F: FnOnce(*mut ElementType) -> Loop + FnMut(*mut ElementType) -> Loop,
    {
        let capacity = self.capacity();
        //for word in (0..).take_while(|&word| word * K_BIT_CHUNK_SIZE < self.capacity()) {
        for word in (0..).take_while(|&word| word * K_BIT_CHUNK_SIZE < capacity) {
            let usage = &self.m_usage[word];
            let value = usage.load(Ordering::Relaxed);
            //for offset in (0..).clone().take_while(|&offset| offset < K_BIT_CHUNK_SIZE && offset + word * K_BIT_CHUNK_SIZE < self.capacity())
            for offset in (0..).clone().take_while(|&offset| {
                offset < K_BIT_CHUNK_SIZE && offset + word * K_BIT_CHUNK_SIZE < capacity
            }) {
                if (value & (K_BIT1 << offset)) != 0 {
                    if f(self.at(word * K_BIT_CHUNK_SIZE + offset)) == Loop::Break {
                        return Loop::Break;
                    }
                }
            }
        }
        return Loop::Finish;
    }

    /*
    fn for_each_active_object_const<F>(&mut self, f: F)
        where
            F: FnOnce(*mut ElementType) -> Loop + Fn(*mut ElementType) -> Loop
    {
    }
    */
}

#[macro_export]
macro_rules! create_object_pool {
    ($element_type: ty, $num_element: expr) => {
        //BitMapObjectPool::<$element_type, {($num_element + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE}, $num_element>::new()
        BitMapObjectPool::<$element_type, $num_element>::new()
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    mod new {
        use super::super::*;
        use std::*;
        struct StubStructInner {
            init: bool,
        }

        impl Drop for StubStructInner {
            fn drop(&mut self) {
                self.init = false;
            }
        }

        struct StubStruct<'a> {
            _inner: StubStructInner,
            the_int: u32,
            _the_string: &'a str,
        }

        impl Drop for StubStruct<'_> {
            fn drop(&mut self) {
                self.the_int = 0;
            }
        }

        #[test]
        fn new_object_pool() {
            let object_pool = create_object_pool!(StubStruct, 10);
            assert_eq!(10, object_pool.capacity());
        }

        #[test]
        fn allocate_one() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            assert_eq!(false, s.is_null());
            assert_eq!(false, object_pool.exhausted());
            unsafe {
                assert_eq!(1, (*s).the_int);
            }
        }

        #[test]
        fn full() {
            let mut object_pool = create_object_pool!(StubStruct, 1);
            let s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            let b = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 2,
                _the_string: "test",
            });
            assert_eq!(false, s.is_null());
            assert_eq!(true, b.is_null());
            assert_eq!(true, object_pool.exhausted());
        }

        #[test]
        fn allocate_two() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            let b = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 2,
                _the_string: "test",
            });
            assert_eq!(false, s.is_null());
            assert_eq!(false, b.is_null());
            assert_eq!(false, object_pool.exhausted());
            assert_eq!(2, object_pool.allocated());
        }

        #[test]
        fn release_one() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            assert_eq!(1, object_pool.allocated());
            object_pool.release_object(s);
            assert_eq!(0, object_pool.allocated());
        }

        #[test]
        fn release_two() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            let b = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 2,
                _the_string: "test",
            });
            assert_eq!(2, object_pool.allocated());
            object_pool.release_object(s);
            object_pool.release_object(b);
            assert_eq!(0, object_pool.allocated());
        }

        #[test]
        fn loop_activate_one() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let _s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            let mut inits: Vec<u32> = Vec::new();
            assert_eq!(
                Loop::Finish,
                object_pool.for_each_active_object(|element: *mut StubStruct| {
                    unsafe {
                        inits.push((*element).the_int);
                    }
                    Loop::Continue
                })
            );
            assert_eq!(1, inits[0]);
        }

        #[test]
        fn loop_activate_two() {
            let mut object_pool = create_object_pool!(StubStruct, 10);
            let _s = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 1,
                _the_string: "test",
            });
            let _b = object_pool.create_object(StubStruct {
                _inner: StubStructInner { init: true },
                the_int: 12,
                _the_string: "test",
            });
            let mut inits: Vec<u32> = Vec::new();
            assert_eq!(
                Loop::Finish,
                object_pool.for_each_active_object(|element: *mut StubStruct| {
                    unsafe {
                        inits.push((*element).the_int);
                    }
                    Loop::Continue
                })
            );
            assert_eq!(1, inits[0]);
            assert_eq!(12, inits[1]);
        }
    }
}
