pub trait ReferenceCountered<SubType, Deletor, const KInitRefCount: usize>
where
    Deletor: FnOnce(* mut SubType) -> () + FnMut(* mut SubType) -> (),
{
    type CounterType = u32;

    fn retain(&mut self) -> * mut SubType;

    fn release(&mut self);
}

