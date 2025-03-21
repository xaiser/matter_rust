use super::base::{Init,RawTransportDelegate,Base,MessageTransportContext};

pub trait TupleInit {
    type DelegateType: RawTransportDelegate;
}

pub struct Tuple<T>
{
    m_transport: T,
}

/*
impl<Type0> Tuple<(Type0,)>
    where
        Type0: Init<DelegateType> + Base<DelegateType>,
        DelegateType: RawTransportDelegate,
{
    #[allow(dead_code)]
    pub fn init(&mut self, delegate: * mut DelegateType, p0: <Type0 as Init<DelegateType>>::InitParamType) -> ChipError
    {
        let err = self.m_transports.0.init(p0);
        if err.is_success() == false {
            return err;
        }
        self.m_transports.0.set_delegate(delegate);
        return err;
    }
}
*/
