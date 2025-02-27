use super::base::{Init,RawTransportDelegate};

struct Tuple<T> {
    m_transports: T,
}

impl<ParamType0, Type0> Tuple<(Type0,)>
    where
        Type0: super::base::Init<InitParamType=ParamType0>,
{
    pub fn init(&mut self, delegate: RawTransportDelegate, p0: ParamType0) {
        self.m_transports.0.init(p0);
    }
}

impl<ParamType0, Type0, ParamType1, Type1> Tuple<(Type0,Type1)>
    where
        Type0: super::base::Init<InitParamType=ParamType0>,
        Type1: super::base::Init<InitParamType=ParamType1>,
{
    pub fn init(&mut self, p0: ParamType0, p1: ParamType1) {
        self.m_transports.0.init(p0);
        self.m_transports.1.init(p1);
    }
}

impl<ParamType0, Type0, ParamType1, Type1> Tuple<(Type0,Type1)>
    where
        Type0: super::base::Init<InitParamType=ParamType0>,
        Type1: super::base::Init<InitParamType=ParamType1>,
{
    pub fn init(&mut self, p0: ParamType0, p1: ParamType1) {
        self.m_transports.0.init(p0);
        self.m_transports.1.init(p1);
    }
}
