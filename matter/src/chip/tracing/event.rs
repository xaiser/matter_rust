#[derive(Debug, Clone, Copy)]
pub struct LableGroup<'a> {
    pub label: &'a str,
    pub group: &'a str
}

#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    Begin(LableGroup<'a>),
    End(LableGroup<'a>),
    Instant(LableGroup<'a>),
    Count(&'a str),
}
