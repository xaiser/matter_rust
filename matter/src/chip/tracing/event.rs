#[derive(Debug, Clone, Copy)]
pub struct LableGroup<'a> {
    pub label: &'a str,
    pub group: &'a str
}

impl<'a> LableGroup<'a> {
    pub const fn new(label: &'a str, group: &'a str) -> Self {
        Self {
            label,
            group,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    Begin(LableGroup<'a>),
    End(LableGroup<'a>),
    Instant(LableGroup<'a>),
    Count(&'a str),
}

impl<'a> Event<'a> {
    pub const fn begin(l: &'a str, g: &'a str) -> Self {
        Event::Begin(LableGroup::new(l, g))
    }

    pub const fn end(l: &'a str, g: &'a str) -> Self {
        Event::End(LableGroup::new(l, g))
    }

    pub const fn instant(l: &'a str, g: &'a str) -> Self {
        Event::Instant(LableGroup::new(l, g))
    }

    pub const fn count(l: &'a str) -> Self {
        Event::Count(l)
    }

    pub fn get_begin(&self) -> Option<LableGroup<'a>> {
        match self {
            Event::<'a>::Begin(lg) => Some(lg.clone()),
            _ => None,
        }
    }
}
