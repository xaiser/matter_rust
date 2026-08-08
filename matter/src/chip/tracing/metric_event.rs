use crate::{
    chip::{
        tracing::{
            metric_keys::MetricKey,
        },
    },
};

pub mod internal {
    use crate::ChipError;

    // This specifies the different categories of metric events that can created. In addition to
    // emitting an event, events paired with a kBeginEvent and kEndEvent can be used to track
    // duration for the event. A kInstantEvent represents a one shot event.
    #[derive(Debug, Clone, Copy)]
    pub enum Type {
        // This specifies an event marked to track the Begin of an operation
        KbeginEvent,

        // This specifies an event marked to track the End of an operation
        KendEvent,

        // This specifies a one shot event
        KinstantEvent
    }

    // This defines the different types of values that can stored when a metric is emitted
    #[derive(Debug, Clone, Copy)]
    pub enum Value {
        Undefined,
        Signed(i32),
        Unsigned(u32),
        ChipError(ChipError),
    }

    impl Value {
        pub const fn new() -> Self {
            Value::Undefined
        }
    }

    impl From<u32> for Value {
        fn from(value: u32) -> Self {
            Value::Unsigned(value)
        }
    }

    impl From<i32> for Value {
        fn from(value: i32) -> Self {
            Value::Signed(value)
        }
    }

    impl From<i8> for Value {
        fn from(value: i8) -> Self {
            Value::Signed(i32::from(value))
        }
    }

    impl From<u8> for Value {
        fn from(value: u8) -> Self {
            Value::Unsigned(u32::from(value))
        }
    }

    impl From<i16> for Value {
        fn from(value: i16) -> Self {
            Value::Signed(i32::from(value))
        }
    }

    impl From<u16> for Value {
        fn from(value: u16) -> Self {
            Value::Unsigned(u32::from(value))
        }
    }

    impl From<ChipError> for Value {
        fn from(value: ChipError) -> Self {
            Value::ChipError(value)
        }
    }
}

use internal::{Type, Value};

/*
 * Define a metric that can be logged. A metric consists of a key and an optional value pair.
 * The value is currently limited to simple scalar values.
 *
 * Additionally a metric is tagged as either an instant event or marked with a begin/end
 * for the event. When the latter is used, a duration can be associated between the two events.
 */
#[derive(Debug, Clone, Copy)]
pub struct MetricEvent {
    m_type: Type,
    m_key: MetricKey,
    m_value: Value,
}

impl MetricEvent {
    pub const fn new(the_type: Type, key: MetricKey) -> Self {
        Self {
            m_type: the_type,
            m_key: key,
            m_value: Value::new(),
        }
    }

    pub fn new_with<T>(the_type: Type, key: MetricKey, value: T) -> Self 
        where
            T: Into<Value>,
    {
        Self {
            m_type: the_type,
            m_key: key,
            m_value: value.into(),
        }
    }

    pub fn the_type(&self) -> Type {
        self.m_type
    }

    pub fn key(&self) -> MetricKey {
        self.m_key
    }

    pub fn value(&self) -> Value {
        self.m_value
    }
}
