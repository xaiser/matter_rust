#[repr(u8)]
#[derive(PartialEq, Clone)]
pub enum State {
    Uninitialized = 0, // Pre-initialized state.
    Initializing = 1,  // State during intialization.
    Initialized = 2,   // Initialized (active) state.
    ShuttingDown = 3,  // State during shutdown.
    Shutdown = 4,      // Post-shutdown state.
    Destroyed = 5,     // Post-destructor state.
}

pub struct ObjectLifeCycle {
    m_state: State,
}

impl ObjectLifeCycle {
    fn transition(&mut self, from: State, to: State) -> bool {
        if self.m_state == from {
            self.m_state = to;
            return true;
        }

        return false;
    }

    pub const fn default() -> Self {
        ObjectLifeCycle {
            m_state: State::Uninitialized,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.m_state == State::Initialized
    }

    pub fn set_initializing(&mut self) -> bool {
        self.transition(State::Uninitialized, State::Initializing)
    }

    pub fn set_initialized(&mut self) -> bool {
        self.transition(State::Initializing, State::Initialized)
    }

    pub fn set_shutting_down(&mut self) -> bool {
        self.transition(State::Initialized, State::ShuttingDown)
    }

    pub fn set_shut_down(&mut self) -> bool {
        self.transition(State::ShuttingDown, State::Shutdown)
    }

    pub fn reset(&mut self) -> bool {
        self.transition(State::Shutdown, State::Uninitialized)
    }

    pub fn reset_from_shutting_down(&mut self) -> bool {
        self.transition(State::ShuttingDown, State::Uninitialized)
    }

    pub fn reset_from_initialized(&mut self) -> bool {
        self.transition(State::Initialized, State::Uninitialized)
    }

    pub fn destory(&mut self) -> bool {
        if self.m_state == State::Uninitialized || self.m_state == State::Shutdown {
            self.m_state = State::Destroyed;
            return true;
        }
        return false;
    }

    pub fn get_state(&self) -> State {
        self.m_state.clone()
    }
}
