pub type IdType = u8;

pub const ROOT_IDX: usize = 0;

pub struct HierarchyStateMachine<'a, E: Copy + 'a, const N:usize>
{
    m_states: [&'a dyn State<Event = E>; N],
    m_current_state: usize,
}

pub trait State { 
    type Event;

    fn handle(&self, event: Self::Event) -> (Option<Self::Event>, Option<IdType>);

    fn entry(&self) {}

    fn exit(&self) {}

    fn parent(&self) -> Option<IdType>;

    fn id(&self) -> IdType;
}

impl<'a, E: Copy + 'a, const N: usize> HierarchyStateMachine<'a, E, N>
{
    pub fn run(&mut self, event: E)
    {
        let mut next_event = Some(event);
        while next_event.is_some() {
            let mut next_state;
            (next_event, next_state) = self.m_states[self.m_current_state].handle(next_event.take().unwrap());

            if let Some(new_state) = self.find(next_state) {
                self.m_current_state = self.transition(self.m_current_state, new_state);
            }
        }
    }

    fn find(&self, state: Option<IdType>) -> Option<usize> {
        if let Some(id) = state {
            for (idx, s) in self.m_states.iter().enumerate() {
                if id == s.id() {
                    return Some(idx);
                }
            }
            return None;
        } else {
            return None;
        }
    }

    fn transition(&mut self, current: usize, next: usize) -> usize {
        // check the range, and cannot go to root
        if current > self.m_states.len() || next > self.m_states.len() || next == ROOT_IDX {
            // don't perform the transition
            return current;
        }
        let common_parent = self.find_common_parent(current, next);

        // run exits from current -> common_parent(but not parent)
        /*
        let current_exit = Some(current);
        while current_exit.is_some_and(|e| e !=  common_parent && e < self.m_states.len()) {
            let e = current_exit.take().unwrap();
            self.m_states[e].exit();
            current_exit = self.find(self.m_states[e].parent());
        }
        */

        return 0;
    }

    fn find_common_parent(&self, a: usize, b: usize) -> usize {
        // We don't expect too much states, so just use brutal force search
        let mut parent_a = Some(a);
        while parent_a.is_some_and(|a| a < self.m_states.len()) {
            let parent_a_index = parent_a.take().unwrap();
            let mut parent_b = Some(b);
            while parent_b.is_some_and(|b| b < self.m_states.len()) {
                let parent_b_index = parent_b.take().unwrap();
                if parent_a_index == parent_b_index {
                    return parent_b_index;
                }
                parent_b = self.find(self.m_states[parent_b_index].parent());
            }
            parent_a = self.find(self.m_states[parent_a_index].parent());
        }
        // should not reach here
        return ROOT_IDX;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::*;

    mod init{
        use super::super::*;
        pub struct DummyState;

        impl State for DummyState {
            type Event = u8;

            fn handle(&self, _event: Self::Event) -> (Option<Self::Event>, Option<IdType>) {
                return (None, None);
            }

            fn parent(&self) -> Option<IdType> {
                None
            }

            fn id(&self) -> IdType { 0 }
        }

        static STATIC_STATE: DummyState = DummyState;

        #[test]
        fn init_dummy_state() {
            let s = DummyState;
        }

        #[test]
        fn init_state_machine() {
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&STATIC_STATE],
                m_current_state: 0
            };
        }
    }

    mod find_parent {
        use super::super::*;
        
        pub struct DummyState {
            id: IdType,
            parent: Option<IdType>,
        }

        impl State for DummyState {
            type Event = u8;

            fn handle(&self, _event: Self::Event) -> (Option<Self::Event>, Option<IdType>) {
                return (None, None);
            }

            fn parent(&self) -> Option<IdType> {
                self.parent.clone()
            }

            fn id(&self) -> IdType { self.id }
        }

        impl DummyState {
            pub fn new(the_id: IdType, the_parent: Option<IdType>) -> Self {
                Self {
                    id: the_id,
                    parent: the_parent,
                }
            }
        }

        #[test]
        fn empty_hsm() {
            let s = HierarchyStateMachine::<u8, 0> {
                m_states: [],
                m_current_state: 0
            };

            assert_eq!(ROOT_IDX, s.find_common_parent(0, 0));
        }

        #[test]
        fn root_state_only() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(ROOT_IDX, s.find_common_parent(0, 0));
        }

        #[test]
        fn root_state_only_a_out_of_range() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(ROOT_IDX, s.find_common_parent(0, 1));
        }

        #[test]
        fn root_state_only_b_out_of_range() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(ROOT_IDX, s.find_common_parent(1, 0));
        }

        #[test]
        fn a_superset_b() {
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s = HierarchyStateMachine::<u8, 2> {
                m_states: [&s0, &s1],
                m_current_state: 0
            };

            assert_eq!(0, s.find_common_parent(0, 1));
            assert_eq!(0, s.find_common_parent(0, 0));
            assert_eq!(0, s.find_common_parent(1, 0));
            assert_eq!(1, s.find_common_parent(1, 1));
        }

        #[test]
        fn a_superset_b_indirectly() {
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(1));
            let s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(0, s.find_common_parent(0, 2));
        }

        #[test]
        fn a_b_not_same_parent() {
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(0));
            let s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(0, s.find_common_parent(1, 2));
        }

        #[test]
        fn a_b_not_same_parent_indirectly() {
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(1));
            let s3 = DummyState::new(3, Some(1));
            let s4 = DummyState::new(4, Some(0));
            let s5 = DummyState::new(5, Some(4));
            let s6 = DummyState::new(6, Some(4));
            let s = HierarchyStateMachine::<u8, 7> {
                m_states: [&s0, &s1, &s2, &s3, &s4, &s5, &s6],
                m_current_state: 0
            };

            assert_eq!(0, s.find_common_parent(3, 6));
        }
    }
}
