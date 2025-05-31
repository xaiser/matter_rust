pub use super::common::{State, ROOT_IDX, IdType};

pub struct HierarchyStateMachine<'a, E: Copy + 'a, const N:usize>
{
    m_states: [&'a dyn State<Event = E>; N],
    m_current_state: usize,
}

impl<'a, E: Copy + 'a, const N: usize> HierarchyStateMachine<'a, E, N>
{
    pub fn run(&mut self, event: E)
    {
        if self.m_current_state >= self.m_states.len() {
            // TODO: Some error log
            return;
        }

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
        if next == ROOT_IDX {
            // don't perform the transition
            return current;
        }

        if let Some(common_parent) = self.find_common_parent(current, next) {
            // run exits from current -> common_parent(but not parent)
            let mut current_exit = Some(current);
            while current_exit.is_some_and(|e| e !=  common_parent && e < self.m_states.len()) {
                let e = current_exit.take().unwrap();
                self.m_states[e].exit();
                current_exit = self.find(self.m_states[e].parent());
            }

            // self-transition case
            if current == next {
                self.m_states[current].exit();
            }

            // run entry
            self.run_entry(common_parent, next);

            // self-transition case
            if current == next {
                self.m_states[current].entry();
            }

            return next;
        } else {
            // no common parent, no transition
            return current;
        }
    }

    fn run_entry(&mut self, parent: usize, current: usize) {
        if current == parent {
            return;
        }

        if let Some(p) = self.find(self.m_states[current].parent()) {
            self.run_entry(parent, p);
        }

        self.m_states[current].entry();
    }

    fn find_common_parent(&self, a: usize, b: usize) -> Option<usize> {
        // We don't expect too much states, so just use brutal force search
        let mut parent_a = Some(a);
        while parent_a.is_some_and(|a| a < self.m_states.len()) {
            let parent_a_index = parent_a.take().unwrap();
            let mut parent_b = Some(b);
            while parent_b.is_some_and(|b| b < self.m_states.len()) {
                let parent_b_index = parent_b.take().unwrap();
                if parent_a_index == parent_b_index {
                    return Some(parent_b_index);
                }
                parent_b = self.find(self.m_states[parent_b_index].parent());
            }
            parent_a = self.find(self.m_states[parent_a_index].parent());
        }
        // should not reach here
        return None;
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

        pub struct DummyState1;

        impl State for DummyState1 {
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
        static STATIC_STATE_1: DummyState1 = DummyState1;

        #[test]
        fn init_dummy_state() {
            let s = DummyState;
        }

        #[test]
        fn init_state_machine() {
            let s = HierarchyStateMachine::<u8, 2> {
                m_states: [&STATIC_STATE, &STATIC_STATE_1],
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

            assert_eq!(None, s.find_common_parent(0, 0));
        }

        #[test]
        fn root_state_only() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(ROOT_IDX, s.find_common_parent(0, 0).unwrap());
        }

        #[test]
        fn root_state_only_a_out_of_range() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(None, s.find_common_parent(0, 1));
        }

        #[test]
        fn root_state_only_b_out_of_range() {
            let s0 = DummyState::new(0, None);
            let s = HierarchyStateMachine::<u8, 1> {
                m_states: [&s0],
                m_current_state: 0
            };

            assert_eq!(None, s.find_common_parent(1, 0));
        }

        #[test]
        fn a_superset_b() {
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s = HierarchyStateMachine::<u8, 2> {
                m_states: [&s0, &s1],
                m_current_state: 0
            };

            assert_eq!(0, s.find_common_parent(0, 1).unwrap());
            assert_eq!(0, s.find_common_parent(0, 0).unwrap());
            assert_eq!(0, s.find_common_parent(1, 0).unwrap());
            assert_eq!(1, s.find_common_parent(1, 1).unwrap());
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

            assert_eq!(0, s.find_common_parent(0, 2).unwrap());
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

            assert_eq!(0, s.find_common_parent(1, 2).unwrap());
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

            assert_eq!(0, s.find_common_parent(3, 6).unwrap());
        }
    } // end of find_parent

    mod transition {
        use super::super::*;
        use std::cell::RefCell;

        #[derive(Debug, PartialEq)]
        enum Ex{
            Entry,
            Exit,
        }

        static mut ORDER: Vec<(Ex, IdType)> = Vec::new();
        
        pub struct DummyState {
            id: IdType,
            entry: RefCell<bool>,
            exit: RefCell<bool>,
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

            fn entry(&self) {
                *self.entry.borrow_mut() = true;
                unsafe {
                    ORDER.push((Ex::Entry, self.id));
                }
            }

            fn exit(&self) {
                *self.exit.borrow_mut() = true;
                unsafe {
                    ORDER.push((Ex::Exit, self.id));
                }
            }

            fn id(&self) -> IdType { self.id }
        }

        impl DummyState {
            pub fn new(the_id: IdType, the_parent: Option<IdType>) -> Self {
                Self {
                    id: the_id,
                    entry: RefCell::new(false),
                    exit: RefCell::new(false),
                    parent: the_parent,
                }
            }
        }

        fn setup() {
            unsafe {
                ORDER.clear();
            }
        }

        #[test]
        fn empty_hsm() {
            setup();
            let mut s = HierarchyStateMachine::<u8, 0> {
                m_states: [],
                m_current_state: 0
            };

            assert_eq!(0, s.transition(0, 1));
        }

        /*
        #[test]
        #[should_panic]
        fn empty_hsm_over_idx() {
            let mut s = HierarchyStateMachine::<u8, 0> {
                m_states: [],
                m_current_state: 0
            };

            assert_eq!(1, s.transition(1, 0));
        }
        */

        #[test]
        fn self_transition() {
            setup();
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(0));
            let mut s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(1, s.transition(1, 1));
            assert_eq!(true, *s1.entry.borrow());
            assert_eq!(true, *s1.exit.borrow());
        }

        #[test]
        fn child_to_parent() {
            setup();
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(1));
            let mut s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(1, s.transition(2, 1));
            assert_eq!(false, *s2.entry.borrow());
            assert_eq!(true, *s2.exit.borrow());
            assert_eq!(false, *s1.entry.borrow());
            assert_eq!(false, *s1.exit.borrow());
            unsafe {
                assert_eq!((Ex::Exit, 2), ORDER[0]);
            }
        }

        #[test]
        fn parent_to_child() {
            setup();
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(1));
            let mut s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(2, s.transition(1, 2));
            assert_eq!(true, *s2.entry.borrow());
            assert_eq!(false, *s2.exit.borrow());
            assert_eq!(false, *s1.entry.borrow());
            assert_eq!(false, *s1.exit.borrow());
            unsafe {
                assert_eq!(1, ORDER.len());
                assert_eq!((Ex::Entry, 2), ORDER[0]);
            }
        }

        #[test]
        fn to_sibling() {
            setup();
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(0));
            let mut s = HierarchyStateMachine::<u8, 3> {
                m_states: [&s0, &s1, &s2],
                m_current_state: 0
            };

            assert_eq!(2, s.transition(1, 2));
            assert_eq!(true, *s2.entry.borrow());
            assert_eq!(false, *s2.exit.borrow());
            assert_eq!(false, *s1.entry.borrow());
            assert_eq!(true, *s1.exit.borrow());
            unsafe {
                assert_eq!(2, ORDER.len());
                assert_eq!((Ex::Exit, 1), ORDER[0]);
                assert_eq!((Ex::Entry, 2), ORDER[1]);
            }
        }

        #[test]
        fn more_layers() {
            setup();
            let s0 = DummyState::new(0, None);
            let s1 = DummyState::new(1, Some(0));
            let s2 = DummyState::new(2, Some(1));
            let s3 = DummyState::new(3, Some(1));
            let s4 = DummyState::new(4, Some(0));
            let s5 = DummyState::new(5, Some(4));
            let s6 = DummyState::new(6, Some(4));
            let mut s = HierarchyStateMachine::<u8, 7> {
                m_states: [&s0, &s1, &s2, &s3, &s4, &s5, &s6],
                m_current_state: 0
            };

            assert_eq!(6, s.transition(3, 6));
            assert_eq!(false, *s3.entry.borrow());
            assert_eq!(true, *s3.exit.borrow());
            assert_eq!(false, *s1.entry.borrow());
            assert_eq!(true, *s1.exit.borrow());
            assert_eq!(true, *s4.entry.borrow());
            assert_eq!(false, *s4.exit.borrow());
            assert_eq!(true, *s6.entry.borrow());
            assert_eq!(false, *s6.exit.borrow());
            unsafe {
                assert_eq!(4, ORDER.len());
                assert_eq!((Ex::Exit, 3), ORDER[0]);
                assert_eq!((Ex::Exit, 1), ORDER[1]);
                assert_eq!((Ex::Entry, 4), ORDER[2]);
                assert_eq!((Ex::Entry, 6), ORDER[3]);
            }
        }
    } // end of transition
}
