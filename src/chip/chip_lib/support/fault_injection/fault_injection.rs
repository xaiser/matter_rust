/* 
 * A copy of NLFaultInjection library
 */
use core::ptr;
use core::ptr::NonNull;

use crate::verify_or_return_value;

/*  The max number of arguments that can be stored in a fault */
pub const K_MAX_FAULT_ARGS: usize = 8;

pub type Identifier = u32;
pub type FaultInjectionResult = Result<(), ErrorCode>;

pub enum ErrorCode {
    KErrInvalid = 1,
}

/**
 * A fault-injection callback function.
 * A function of this type can be attached to a fault ID, and will be invoked every time
 * FaultInjectionMgr::CheckFault is called on the fault ID.
 * The main purpose of registering a callback is to be able to turn on lower-level faults from
 * higher level events; e.g., "fail in SendMessage for the next WDM ViewRequest."
 * The callback can also be used to let the application decide if the fault is supposed to be
 * triggered at each invocation. If the callback returns true, the fault is triggered.
 *
 * @param[in]   aFaultID        The fault ID
 * @param[in]   aFaultRecord    Pointer to the Record for aFaultID;
 *                              This allows the callback to check how the fault is configured
 *                              before taking action.
 * @param[in]   aContext        The pointer stored by the application in the Callback
 *                              structure.
 * @return      true if the fault is to be triggered. false if this callback does not want to
 *              force the fault to be triggered.
 */
pub type CallbackFn = fn(Identifier, * mut Record, * mut ()) -> bool;

/**
 * The type of a function that returns a reference to a Manager
 * The module is expected to provide such a function so that
 * it can be added to an array of GetManagerFn instances and passed to
 * ParseFaultInjectionStr.
 */
pub type GetManagerFn = fn() -> &'static mut Manager;

/**
 * A callback for the application to implement support for restarting
 * the system.
 */
pub type RebootCallbackFn = fn() -> ();

/**
 * A callback to inform the application that a Manager has decided to inject a fault.
 * The main use of this type of callback is to print a log statement.
 */
pub type PostInjectionCallbackFn = fn(* mut Manager, Identifier, * mut Record);

/**
 * A table of callbacks used by all managers.
 */
pub struct GlobalCallbackTable {
    m_reboot_cb: RebootCallbackFn, /* See RebootCallbackFn */
    m_post_injection_cb: PostInjectionCallbackFn, /* See PostInjectionCallbackFn */
}

/**
 * A structure to hold global state that is used
 * by all Managers.
 */
pub struct GlobalContext {
    m_cb_table: GlobalCallbackTable,
}

/**
 * A structure to store an array of GetManagerFn arrays, used by ParseFaultInjectionStr.
 * The main purpose of this is to pass a collection of static tables owned of GetManagerFn owned
 * by separate modules to ParseFaultInjectionStr.
 */
pub struct ManagerTable {
    m_array: * const GetManagerFn, /* A pointer to an array of GetManagerFn */
    m_num_items: usize, /* The length of mArray */
}

/**
 * A linked-list node to hold a callback function to be attached to a fault ID.
 * The application can store a pointer in the mContext member.
 */
pub struct Callback {
    pub m_call_back_fn: CallbackFn,
    pub m_context: * mut (),
    pub m_next: * mut Callback,
}

/**
 * Structure that stores the configuration of a given fault ID.
 * The module defining the fault-injection API needs to provide an array of Record
 * and pass it to its Manager instance via the Init method.
 */
pub struct Record {
    m_num_calls_to_skip: u16, /* The number of times this fault should not trigger before it starts failing */

    m_num_calls_to_fail: u16,  /*< The number of times this fault should fail, before disabling itself */

    m_percentage: u8,        /*< A number between 0 and 100 that indicates the percentage of times the fault should be triggered */

    m_reboot: u8,            /* This fault should reboot the system */

    m_length_of_arguments: u8, /* The length of the array pointed to by mArguments */

    m_num_arguments: u8,      /* The number of items currently stored in the array pointed to by mArguments */

    m_callback_list: * mut Callback,      /* A list of callbacks */

    m_num_times_checked: u32,   /* The number of times the fault location was executed */

    m_arguments: * mut i32,         /* A pointer to an array of integers to store extra arguments; this array is meant to
                                       be populated by either of the following:
                                       - the ParseFaultInjectionStr, so the values are available at the fault injection site
                                         and when the fault is injected.
                                       - the logic around the fault injection site, to save useful values that can then
                                         be logged by a callback installed by the application, and so made available for use
                                         in subsequent test runs as arguments to the injected code.
                                         For example, the values can be exact arguments to be passed in, or ranges to be
                                         iterated on (like the length of a byte array to be fuzzed). */
}

mod InterManager {
    pub type LockCbFn = fn(* mut ());
}

static mut S_GLOBAL_CONTEXT: * mut GlobalContext = ptr::null_mut();
pub const K_MUTEXT_DO_NOT_TAKE: bool = false;
pub const K_MUTEXT_TAKE: bool = true;

/**
 * The callback function that implements the deterministic
 * injection feature (see FailAtFault).
 */
fn deterministc_cb_fn(_id: Identifier, p_record: * mut Record, _context: * mut ()) -> bool {
    let mut retval = false;
    unsafe {
        if let Some(record) = p_record.as_mut() {
            if record.m_num_calls_to_skip > 0 {
                record.m_num_calls_to_skip -= 1;
            } else if record.m_num_calls_to_fail > 0 {
                record.m_num_calls_to_fail -= 1;
                retval = true;
            }
        }
    }
    return retval;
}

/**
 * Callback list node for DeterministicCbFn.
 * This node terminates all callback lists.
 */
static mut S_DETERMINSTIC_CB: Callback = Callback { 
    m_call_back_fn: deterministc_cb_fn,
    m_context: ptr::null_mut(),
    m_next: ptr::null_mut(),
};

/**
 * The callback function that implements the random
 * injection feature (see FailRandomlyAtFault).
 */
fn random_cb_fn(_id: Identifier, p_record: * mut Record, _context: * mut ()) -> bool {
    let mut retval = false;
    unsafe {
        if let Some(record) = p_record.as_mut() {
            if record.m_percentage > 0 {
                /* 
                 * TODO: implement this
                 */
            }
        }
    }
    return retval;
}

static mut S_RANDOM_CB: Callback = Callback {
    m_call_back_fn: random_cb_fn,
    m_context: ptr::null_mut(),
    m_next: ptr::addr_of_mut!(S_DETERMINSTIC_CB),
};

static mut S_END_OF_CUSTOM_CALLBACKS: * const Callback = ptr::addr_of!(S_RANDOM_CB);

/**
 * The module that provides a fault-injection API needs to provide an instance of Manager,
 * and initialize it with an array of Record.
 */
pub struct Manager {
    m_num_faults: usize,
    m_fault_records: * mut Record,
    m_name: &'static str,
    m_fault_names: &'static [&'static str],
    m_lock: InterManager::LockCbFn,
    m_unlock: InterManager::LockCbFn,
    m_lock_context: * mut (),
}

fn empty_lock(context: * mut ()) {}
fn empty_unlock(context: * mut ()) {}

impl Default for Manager {
    fn default() -> Self {
        static EMPTY_NAME: &str = "";
        static EMPTY_FAULT_NAMES: [&str; 1] = [""];
        Manager {
            m_num_faults: 0,
            m_fault_records: ptr::null_mut(),
            m_name: &EMPTY_NAME,
            m_fault_names: &EMPTY_FAULT_NAMES,
            m_lock: empty_lock,
            m_unlock: empty_unlock,
            m_lock_context: ptr::null_mut(),
        }
    }
}

impl Manager {
    pub fn init(&mut self, in_num_faults: usize, in_fault_array: * mut Record, in_manager_name: &'static str, in_fault_names: &'static [&'static str]) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());
        verify_or_return_value!(in_num_faults > 0 && in_fault_array.is_null() == false && in_manager_name.is_empty() == false && in_fault_names.is_empty() == false, err, err = Err(ErrorCode::KErrInvalid));

        self.m_name = in_manager_name;
        self.m_num_faults = in_num_faults;
        self.m_fault_records = in_fault_array;
        self.m_fault_names = in_fault_names;
        self.m_lock = empty_lock;
        self.m_unlock = empty_unlock;
        self.m_lock_context = ptr::null_mut();
        Ok(())
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  fn set_up() {
  }

  #[test]
  fn init() {
      set_up();
      let m = Manager::default();

      assert_eq!(0, m.m_num_faults);
  }
}
