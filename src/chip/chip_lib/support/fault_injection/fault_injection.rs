/* 
 * A copy of NLFaultInjection library
 */
use core::ptr;

use crate::verify_or_return_value;
use crate::verify_or_return_error;

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
    pub m_reboot_cb: Option<RebootCallbackFn>, /* See RebootCallbackFn */
    pub m_post_injection_cb: Option<PostInjectionCallbackFn>, /* See PostInjectionCallbackFn */
}

/**
 * A structure to hold global state that is used
 * by all Managers.
 */
pub struct GlobalContext {
    pub m_cb_table: GlobalCallbackTable,
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
#[derive(Copy,Clone)]
pub struct Record {
    pub m_num_calls_to_skip: u16, /* The number of times this fault should not trigger before it starts failing */

    pub m_num_calls_to_fail: u16,  /*< The number of times this fault should fail, before disabling itself */

    pub m_percentage: u8,        /*< A number between 0 and 100 that indicates the percentage of times the fault should be triggered */

    pub m_reboot: bool,            /* This fault should reboot the system */

    pub m_length_of_arguments: u8, /* The length of the array pointed to by mArguments */

    pub m_num_arguments: u8,      /* The number of items currently stored in the array pointed to by mArguments */

    pub m_callback_list: * mut Callback,      /* A list of callbacks */

    pub m_num_times_checked: u32,   /* The number of times the fault location was executed */

    pub m_arguments: &'static [i32],         /* A pointer to an array of integers to store extra arguments; this array is meant to
                                       be populated by either of the following:
                                       - the ParseFaultInjectionStr, so the values are available at the fault injection site
                                         and when the fault is injected.
                                       - the logic around the fault injection site, to save useful values that can then
                                         be logged by a callback installed by the application, and so made available for use
                                         in subsequent test runs as arguments to the injected code.
                                         For example, the values can be exact arguments to be passed in, or ranges to be
                                         iterated on (like the length of a byte array to be fuzzed). */
}

impl Record {
    pub const fn const_default() -> Self {
        Record {
            m_num_calls_to_skip: 0,
            m_num_calls_to_fail: 0,
            m_percentage: 0,
            m_reboot: false,
            m_length_of_arguments: 0,
            m_num_arguments: 0,
            m_callback_list: ptr::null_mut(),
            m_num_times_checked: 0,
            m_arguments: &[]
        }
    }
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
    let retval = false;
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
 * Configure the instance of GlobalContext to use.
 * On systems in which faults are configured and injected from different threads,
 * this function should be called before threads are started.
 *
 * @param[in] inGlobalContext   Pointer to the GlobalContext provided by the application
 */
pub fn set_global_context(context: * mut GlobalContext) {
    unsafe {
        S_GLOBAL_CONTEXT = context;
    }
}

/**
 * The module that provides a fault-injection API needs to provide an instance of Manager,
 * and initialize it with an array of Record.
 */
pub struct Manager {
    m_num_faults: usize,
    m_fault_records: &'static mut [Record],
    m_name: &'static str,
    m_fault_names: &'static [&'static str],
    m_lock: InterManager::LockCbFn,
    m_unlock: InterManager::LockCbFn,
    m_lock_context: * mut (),
}

fn empty_lock(_context: * mut ()) {}
fn empty_unlock(_context: * mut ()) {}

impl Default for Manager {
    fn default() -> Self {
        static EMPTY_NAME: &str = "";
        static EMPTY_FAULT_NAMES: [&str; 0] = [];
        static mut EMPTY_RECORD: [Record; 0] = [];
        unsafe {
            Manager {
                m_num_faults: 0,
                m_fault_records: &mut EMPTY_RECORD,
                m_name: &EMPTY_NAME,
                m_fault_names: &EMPTY_FAULT_NAMES,
                m_lock: empty_lock,
                m_unlock: empty_unlock,
                m_lock_context: ptr::null_mut(),
            }
        }
    }
}

impl Manager {
    pub const fn const_default() -> Self {
        static EMPTY_NAME: &str = "";
        static EMPTY_FAULT_NAMES: [&str; 0] = [];
        static mut EMPTY_RECORD: [Record; 0] = [];
        unsafe {
            Manager {
                m_num_faults: 0,
                m_fault_records: &mut EMPTY_RECORD,
                m_name: &EMPTY_NAME,
                m_fault_names: &EMPTY_FAULT_NAMES,
                m_lock: empty_lock,
                m_unlock: empty_unlock,
                m_lock_context: ptr::null_mut(),
            }
        }
    }
    /**
     * Initialize the Manager instance.
     *
     * @param[in]   inNumFaults     The size of inFaultArray, equal to the number of fault IDs.
     * @param[in]   inFaultArray    A pointer to an array of Record, in which this object
     *                              will store the configuration of each fault.
     * @param[in]   inManagerName   A pointer to a C string containing the name of the Manager.
     * @param[in]   inFaultNames    A pointer to an array of inNumFaults C strings that describe
     *                              each fault ID.
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn init(&mut self, in_num_faults: usize, in_fault_array: &'static mut [Record], in_manager_name: &'static str, in_fault_names: &'static [&'static str]) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());
        verify_or_return_value!(in_num_faults > 0 && in_fault_array.is_empty() == false && in_manager_name.is_empty() == false && in_fault_names.is_empty() == false, err, err = Err(ErrorCode::KErrInvalid));

        self.m_name = in_manager_name;
        self.m_num_faults = in_num_faults;
        self.m_fault_records = in_fault_array;
        self.m_fault_names = in_fault_names;
        self.m_lock = empty_lock;
        self.m_unlock = empty_unlock;
        self.m_lock_context = ptr::null_mut();

        for i in 0..self.m_num_faults {
            unsafe{
                self.m_fault_records[i].m_callback_list = &mut S_RANDOM_CB;
            }
        }

        return err;
    }

    fn lock(&mut self) {
    }

    fn unlock(&mut self) {
    }

    /**
     * Configure a fault to be triggered randomly, with a given probability defined as a percentage
     * This is meant to be used on live systems to generate a build that will encounter random failures.
     *
     * @param[in]   inId            The fault ID
     * @param[in]   inPercentage    An integer between 0 and 100. 100 means "always". 0 means "never".
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn fail_randomly_at_fault(&mut self, id: Identifier, percentage: u8) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());

        verify_or_return_value!(((id as usize) < self.m_num_faults) && (percentage <= 100), err, err = Err(ErrorCode::KErrInvalid));

        self.lock();

        self.m_fault_records[id as usize].m_num_calls_to_skip = 0;
        self.m_fault_records[id as usize].m_num_calls_to_fail = 0;
        self.m_fault_records[id as usize].m_percentage = percentage;

        self.unlock();

        err
    }


    /**
     * Configure a fault to be triggered deterministically.
     *
     * @param[in]   inId                The fault ID
     * @param[in]   inNumCallsToSkip    The number of times this fault is to be skipped before it
     *                                  starts to fail.
     * @param[in]   inNumCallsToFail    The number of times the fault should be triggered.
     * @param[in]   inTakeMutex         By default this method takes the Manager's mutex.
     *                                  If inTakeMutex is set to kMutexDoNotTake, the mutex is not taken.
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn fail_at_fault_with_lock(&mut self, id: Identifier, num_calls_to_skip: u32, num_calls_to_fail: u32, take_mutex: bool) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());

        verify_or_return_value!(((id as usize) < self.m_num_faults) && (num_calls_to_skip <= u16::MAX.into()) && (num_calls_to_fail <= u16::MAX.into()), err, err = Err(ErrorCode::KErrInvalid));

        if take_mutex {
            self.lock();
        }

        self.m_fault_records[id as usize].m_num_calls_to_skip = num_calls_to_skip as u16;
        self.m_fault_records[id as usize].m_num_calls_to_fail = num_calls_to_fail as u16;
        self.m_fault_records[id as usize].m_percentage = 0;

        if take_mutex {
            self.unlock();
        }

        err
    }

    pub fn fail_at_fault(&mut self, id: Identifier, num_calls_to_skip: u32, num_calls_to_fail: u32) -> FaultInjectionResult {
        return self.fail_at_fault_with_lock(id, num_calls_to_skip, num_calls_to_fail, K_MUTEXT_TAKE);
    }

    /**
     * Configure a fault to reboot the system when triggered.
     * If the application has installed a RebootCallbackFn, it will
     * be invoked when fault inId is triggered.
     * If the application has not installed the callback, the system
     * will crash.
     *
     * @param[in]   inId                The fault ID
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn reboot_at_fault(&mut self, id: Identifier) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());

        verify_or_return_value!((id as usize) < self.m_num_faults, err, err = Err(ErrorCode::KErrInvalid));

        self.lock();

        self.m_fault_records[id as usize].m_reboot = true;

        self.unlock();

        err
    }

    /**
     * Store a set of arguments for a given fault ID.
     * The array of arguments is made available to the code injected with
     * the nlFAULT_INJECT macro.
     * For this to work for a given fault ID, the Manager must allocate memory to
     * store the arguments and configure the Record's mLengthOfArguments and
     * mArguments members accordingly.
     *
     * @param[in]   inId                The fault ID
     * @param[in]   inArgs              The slice to the array of integers to be stored in the fault
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn store_args_at_fault(&mut self, id: Identifier, args: &'static [i32]) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());
        verify_or_return_value!(((id as usize) < self.m_num_faults) && args.len() <= u8::MAX.into(), err, err = Err(ErrorCode::KErrInvalid));

        self.lock();

        self.m_fault_records[id as usize].m_arguments = args;

        self.unlock();

        err
    }

    /**
     * Detaches a callback from a fault.
     *
     * @param[in]   inId        The fault
     * @param[in]   inCallback  The callback node to be removed.
     * @param[in]   inTakeMutex         By default this method takes the Manager's mutex.
     *                                  If inTakeMutex is set to kMutexDoNotTake, the mutex is not taken.
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn remove_callback_at_fault_with_lock(&mut self, id: Identifier, callback: * mut Callback, take_mutex: bool) -> FaultInjectionResult {
        let mut err: FaultInjectionResult = Ok(());
        verify_or_return_value!(((id as usize) < self.m_num_faults) && callback.is_null() == false, err, err = Err(ErrorCode::KErrInvalid));

        if take_mutex == true {
            self.lock();
        }

        let mut cb: &mut * mut Callback = &mut self.m_fault_records[id as usize].m_callback_list;

        unsafe {
            while (*cb).is_null() == false {
                if (*cb) == callback {
                    (*cb) = (*(*cb)).m_next;
                    break;
                }
                cb = &mut (*(*cb)).m_next;
            }
        }

        if take_mutex == true {
            self.unlock();
        }

        err
    }

    pub fn remove_callback_at_fault(&mut self, id: Identifier, callback: * mut Callback) -> FaultInjectionResult {
        return self.remove_callback_at_fault_with_lock(id, callback, K_MUTEXT_TAKE);
    }


    /**
     * Attach a callback to a fault ID.
     * Calling this twice does not attach the callback twice.
     *
     * @param[in]   inId        The fault ID
     * @param[in]   inCallback  The callback node to be attached to the fault
     *
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn insert_callback_at_fault(&mut self, id: Identifier, callback: * mut Callback) -> FaultInjectionResult {

        self.remove_callback_at_fault(id, callback)?;

        self.lock();

        unsafe {
            (*callback).m_next = self.m_fault_records[id as usize].m_callback_list;
        }
        self.m_fault_records[id as usize].m_callback_list = callback;

        self.unlock();

        Ok(())
    }

    pub fn get_fault_records(&self) -> &[Record] {
        self.m_fault_records
    }

    /**
     * When the program traverses the location at which a fault should be injected, this method is invoked
     * on the manager to query the configuration of the fault ID.
     *
     * A fault can be triggered randomly, deterministically or on a call-by-call basis by a callback.
     * All three types of trigger can be installed at the same time, and they all get a chance of
     * injecting the fault.
     *
     * @param[in] inId                The fault ID
     * @param[in] inTakeMutex         By default this method takes the Manager's mutex.
     *                                If inTakeMutex is set to kMutexDoNotTake, the mutex is not taken.
     *
     * @return    true if the fault should be injected; false otherwise.
     */
    pub fn check_fault_with_lock(&mut self, id: Identifier, take_mutex: bool) -> bool {

        verify_or_return_error!((id as usize) < self.m_num_faults, false);

        if true == take_mutex {
            self.lock();
        }

        let record_index = id as usize;

        let mut cb = self.m_fault_records[record_index].m_callback_list;
        let mut next: * mut Callback;
        let mut ret_val = false;

        while cb.is_null() == false {
            unsafe {
                next = (*cb).m_next;
                if true == ((*cb).m_call_back_fn)(id, ptr::addr_of_mut!(self.m_fault_records[record_index]), (*cb).m_context) {
                    ret_val = true;
                }
                cb = next;
            }
        }
        let reboot = self.m_fault_records[record_index].m_reboot;

        unsafe {
            if ret_val == true && S_GLOBAL_CONTEXT.is_null() == false {
                if let Some(post_injection_cb) = (*S_GLOBAL_CONTEXT).m_cb_table.m_post_injection_cb {
                    post_injection_cb(self as * const Self as _, id, ptr::addr_of_mut!(self.m_fault_records[record_index]));
                }
            }

            if ret_val == true && reboot == true {
                if S_GLOBAL_CONTEXT.is_null() == false {
                    if let Some(reboot_cb) = (*S_GLOBAL_CONTEXT).m_cb_table.m_reboot_cb {
                        reboot_cb();
                    } else {
                        Self::die();
                    }
                }
                else {
                    Self::die();
                }
            }
        }

        self.m_fault_records[record_index].m_num_times_checked += 1;

        if take_mutex == true {
            self.unlock();
        }

        return ret_val;
    }

    pub fn check_fault(&mut self, id: Identifier) -> bool {
        return self.check_fault_with_lock(id, K_MUTEXT_TAKE);
    }

    /**
     * When the program traverses the location at which a fault should be injected, this method is invoked
     * on the manager to query the configuration of the fault ID.
     *
     * This version of the method retrieves the arguments stored in the Record.
     *
     * A fault can be triggered randomly, deterministically or on a call-by-call basis by a callback.
     * All three types of trigger can be installed at the same time, and they all get a chance of
     * injecting the fault.
     *
     * @param[in] inId            The fault ID
     * @param[in] inTakeMutex     By default this method takes the Manager's mutex.
     *                            If inTakeMutex is set to kMutexDoNotTake, the mutex is not taken.
     *
     * @return    true if the fault should be injected; false otherwise. With the arguments
     *            configured for the faultId.
     */
    pub fn check_fault_with_out_args_with_lock(&mut self, id: Identifier, take_mutex: bool) -> (&[i32], bool) {
        if true == take_mutex {
            self.lock();
        }

        let ret_val = self.check_fault(id);
        let mut out_args: &[i32] = &[];
        if true == ret_val {
            out_args = self.m_fault_records[id as usize].m_arguments;
        }

        if true == take_mutex {
            self.unlock();
        }

        return (out_args, ret_val);
    }

    pub fn check_fault_with_out_args(&mut self, id: Identifier) -> (&[i32], bool) {
        return self.check_fault_with_out_args_with_lock(id, K_MUTEXT_TAKE);
    }

    /**
     * Reset the counters in the fault Records
     * Note that calling this method does not impact the current configuration
     * in any way (including the number of times a fault is to be skipped
     * before it should fail).
     */
    pub fn reset_fault_counters(&mut self) {
        self.lock();

        self.m_fault_records.iter_mut().for_each(|record| {
            record.m_num_times_checked = 0;
        }
        );
        
        self.unlock();
    }

    /**
     * Reset the configuration of a fault Record
     *
     * @param[in] inId        The fault ID
     *
     * @return      KErrInvalid if the inputs are not valid.
     */
    pub fn reset_configurations(&mut self, id: Identifier) -> FaultInjectionResult {
        verify_or_return_error!((id as usize) < self.m_num_faults, Err(ErrorCode::KErrInvalid));

        self.lock();

        let record_index = id as usize;

        let mut cb = self.m_fault_records[record_index].m_callback_list;
        unsafe {
            while cb.is_null() == false && (cb as * const Callback) != S_END_OF_CUSTOM_CALLBACKS {
                let _ = self.remove_callback_at_fault_with_lock(id, cb, K_MUTEXT_DO_NOT_TAKE);
                cb = self.m_fault_records[record_index].m_callback_list;
            }
        }

        let record: &mut Record = &mut self.m_fault_records[record_index];
        record.m_num_calls_to_skip = 0;
        record.m_num_calls_to_fail = 0;
        record.m_percentage = 0;
        record.m_reboot = false;
        record.m_arguments = &[];

        self.unlock();

        Ok(())
    }

    pub fn reset_configurations_all(&mut self) -> FaultInjectionResult {
        for id in 0..self.m_fault_records.len() {
            self.reset_configurations(id as Identifier)?;
        }
        return Ok(());
    }

    fn die() {
        panic!();
    }

}

#[macro_export]
macro_rules! fault_inject {
    ($manager:expr, $id:expr $(, $action:stmt)*) => {
        if ($manager.check_fault($id)) {
            $($action)*
        }
    };
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod init {
      use super::super::*;
      use std::*;

      const NUM_FAULTS: usize = 3;
      static mut FAULT_RECORDS: [Record; NUM_FAULTS] = [ Record::const_default(); NUM_FAULTS];
      static MANAGER_NAME: &str = "test_manager";
      static mut FAULT_NAMES: [&str; NUM_FAULTS] = [ "f1", "f2", "f3" ];


      fn set_up() {
      }

      #[test]
      fn init_successfully() {
          set_up();
          let mut m = Manager::default();
          unsafe {
              assert_eq!(true, m.init(NUM_FAULTS, &mut FAULT_RECORDS, &MANAGER_NAME, &FAULT_NAMES).is_ok());
          }
      }

      #[test]
      fn init_with_0_num_fault() {
          set_up();
          let mut m = Manager::default();
          unsafe {
              assert_eq!(true, m.init(0, &mut FAULT_RECORDS, &MANAGER_NAME, &FAULT_NAMES).is_err());
          }
      }

      #[test]
      fn init_with_0_record() {
          set_up();
          let mut m = Manager::default();
          static mut EMPTY_RECORDS: [Record; 0] = [];
          unsafe {
              assert_eq!(true, m.init(NUM_FAULTS, &mut EMPTY_RECORDS, &MANAGER_NAME, &FAULT_NAMES).is_err());
          }
      }

      #[test]
      fn init_empty_manager_name() {
          set_up();
          let mut m = Manager::default();
          unsafe {
              assert_eq!(true, m.init(NUM_FAULTS, &mut FAULT_RECORDS, "", &FAULT_NAMES).is_err());
          }
      }

      #[test]
      fn init_empty_fault_names() {
          set_up();
          let mut m = Manager::default();
          unsafe {
              assert_eq!(true, m.init(NUM_FAULTS, &mut FAULT_RECORDS, &MANAGER_NAME, &[]).is_err());
          }
      }
  }

  mod failt_at {
      use super::super::*;
      use std::*;

      const NUM_FAULTS: usize = 3;
      static mut FAULT_RECORDS: [Record; NUM_FAULTS] = [Record::const_default(); NUM_FAULTS];
      static MANAGER_NAME: &str = "test_manager";
      static mut FAULT_NAMES: [&str; NUM_FAULTS] = [ "f1", "f2", "f3" ];
      static mut FAULT_MANAGER: Manager = Manager::const_default();

      fn set_up() {
          unsafe {
              for i in 0.. NUM_FAULTS {
                  FAULT_RECORDS[i] = Record::const_default();
              }
              let _ = FAULT_MANAGER.init(NUM_FAULTS, &mut FAULT_RECORDS, &MANAGER_NAME, &FAULT_NAMES);
          }
      }

      #[test]
      fn fail_at_randomly_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_randomly_at_fault(0, 0).is_ok());
          }
      }

      #[test]
      fn fail_at_randomly_with_id_over_range() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_randomly_at_fault(NUM_FAULTS.try_into().unwrap(), 0).is_err());
          }
      }

      #[test]
      fn fail_at_randomly_with_101_percentage() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_randomly_at_fault(0, 101).is_err());
          }
      }

      #[test]
      fn fail_at_fault_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_at_fault_with_lock(0, 0, 0, false).is_ok());
          }
      }

      #[test]
      fn fail_at_fault_with_id_over_range() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_at_fault_with_lock(NUM_FAULTS.try_into().unwrap(), 0, 0, false).is_err());
          }
      }

      #[test]
      fn fail_at_fault_but_num_skip_too_big() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_at_fault_with_lock(0, u16::MAX as u32 + 1, 0, false).is_err());
          }
      }

      #[test]
      fn fail_at_fault_but_num_check_too_big() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.fail_at_fault_with_lock(0, 0, u16::MAX as u32 + 1, false).is_err());
          }
      }

      #[test]
      fn reboot_at_fault_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.reboot_at_fault(0).is_ok());
          }
      }

      #[test]
      fn reboot_at_fault_with_id_over_range() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.reboot_at_fault(NUM_FAULTS.try_into().unwrap()).is_err());
          }
      }

      #[test]
      fn store_args_at_fault_successfully() {
          set_up();
          unsafe {
              static DATA: [i32; 3] = [1,2,3];
              assert_eq!(true, FAULT_MANAGER.store_args_at_fault(0, &DATA[0..2]).is_ok());
          }
      }

      #[test]
      fn store_args_at_fault_with_id_over_range() {
          set_up();
          unsafe {
              static DATA: [i32; 3] = [1,2,3];
              assert_eq!(true, FAULT_MANAGER.store_args_at_fault(NUM_FAULTS.try_into().unwrap(), &DATA[0..2]).is_err());
          }
      }
  }

  mod insert_remove_callbacks {
      use super::super::*;
      use std::*;

      const NUM_FAULTS: usize = 3;
      static mut FAULT_RECORDS: [Record; NUM_FAULTS] = [Record::const_default(); NUM_FAULTS];
      static MANAGER_NAME: &str = "test_manager";
      static mut FAULT_NAMES: [&str; NUM_FAULTS] = [ "f1", "f2", "f3" ];
      static mut FAULT_MANAGER: Manager = Manager::const_default();
      static mut CALLBACK_STUB_1: Callback = Callback {
          m_call_back_fn: stub_call,
          m_context: ptr::null_mut(),
          m_next: ptr::null_mut(),
      };
      static mut CALLBACK_STUB_2: Callback = Callback {
          m_call_back_fn: stub_call,
          m_context: ptr::null_mut(),
          m_next: ptr::null_mut(),
      };

      fn stub_call(_id: Identifier, _record: * mut Record, _context: * mut ()) -> bool {
          true
      }

      fn set_up() {
          unsafe {
              for i in 0.. NUM_FAULTS {
                  FAULT_RECORDS[i] = Record::const_default();
              }
              let _ = FAULT_MANAGER.init(NUM_FAULTS, &mut FAULT_RECORDS, &MANAGER_NAME, &FAULT_NAMES);
              CALLBACK_STUB_1 = Callback {
                  m_call_back_fn: stub_call,
                  m_context: ptr::null_mut(),
                  m_next: ptr::null_mut(),
              };
              CALLBACK_STUB_2 = Callback {
                  m_call_back_fn: stub_call,
                  m_context: ptr::null_mut(),
                  m_next: ptr::null_mut(),
              };
          }
      }

      #[test]
      fn insert_one_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(ptr::addr_of_mut!(CALLBACK_STUB_1), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }

      #[test]
      fn insert_with_id_overrange() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(NUM_FAULTS.try_into().unwrap(), ptr::addr_of_mut!(CALLBACK_STUB_1)).is_err());
          }
      }

      #[test]
      fn insert_with_empty_callback() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::null_mut()).is_err());
          }
      }

      #[test]
      fn insert_two_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_2)).is_ok());
              assert_eq!(ptr::addr_of_mut!(CALLBACK_STUB_2), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }

      #[test]
      fn insert_same_one_twice_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(ptr::addr_of_mut!(CALLBACK_STUB_1), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }

      #[test]
      fn insert_one_remove_one_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(true, FAULT_MANAGER.remove_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(ptr::addr_of_mut!(S_RANDOM_CB), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }

      #[test]
      fn insert_one_remove_one_insert_one_successfully() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(true, FAULT_MANAGER.remove_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_1)).is_ok());
              assert_eq!(ptr::addr_of_mut!(CALLBACK_STUB_1), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }
  }

  mod check_fault {
      use super::super::*;
      use std::*;

      const NUM_FAULTS: usize = 3;
      static mut FAULT_RECORDS: [Record; NUM_FAULTS] = [Record::const_default(); NUM_FAULTS];
      static MANAGER_NAME: &str = "test_manager";
      static mut FAULT_NAMES: [&str; NUM_FAULTS] = [ "f1", "f2", "f3" ];
      static mut FAULT_MANAGER: Manager = Manager::const_default();
      static mut CALLBACK_STUB_TRUE: Callback = Callback {
          m_call_back_fn: stub_call_true,
          m_context: ptr::null_mut(),
          m_next: ptr::null_mut(),
      };
      static mut CALLBACK_STUB_FALSE: Callback = Callback {
          m_call_back_fn: stub_call_false,
          m_context: ptr::null_mut(),
          m_next: ptr::null_mut(),
      };
      static mut GLOBAL_CONTEXT_CHECK: GlobalContext = GlobalContext {
          m_cb_table: GlobalCallbackTable {
              m_reboot_cb: Some(reboot_check),
              m_post_injection_cb: Some(post_injection_check),
          }
      };
      static mut POST_INJECT_CHECK: bool = false;
      static mut IS_REBOOT: bool = false;

      fn stub_call_true(_id: Identifier, _record: * mut Record, _context: * mut ()) -> bool {
          true
      }

      fn stub_call_false(_id: Identifier, _record: * mut Record, _context: * mut ()) -> bool {
          false
      }

      fn reboot_check() {
          unsafe {
              IS_REBOOT = true;
          }
      }

      fn post_injection_check(_manager: * mut Manager, _id: Identifier, _record: * mut Record ) {
          unsafe {
              POST_INJECT_CHECK = true;
          }
      }

      fn set_up() {
          unsafe {
              for i in 0.. NUM_FAULTS {
                  FAULT_RECORDS[i] = Record::const_default();
              }
              let _ = FAULT_MANAGER.init(NUM_FAULTS, &mut FAULT_RECORDS, &MANAGER_NAME, &FAULT_NAMES);
              CALLBACK_STUB_TRUE = Callback {
                  m_call_back_fn: stub_call_true,
                  m_context: ptr::null_mut(),
                  m_next: ptr::null_mut(),
              };
              CALLBACK_STUB_FALSE = Callback {
                  m_call_back_fn: stub_call_false,
                  m_context: ptr::null_mut(),
                  m_next: ptr::null_mut(),
              };
              POST_INJECT_CHECK = false;
              IS_REBOOT = false;
              set_global_context(ptr::addr_of_mut!(GLOBAL_CONTEXT_CHECK));
          }
      }

      #[test]
      fn check_true() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
              assert_eq!(true, POST_INJECT_CHECK);
          }
      }

      #[test]
      fn check_with_id_overrange() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(false, FAULT_MANAGER.check_fault(NUM_FAULTS.try_into().unwrap()));
          }
      }

      #[test]
      fn check_no_callback() {
          set_up();
          unsafe {
              assert_eq!(false, FAULT_MANAGER.check_fault(0));
          }
      }

      #[test]
      fn check_with_false_callback() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_FALSE)).is_ok());
              assert_eq!(false, FAULT_MANAGER.check_fault(0));
              assert_eq!(false, POST_INJECT_CHECK);
          }
      }

      #[test]
      fn check_with_2_callbacks() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_FALSE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
          }
      }

      #[test]
      fn check_true_without_global_context() {
          set_up();
          set_global_context(ptr::null_mut());
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
              assert_eq!(false, POST_INJECT_CHECK);
          }
      }

      #[test]
      fn check_true_without_post_injection_cb() {
          set_up();
          static mut GLOBAL_CONTEXT_EMPTY: GlobalContext = GlobalContext {
              m_cb_table: GlobalCallbackTable {
                  m_reboot_cb: Some(reboot_check),
                  m_post_injection_cb: None,
              }
          };
          unsafe {
              set_global_context(ptr::addr_of_mut!(GLOBAL_CONTEXT_EMPTY));
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
              assert_eq!(false, POST_INJECT_CHECK);
          }
      }

      #[test]
      fn check_true_with_reboot() {
          set_up();
          unsafe {
              let _ = FAULT_MANAGER.reboot_at_fault(0);
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
              assert_eq!(true, IS_REBOOT);
          }
      }

      #[test]
      fn check_false_with_reboot() {
          set_up();
          unsafe {
              let _ = FAULT_MANAGER.reboot_at_fault(0);
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_FALSE)).is_ok());
              assert_eq!(false, FAULT_MANAGER.check_fault(0));
              assert_eq!(false, IS_REBOOT);
          }
      }

      #[test]
      #[should_panic]
      fn check_true_with_reboot_no_global_context() {
          set_up();
          unsafe {
              let _ = FAULT_MANAGER.reboot_at_fault(0);
              set_global_context(ptr::null_mut());
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
          }
      }

      #[test]
      #[should_panic]
      fn check_true_with_reboot_no_reboot_cb() {
          set_up();
          static mut GLOBAL_CONTEXT_EMPTY: GlobalContext = GlobalContext {
              m_cb_table: GlobalCallbackTable {
                  m_reboot_cb: None,
                  m_post_injection_cb: Some(post_injection_check),
              }
          };
          unsafe {
              let _ = FAULT_MANAGER.reboot_at_fault(0);
              set_global_context(ptr::addr_of_mut!(GLOBAL_CONTEXT_EMPTY));
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
          }
      }

      #[test]
      fn check_true_with_empty_out_args() {
          set_up();
          unsafe {
              let out_args: &[i32];
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              let (out_args, ret) = FAULT_MANAGER.check_fault_with_out_args(0);
              assert_eq!(true, ret);
              assert_eq!(0, out_args.len());
          }
      }

      #[test]
      fn check_true_with_out_args() {
          set_up();
          unsafe {
              let out_args: &[i32];
              let _ = FAULT_MANAGER.store_args_at_fault(0, &[1,2,3]);
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              let (out_args, ret) = FAULT_MANAGER.check_fault_with_out_args(0);
              assert_eq!(true, ret);
              assert_eq!(3, out_args.len());
          }
      }

      #[test]
      fn check_false_with_out_args() {
          set_up();
          unsafe {
              let out_args: &[i32];
              let _ = FAULT_MANAGER.store_args_at_fault(0, &[1,2,3]);
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_FALSE)).is_ok());
              let (out_args, ret) = FAULT_MANAGER.check_fault_with_out_args(0);
              assert_eq!(false, ret);
              assert_eq!(0, out_args.len());
          }
      }

      #[test]
      fn reset_counter() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.check_fault(0));
              assert_eq!(1, FAULT_MANAGER.get_fault_records()[0].m_num_times_checked);
              FAULT_MANAGER.reset_fault_counters();
              assert_eq!(0, FAULT_MANAGER.get_fault_records()[0].m_num_times_checked);
          }
      }

      #[test]
      fn reset_configurations() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.reset_configurations(0).is_ok());
              assert_eq!(ptr::addr_of_mut!(S_RANDOM_CB), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }

      #[test]
      fn reset_configurations_with_id_overrange() {
          set_up();
          unsafe {
              assert_eq!(true, FAULT_MANAGER.insert_callback_at_fault(0, ptr::addr_of_mut!(CALLBACK_STUB_TRUE)).is_ok());
              assert_eq!(true, FAULT_MANAGER.reset_configurations(NUM_FAULTS.try_into().unwrap()).is_err());
              assert_eq!(ptr::addr_of_mut!(CALLBACK_STUB_TRUE), FAULT_MANAGER.get_fault_records()[0].m_callback_list);
          }
      }
  }

}
