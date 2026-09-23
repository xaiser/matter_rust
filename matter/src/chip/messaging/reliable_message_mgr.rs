use crate::{
    chip::{
        messaging::{
            reliable_message_context::ReliableMessageContext,
        },
    },
    chip_static_assert,
};
use core::time::Duration;

// TODO: make this config-able
static ADDITIONAL_MRP_BACKOFF_TIME: Duration = Duration::from_millis(1);

pub struct ReliableMessageMgr;

pub mod shared {
    use super::ReliableMessageMgr;
    use core::cell::{RefCell, Ref, RefMut};
    pub struct SharedReliableMessageMgr<'a> {
        m_inner: &'a RefCell<ReliableMessageMgr>,
    }

    impl SharedReliableMessageMgr<'_> {
        pub fn get(&self) -> Ref<'_, ReliableMessageMgr> {
            self.m_inner.borrow()
        }

        pub fn get_mut(&self) -> RefMut<'_, ReliableMessageMgr> {
            self.m_inner.borrow_mut()
        }
    }
}

pub type SharedReliableMessageMgr = shared::SharedReliableMessageMgr<'static>;

impl ReliableMessageMgr {
    /*
     *  Iterate through active exchange contexts and retrans table entries. Clear the entry matching
     *  the specified ExchangeContext and the message ID from the retransmision table.
     */
    pub fn check_and_rem_retrans_table<Context: ReliableMessageContext>(&mut self, _rc: &mut Context, _ack_message_counter: u32) -> bool {
        false
    }

    pub fn get_backoff(base_interval: Duration, send_count: u8, compute_max_possible: bool) -> Duration {
        // See section "4.11.8. Parameters and Constants" for the parameters below:
        // MRP_BACKOFF_JITTER = 0.25
        const MRP_BACKOFF_JITTER_BASE: u32 = 1024;
        // MRP_BACKOFF_MARGIN = 1.1
        const MRP_BACKOFF_MARGIN_NUMERATOR: u32 = 1127;
        const MRP_BACKOFF_MARGIN_DENOMINATOR: u32 = 1024;
        // MRP_BACKOFF_BASE = 1.6
        const MRP_BACKOFF_BASE_NUMERATOR: u32 = 16;
        const MRP_BACKOFF_BASE_DENOMINATOR: u32 = 10;
        const MRP_BACKOFF_THRESHOLD: i32 = 1;

        // Implement `i = MRP_BACKOFF_MARGIN * i` from section "4.12.2.1. Retransmissions", where:
        //   i == interval
        let mut interval = base_interval;

        interval = interval.saturating_mul(MRP_BACKOFF_MARGIN_NUMERATOR);

        // since DENOMINATOR is never 0, just unwrap()
        chip_static_assert!(MRP_BACKOFF_MARGIN_DENOMINATOR != 0);
        interval = interval.checked_div(MRP_BACKOFF_MARGIN_DENOMINATOR).unwrap();

        // Implement:
        //   mrpBackoffTime = i * MRP_BACKOFF_BASE^(max(0,n-MRP_BACKOFF_THRESHOLD)) * (1.0 + random(0,1) * MRP_BACKOFF_JITTER)
        // from section "4.12.2.1. Retransmissions", where:
        //   i == interval
        //   n == sendCount
        
        // 1. Calculate exponent `max(0,n−MRP_BACKOFF_THRESHOLD)`
        let exponent = {
            let mut exp = (send_count as i32) - MRP_BACKOFF_THRESHOLD;
            if exp < 0 {
                exp = 0; // Enforece floor
            }
            if exp > 4 {
                exp = 4; // Enforce reasonable maximum after 5 tries
            }

            exp
        };

        // 2. Calculate `mrpBackoffTime = i * MRP_BACKOFF_BASE^(max(0,n-MRP_BACKOFF_THRESHOLD))`
        let mut backoff_num: u32 = 1;
        let mut backoff_denom: u32 = 1;

        for _ in 0..exponent {
            backoff_num *= MRP_BACKOFF_BASE_NUMERATOR;
            backoff_denom *= MRP_BACKOFF_BASE_DENOMINATOR;
        }

        // since exponent is in the rang (0..4), backoff_denom will neven be 0.
        let mut mrp_backoff_time = interval.saturating_mul(backoff_num).checked_div(backoff_denom).unwrap();

        // 3. Calculate `mrpBackoffTime *= (1.0 + random(0,1) * MRP_BACKOFF_JITTER)`
        let jitter: u32 = {
            let rand = if compute_max_possible {
                u8::MAX
            } else {
                crate::chip::crypto::get_rand_u8()
            };

            MRP_BACKOFF_JITTER_BASE + rand as u32
        };

        chip_static_assert!(MRP_BACKOFF_JITTER_BASE != 0);
        mrp_backoff_time = mrp_backoff_time.saturating_mul(jitter).checked_div(MRP_BACKOFF_JITTER_BASE).unwrap().saturating_add(ADDITIONAL_MRP_BACKOFF_TIME);

        mrp_backoff_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_time_base_case() {
        assert!(
            Duration::from_micros(2375).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(1), 0, true)).as_millis() < 5);
        assert!(
            Duration::from_micros(2375).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(1), 1, true)).as_millis() < 5);
        assert!(
            Duration::from_micros(6632).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(1), 4, true)).as_millis() < 5);
        assert!(
            Duration::from_micros(6632).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(1), 5, true)).as_millis() < 5);
        assert!(
            Duration::from_micros(3750).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(2), 0, true)).as_millis() < 5);
        assert!(
            Duration::from_micros(12264).abs_diff(
                ReliableMessageMgr::get_backoff(Duration::from_millis(2), 4, true)).as_millis() < 5);
    }
} // end of tests
