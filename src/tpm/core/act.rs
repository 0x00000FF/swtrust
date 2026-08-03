//! The Authenticated Countdown Timer, Part 1 clause 40.
//!
//! An ACT is a 32 bit counter that decrements once per second while the TPM is
//! powered, and signals when it reaches zero. A platform uses one as a watchdog:
//! something outside the TPM has to keep setting the timeout anew, and if it
//! stops doing so the timer expires and the platform acts on it.
//!
//! The PC Client Platform TPM Profile 1.07 clause 5.1.2 asks a TPM that
//! implements TPM2_ACT_SetTimeout to support one instance, so there is one here
//! and it answers to TPM_RH_ACT_0.

use crate::tpm::constants::alg;
use crate::tpm::structures::attributes::ActAttributes;
use crate::tpm::structures::base::TpmtHa;

/// The value that clears a signal without starting a new countdown.
///
/// Part 3 clause 33.2.1: "When ACT Timeout is zero and the signaled attribute is
/// SET, writing a startTimeout of FF FF FF FF will clear signaled and stop the
/// counting."
pub const CLEAR_SIGNALED: u32 = u32::MAX;

/// One authenticated countdown timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Act {
    /// Seconds remaining. Zero means the timer is not counting.
    timeout: u32,
    /// TPMA_ACT.signaled.
    signaled: bool,
    /// TPMA_ACT.preserveSignaled.
    preserve_signaled: bool,
    /// Milliseconds counted towards the next whole second.
    fraction: u64,
    /// True once TPM2_ACT_SetTimeout has been used since the last startup.
    ///
    /// Part 1 clause 40.2 saves the whole timeout across an orderly shutdown
    /// when this is set, and half of it when it is not.
    written: bool,
    /// The ACT specific authorization policy, set by TPM2_SetPrimaryPolicy.
    pub policy: TpmtHa,
}

impl Default for Act {
    fn default() -> Self {
        Act {
            timeout: 0,
            signaled: false,
            preserve_signaled: false,
            fraction: 0,
            written: false,
            policy: TpmtHa::null(),
        }
    }
}

impl Act {
    /// Seconds remaining before the timer expires.
    pub fn timeout(&self) -> u32 {
        self.timeout
    }

    pub fn signaled(&self) -> bool {
        self.signaled
    }

    pub fn preserve_signaled(&self) -> bool {
        self.preserve_signaled
    }

    /// The TPMA_ACT this timer reports.
    pub fn attributes(&self) -> ActAttributes {
        let mut bits = 0u32;
        if self.signaled {
            bits |= ActAttributes::SIGNALED;
        }
        if self.preserve_signaled {
            bits |= ActAttributes::PRESERVE_SIGNALED;
        }
        ActAttributes(bits)
    }

    /// Let `millis` of powered time pass.
    ///
    /// Clause 40.2: the counter "will decrement by one each second that the TPM
    /// is powered". Reaching zero by decrementing is a signal; a timer that is
    /// already zero stays put and signals nothing.
    pub fn advance(&mut self, millis: u64) {
        if self.timeout == 0 {
            return;
        }
        self.fraction += millis;
        let seconds = self.fraction / 1000;
        self.fraction %= 1000;
        if seconds == 0 {
            return;
        }
        let seconds = u32::try_from(seconds).unwrap_or(u32::MAX);
        if seconds >= self.timeout {
            self.timeout = 0;
            self.signaled = true;
        } else {
            self.timeout -= seconds;
        }
    }

    /// TPM2_ACT_SetTimeout, Part 3 clause 33.2.1.
    ///
    /// The clause gives four states for the pair of the current timeout and the
    /// requested one, and each decides what happens to `signaled`.
    pub fn set_timeout(&mut self, start: u32) {
        self.written = true;
        self.fraction = 0;
        // The value that clears a signal is a request to stop, not a request to
        // count for that many seconds. Clause 33.2.1 asks for all three of a
        // stopped timer, a set signal and that value; with the signal clear it
        // is an ordinary non-zero timeout and starts a countdown.
        if start == CLEAR_SIGNALED && self.timeout == 0 && self.signaled {
            self.signaled = false;
            self.preserve_signaled = false;
            return;
        }
        match (self.timeout == 0, start == 0) {
            // 1) zero and non-zero, and 2) non-zero and non-zero.
            (_, false) => self.signaled = false,
            // 3) zero and zero leaves it as it was.
            (true, true) => {}
            // 4) non-zero and zero signals, because the timer went to zero.
            (false, true) => self.signaled = true,
        }
        self.timeout = start;
        // "When this command is successful, preserveSignaled will be CLEAR."
        self.preserve_signaled = false;
    }

    /// TPM Reset or TPM Restart, clause 40.2.
    ///
    /// "all ACT timeouts are set to zero with no side effects (no event
    /// triggered)", and Part 2 Table 46 clears both attributes and clause 40.2
    /// returns the policy to an Empty Policy.
    pub fn on_reset(&mut self) {
        self.timeout = 0;
        self.signaled = false;
        self.preserve_signaled = false;
        self.fraction = 0;
        self.written = false;
        self.policy = TpmtHa::null();
    }

    /// TPM Resume, clause 40.2 and Part 2 Table 46.
    ///
    /// The timeout, the signal and the policy all survive, and the signal is
    /// copied into preserveSignaled so a caller can tell that a reset may have
    /// been caused by this timer expiring.
    pub fn on_resume(&mut self) {
        self.preserve_signaled = self.signaled;
        self.written = false;
        self.fraction = 0;
    }

    /// The timeout TPM2_Shutdown(TPM_SU_STATE) writes out.
    ///
    /// Clause 40.2: the current timeout when TPM2_ACT_SetTimeout has been used
    /// since the last startup, and half of it otherwise, which stops a caller
    /// extending the timer for ever by shutting down and starting up again.
    pub fn saved_timeout(&self) -> u32 {
        if self.written {
            self.timeout
        } else {
            self.timeout / 2
        }
    }

    /// Restore a timeout saved by an orderly shutdown.
    pub fn restore(&mut self, timeout: u32, signaled: bool) {
        self.timeout = timeout;
        self.signaled = signaled;
        self.fraction = 0;
        self.written = false;
    }

    /// True when the policy is an Empty Policy.
    pub fn has_no_policy(&self) -> bool {
        self.policy.hash_alg == alg::NULL || self.policy.digest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timer_counts_down_one_second_at_a_time() {
        let mut a = Act::default();
        a.set_timeout(3);
        assert_eq!(a.timeout(), 3);
        a.advance(999);
        assert_eq!(a.timeout(), 3, "less than a second changes nothing");
        a.advance(1);
        assert_eq!(a.timeout(), 2);
        a.advance(2000);
        assert_eq!(a.timeout(), 0);
        assert!(a.signaled(), "reaching zero is a signal");
    }

    #[test]
    fn a_timer_that_is_already_zero_neither_counts_nor_signals() {
        let mut a = Act::default();
        a.advance(10_000);
        assert_eq!(a.timeout(), 0);
        assert!(!a.signaled());
    }

    /// Part 3 clause 33.2.1 lists four states, and each is checked here.
    #[test]
    fn setting_a_timeout_follows_the_four_states() {
        // 1) zero and non-zero: signaled CLEAR.
        let mut a = Act::default();
        a.set_timeout(5);
        a.advance(5000);
        assert!(a.signaled());
        a.set_timeout(7);
        assert!(!a.signaled());
        assert_eq!(a.timeout(), 7);

        // 2) non-zero and non-zero: signaled CLEAR.
        a.set_timeout(9);
        assert!(!a.signaled());

        // 4) non-zero and zero: signaled SET.
        a.set_timeout(0);
        assert!(a.signaled());
        assert_eq!(a.timeout(), 0);

        // 3) zero and zero: unchanged.
        a.set_timeout(0);
        assert!(a.signaled());
    }

    #[test]
    fn the_clearing_value_stops_the_timer_without_starting_it() {
        let mut a = Act::default();
        a.set_timeout(1);
        a.advance(1000);
        assert!(a.signaled());
        a.set_timeout(CLEAR_SIGNALED);
        assert!(!a.signaled(), "the signal is cleared");
        assert_eq!(a.timeout(), 0, "and no new countdown is started");
    }

    /// Clause 33.2.1 asks for a stopped timer, a set signal and the value. With
    /// the signal clear it is an ordinary timeout, which state 1 of the same
    /// clause starts.
    #[test]
    fn the_clearing_value_starts_a_countdown_when_nothing_has_signalled() {
        let mut a = Act::default();
        assert!(!a.signaled());
        a.set_timeout(CLEAR_SIGNALED);
        assert_eq!(a.timeout(), CLEAR_SIGNALED, "state 1 starts the countdown");
        assert!(!a.signaled());

        // A running timer takes it as a timeout too, which is state 2.
        let mut a = Act::default();
        a.set_timeout(5);
        a.set_timeout(CLEAR_SIGNALED);
        assert_eq!(a.timeout(), CLEAR_SIGNALED);
        assert!(!a.signaled());
    }

    #[test]
    fn a_reset_clears_everything_without_signalling() {
        let mut a = Act::default();
        a.set_timeout(30);
        a.on_reset();
        assert_eq!(a.timeout(), 0);
        assert!(!a.signaled(), "a reset triggers no event");
        assert!(!a.preserve_signaled());
    }

    #[test]
    fn a_resume_copies_the_signal_into_the_preserved_one() {
        let mut a = Act::default();
        a.set_timeout(1);
        a.advance(1000);
        assert!(a.signaled());
        a.on_resume();
        assert!(a.preserve_signaled());
        assert!(a.signaled(), "the signal itself survives a resume");
    }

    #[test]
    fn half_the_timeout_is_saved_when_it_was_not_set_since_startup() {
        let mut a = Act::default();
        a.set_timeout(100);
        assert_eq!(a.saved_timeout(), 100, "set since startup, so all of it");
        a.on_resume();
        assert_eq!(a.saved_timeout(), 50, "otherwise half");
    }

    #[test]
    fn a_successful_set_clears_the_preserved_signal() {
        let mut a = Act::default();
        a.set_timeout(1);
        a.advance(1000);
        a.on_resume();
        assert!(a.preserve_signaled());
        a.set_timeout(10);
        assert!(!a.preserve_signaled());
    }
}
