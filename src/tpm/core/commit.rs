//! Commit random values for split ECC operations, Part 1 clause 44.2.
//!
//! Some ECC schemes need two commands. The first, TPM2_Commit or
//! TPM2_EC_Ephemeral, produces an ephemeral secret and returns points derived
//! from it. The second, a signing command or TPM2_ZGen_2Phase, uses the same
//! secret. Clause 44.2.2 requires that secret to have at least the security
//! strength of the key, to stay inside the TPM, and to be used only once.
//!
//! The secret is not stored. Clause 44.2.2 allows a TPM to derive it instead,
//! by Equation 60:
//!
//! ```text
//! r := KDFa(nameAlg, commitRandom, "ECDAA Commit", name, commitCount, bits)
//! ```
//!
//! so what has to be kept is a nonce chosen at each TPM Reset, a counter, and
//! a bit array recording which counters are still outstanding. That is what
//! this module holds. The low order bits of the counter index the array, and
//! the low order sixteen bits are what the caller is given.
//!
//! Using a commit clears its bit, so the same counter cannot be used twice.

use crate::tpm::config;
use crate::tpm::constants::rc;
use crate::tpm::crypto::hmac::kdfa;
use crate::tpm::crypto::rand::Rng;
use crate::tpm::error::{TpmRc, TpmResult};

/// The label that separates this use of KDFa from every other one.
const LABEL: &str = "ECDAA Commit";

/// Outstanding split operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Commits {
    /// The nonce of Equation 60, new at each TPM Reset.
    random: Vec<u8>,
    /// The counter of Equation 60, zero at each TPM Reset.
    ///
    /// Clause 44.2.5 reconstructs a counter wider than the sixteen bits the
    /// caller is given, so the whole width is kept and derived from. A counter
    /// of sixteen bits would repeat its Equation 60 inputs every 65536
    /// commits, which is exactly what the reconstruction exists to avoid.
    count: u64,
    /// One bit per counter that has been handed out and not yet used.
    used: Vec<u8>,
}

impl Commits {
    pub fn new() -> Commits {
        Commits::default()
    }

    /// Start again with a fresh nonce, which is what a TPM Reset does.
    ///
    /// Every outstanding commit is dropped, because the value it stood for
    /// cannot be derived again once the nonce has changed.
    pub fn reset(&mut self, rng: &mut dyn Rng) -> TpmResult<()> {
        // Clause 44.2.3 wants a nonce of twice the security strength of any
        // ECDAA key the TPM supports, which for P-521 is 256 bits of strength.
        self.random = rng.bytes(config::COMMIT_NONCE_BYTES)?;
        self.count = 0;
        self.used = vec![0u8; config::MAX_COMMIT_SEQUENCES as usize / 8];
        Ok(())
    }

    /// How many split operations may be outstanding at once.
    pub fn capacity(&self) -> u16 {
        config::MAX_COMMIT_SEQUENCES
    }

    /// True when this TPM has been reset and can take a commit.
    pub fn is_ready(&self) -> bool {
        !self.random.is_empty() && !self.used.is_empty()
    }

    /// The array index a counter uses, which is its low order bits.
    fn index(counter: u64) -> usize {
        (counter as usize) & (config::MAX_COMMIT_SEQUENCES as usize - 1)
    }

    fn is_set(&self, counter: u64) -> bool {
        let i = Commits::index(counter);
        self.used.get(i / 8).map(|b| b & (1 << (i % 8)) != 0) == Some(true)
    }

    fn set(&mut self, counter: u64, on: bool) {
        let i = Commits::index(counter);
        if let Some(b) = self.used.get_mut(i / 8) {
            if on {
                *b |= 1 << (i % 8);
            } else {
                *b &= !(1 << (i % 8));
            }
        }
    }

    /// Equation 60. `bits` is the bit count of the curve order.
    fn derive(&self, name_alg: u16, name: &[u8], counter: u64, bits: u32) -> TpmResult<Vec<u8>> {
        if !self.is_ready() {
            return Err(TpmRc(rc::NO_RESULT));
        }
        // The counter is the context of the derivation, so two commits under
        // the same key give different values.
        kdfa(
            name_alg,
            &self.random,
            LABEL,
            name,
            &counter.to_be_bytes(),
            bits,
        )
    }

    /// The value the next commit would use, and the counter naming it.
    ///
    /// Nothing is recorded. Part 1 clause 44.2.3 assigns the counter in step
    /// 13 and advances it in step 14, after step 12 has had its chance to
    /// fail, so a caller derives here and calls [`Commits::take`] only once
    /// everything else has succeeded.
    pub fn next(&self, name_alg: u16, name: &[u8], bits: u32) -> TpmResult<(Vec<u8>, u16)> {
        if !self.is_ready() {
            return Err(TpmRc(rc::NO_RESULT));
        }
        // Counters are issued in order, so the slot a new one takes is held
        // only by the counter exactly one turn of the array behind it. That
        // one has already fallen outside the window of clause 44.2.5 and can
        // no longer be used, so taking its slot loses nothing. Clause 44.2.3
        // has no answer for a full array, and with the window check there is
        // no such thing.
        let r = self.derive(name_alg, name, self.count, bits)?;
        Ok((r, self.count as u16))
    }

    /// Record the counter [`Commits::next`] reported, which is steps 13 and 14.
    pub fn take(&mut self, counter: u16) {
        debug_assert_eq!(counter, self.count as u16);
        self.set(self.count, true);
        self.count = self.count.wrapping_add(1);
    }

    /// The full width counter a sixteen bit one names, per clause 44.2.5.
    ///
    /// ```text
    /// 1. set t := low-order 16 bits of commitCount
    /// 2. verify that t - 2^N < counter < t else return TPM_RC_RANGE
    /// ```
    ///
    /// A counter outside that window is one the array no longer speaks for.
    /// Without the check a counter from an earlier turn of the array would
    /// pass, because its slot may have been set again by a newer commit, and
    /// the value it derived would be one that had already been used. Two ECDAA
    /// signatures over the same commit value give away the private key, so
    /// this check is what keeps a commit to a single use.
    fn full_counter(&self, counter: u16) -> TpmResult<u64> {
        let t = self.count as u16;
        let age = t.wrapping_sub(counter);
        if age == 0 || age as u32 >= config::MAX_COMMIT_SEQUENCES as u32 {
            return Err(TpmRc(rc::RANGE));
        }
        // Steps 5 to 7 rebuild the wider counter, which is the current one
        // less however far back the caller reached.
        Ok(self.count - age as u64)
    }

    /// Recover the value for a counter and spend it.
    ///
    /// Part 1 clause 44.2.2 allows a commit to be used once, so the bit is
    /// cleared here and a second attempt with the same counter fails.
    pub fn use_counter(
        &mut self,
        name_alg: u16,
        name: &[u8],
        counter: u16,
        bits: u32,
    ) -> TpmResult<Vec<u8>> {
        let full = self.full_counter(counter)?;
        // Step 4.
        if !self.is_set(full) {
            return Err(TpmRc(rc::VALUE));
        }
        let r = self.derive(name_alg, name, full, bits)?;
        // Step 9.
        self.set(full, false);
        Ok(r)
    }

    /// Recover the value for a counter without spending it.
    pub fn peek(&self, name_alg: u16, name: &[u8], counter: u16, bits: u32) -> TpmResult<Vec<u8>> {
        let full = self.full_counter(counter)?;
        if !self.is_set(full) {
            return Err(TpmRc(rc::VALUE));
        }
        self.derive(name_alg, name, full, bits)
    }

    /// How many commits are waiting to be used.
    pub fn outstanding(&self) -> usize {
        self.used.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// The nonce and counter, so the state file can carry them.
    pub fn parts(&self) -> (&[u8], u64, &[u8]) {
        (&self.random, self.count, &self.used)
    }

    /// Put back what [`Commits::parts`] reported.
    pub fn restore(&mut self, random: Vec<u8>, count: u64, used: Vec<u8>) {
        self.random = random;
        self.count = count;
        self.used = used;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;
    use crate::tpm::crypto::rand::Drbg;

    fn commits() -> Commits {
        let mut rng = Drbg::new(&[0x42u8; 48], b"commit test").unwrap();
        let mut c = Commits::new();
        c.reset(&mut rng).unwrap();
        c
    }

    /// Derive and record in one step, which is what a command does once its
    /// own work has succeeded.
    fn issue(c: &mut Commits, name: &[u8]) -> (Vec<u8>, u16) {
        let (r, counter) = c.next(alg::SHA256, name, 256).unwrap();
        c.take(counter);
        (r, counter)
    }

    #[test]
    fn a_commit_gives_a_value_that_can_be_recovered_once() {
        let mut c = commits();
        let name = b"a name";
        let (r, counter) = issue(&mut c, name);
        assert_eq!(r.len(), 32);
        assert_eq!(counter, 0);
        assert_eq!(c.outstanding(), 1);

        let again = c.use_counter(alg::SHA256, name, counter, 256).unwrap();
        assert_eq!(again, r);
        assert_eq!(c.outstanding(), 0);

        // Part 1 clause 44.2.2 allows one use, so a second is refused.
        assert_eq!(
            c.use_counter(alg::SHA256, name, counter, 256).unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }

    #[test]
    fn each_commit_gives_a_different_value() {
        let mut c = commits();
        let name = b"a name";
        let (r0, c0) = issue(&mut c, name);
        let (r1, c1) = issue(&mut c, name);
        assert_ne!(c0, c1);
        assert_ne!(r0, r1);
        let other = c.peek(alg::SHA256, b"another name", c0, 256).unwrap();
        assert_ne!(other, r0);
    }

    #[test]
    fn a_counter_that_was_never_committed_is_refused() {
        let mut c = commits();
        issue(&mut c, b"n");
        // Inside the window but never handed out.
        assert_eq!(
            c.use_counter(alg::SHA256, b"n", 1, 256).unwrap_err(),
            TpmRc(rc::RANGE)
        );
    }

    #[test]
    fn a_counter_from_an_earlier_turn_of_the_array_is_refused() {
        // The heart of clause 44.2.5 step 2. Counter 0 is used, the counter
        // walks all the way round, and counter 128 lands on the same slot.
        // Replaying counter 0 must not recover the value counter 0 had, or
        // two signatures would share a commit value and give away the key.
        let mut c = commits();
        let name = b"a name";
        let (r0, zero) = issue(&mut c, name);
        assert_eq!(zero, 0);
        c.use_counter(alg::SHA256, name, zero, 256).unwrap();

        // Walk the counter round until it comes back to slot zero.
        for _ in 0..config::MAX_COMMIT_SEQUENCES - 1 {
            let (_, n) = issue(&mut c, name);
            c.use_counter(alg::SHA256, name, n, 256).unwrap();
        }
        // Counter 128 shares slot 0 with counter 0.
        let (r128, one_two_eight) = issue(&mut c, name);
        assert_eq!(one_two_eight, config::MAX_COMMIT_SEQUENCES);
        assert_ne!(r128, r0);

        // Replaying counter 0 is outside the window and is refused, even
        // though its slot is set by the newer commit.
        assert_eq!(
            c.use_counter(alg::SHA256, name, 0, 256).unwrap_err(),
            TpmRc(rc::RANGE),
            "a stale counter reached a live slot"
        );
        // The newer commit is untouched by the attempt.
        assert_eq!(c.outstanding(), 1);
        assert_eq!(
            c.use_counter(alg::SHA256, name, one_two_eight, 256).unwrap(),
            r128
        );
    }

    #[test]
    fn the_window_is_the_counters_just_behind_the_current_one() {
        let mut c = commits();
        for _ in 0..10 {
            issue(&mut c, b"n");
        }
        // The current counter has not been handed out.
        assert_eq!(
            c.use_counter(alg::SHA256, b"n", 10, 256).unwrap_err(),
            TpmRc(rc::RANGE)
        );
        // One beyond it is not either.
        assert_eq!(
            c.use_counter(alg::SHA256, b"n", 11, 256).unwrap_err(),
            TpmRc(rc::RANGE)
        );
        // The ones behind it are in the window and were handed out.
        assert!(c.use_counter(alg::SHA256, b"n", 9, 256).is_ok());
        assert!(c.use_counter(alg::SHA256, b"n", 0, 256).is_ok());
    }

    #[test]
    fn a_reset_drops_every_outstanding_commit() {
        let mut rng = Drbg::new(&[0x11u8; 48], b"t").unwrap();
        let mut c = commits();
        let (r, counter) = issue(&mut c, b"n");
        assert_eq!(c.outstanding(), 1);
        c.reset(&mut rng).unwrap();
        assert_eq!(c.outstanding(), 0);
        assert!(c.use_counter(alg::SHA256, b"n", counter, 256).is_err());
        let (again, _) = issue(&mut c, b"n");
        assert_ne!(again, r);
    }

    #[test]
    fn the_oldest_slot_gives_way_rather_than_jamming() {
        // A full array is not an error. The slot a new counter needs belongs
        // to the counter one turn behind, which the window has already put
        // out of reach, so committing always works and the oldest is what
        // gives way.
        let mut c = commits();
        for _ in 0..config::MAX_COMMIT_SEQUENCES {
            issue(&mut c, b"n");
        }
        assert_eq!(c.outstanding(), config::MAX_COMMIT_SEQUENCES as usize);
        // Counter 0 is exactly one turn behind and is no longer usable.
        assert_eq!(
            c.use_counter(alg::SHA256, b"n", 0, 256).unwrap_err(),
            TpmRc(rc::RANGE)
        );
        // Committing still works, and takes the slot counter 0 held.
        let (_, next) = issue(&mut c, b"n");
        assert_eq!(next, config::MAX_COMMIT_SEQUENCES);
        // The one just behind the new counter is still good.
        assert!(c.use_counter(alg::SHA256, b"n", next, 256).is_ok());
    }

    #[test]
    fn nothing_is_recorded_until_it_is_taken() {
        // Part 1 clause 44.2.3 assigns the counter in step 13, after step 12
        // has had its chance to fail. A command that gave up between the two
        // must leave no trace.
        let mut c = commits();
        let (r, counter) = c.next(alg::SHA256, b"n", 256).unwrap();
        assert_eq!(c.outstanding(), 0, "next must not record anything");
        // Asking again gives the same answer, because nothing moved.
        let (again, same) = c.next(alg::SHA256, b"n", 256).unwrap();
        assert_eq!((r, counter), (again, same));
        c.take(counter);
        assert_eq!(c.outstanding(), 1);
    }

    #[test]
    fn a_generator_that_has_not_been_reset_produces_nothing() {
        let c = Commits::new();
        assert!(!c.is_ready());
        assert!(c.next(alg::SHA256, b"n", 256).is_err());
    }

    #[test]
    fn the_state_survives_a_round_trip() {
        let mut c = commits();
        let (r, counter) = issue(&mut c, b"n");
        let (random, count, used) = c.parts();
        let (random, count, used) = (random.to_vec(), count, used.to_vec());

        let mut back = Commits::new();
        back.restore(random, count, used);
        assert!(back.is_ready());
        assert_eq!(back.outstanding(), 1);
        assert_eq!(back.use_counter(alg::SHA256, b"n", counter, 256).unwrap(), r);
    }
}
