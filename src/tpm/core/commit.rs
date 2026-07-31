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
    count: u16,
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
    fn index(counter: u16) -> usize {
        (counter as usize) & (config::MAX_COMMIT_SEQUENCES as usize - 1)
    }

    fn is_set(&self, counter: u16) -> bool {
        let i = Commits::index(counter);
        self.used.get(i / 8).map(|b| b & (1 << (i % 8)) != 0) == Some(true)
    }

    fn set(&mut self, counter: u16, on: bool) {
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
    fn derive(&self, name_alg: u16, name: &[u8], counter: u16, bits: u32) -> TpmResult<Vec<u8>> {
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

    /// Take the next counter and the value that goes with it.
    ///
    /// The counter is marked outstanding, so [`Commits::use_counter`] will
    /// accept it once.
    pub fn commit(&mut self, name_alg: u16, name: &[u8], bits: u32) -> TpmResult<(Vec<u8>, u16)> {
        if !self.is_ready() {
            return Err(TpmRc(rc::NO_RESULT));
        }
        // A counter whose slot is still outstanding would overwrite a commit
        // the caller has not finished with, so the array being full is
        // reported rather than silently wrapping over it.
        if self.outstanding() >= config::MAX_COMMIT_SEQUENCES as usize {
            return Err(TpmRc(rc::MEMORY));
        }
        while self.is_set(self.count) {
            self.count = self.count.wrapping_add(1);
        }
        let counter = self.count;
        let r = self.derive(name_alg, name, counter, bits)?;
        self.set(counter, true);
        self.count = self.count.wrapping_add(1);
        Ok((r, counter))
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
        if !self.is_set(counter) {
            return Err(TpmRc(rc::VALUE));
        }
        let r = self.derive(name_alg, name, counter, bits)?;
        self.set(counter, false);
        Ok(r)
    }

    /// Recover the value for a counter without spending it.
    pub fn peek(
        &self,
        name_alg: u16,
        name: &[u8],
        counter: u16,
        bits: u32,
    ) -> TpmResult<Vec<u8>> {
        if !self.is_set(counter) {
            return Err(TpmRc(rc::VALUE));
        }
        self.derive(name_alg, name, counter, bits)
    }

    /// How many commits are waiting to be used.
    pub fn outstanding(&self) -> usize {
        self.used.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// The nonce and counter, so the state file can carry them.
    pub fn parts(&self) -> (&[u8], u16, &[u8]) {
        (&self.random, self.count, &self.used)
    }

    /// Put back what [`Commits::parts`] reported.
    pub fn restore(&mut self, random: Vec<u8>, count: u16, used: Vec<u8>) {
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

    #[test]
    fn a_commit_gives_a_value_that_can_be_recovered_once() {
        let mut c = commits();
        let name = b"a name";
        let (r, counter) = c.commit(alg::SHA256, name, 256).unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(counter, 0);
        assert_eq!(c.outstanding(), 1);

        // The same counter gives the same value back.
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
        let (r0, c0) = c.commit(alg::SHA256, name, 256).unwrap();
        let (r1, c1) = c.commit(alg::SHA256, name, 256).unwrap();
        assert_ne!(c0, c1);
        assert_ne!(r0, r1);
        // A different key Name gives a different value for the same counter.
        let other = c.peek(alg::SHA256, b"another name", c0, 256).unwrap();
        assert_ne!(other, r0);
    }

    #[test]
    fn a_counter_that_was_never_committed_is_refused() {
        let mut c = commits();
        assert_eq!(
            c.use_counter(alg::SHA256, b"n", 7, 256).unwrap_err(),
            TpmRc(rc::VALUE)
        );
        assert_eq!(c.peek(alg::SHA256, b"n", 7, 256).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn a_reset_drops_every_outstanding_commit() {
        let mut rng = Drbg::new(&[0x11u8; 48], b"t").unwrap();
        let mut c = commits();
        let (r, counter) = c.commit(alg::SHA256, b"n", 256).unwrap();
        assert_eq!(c.outstanding(), 1);
        c.reset(&mut rng).unwrap();
        assert_eq!(c.outstanding(), 0);
        // The value cannot be recovered, because the nonce it came from is
        // gone. That is what makes a commit survive no longer than the reset.
        assert!(c.use_counter(alg::SHA256, b"n", counter, 256).is_err());
        let (again, _) = c.commit(alg::SHA256, b"n", 256).unwrap();
        assert_ne!(again, r);
    }

    #[test]
    fn the_array_fills_and_says_so() {
        let mut c = commits();
        for _ in 0..config::MAX_COMMIT_SEQUENCES {
            c.commit(alg::SHA256, b"n", 256).unwrap();
        }
        assert_eq!(c.outstanding(), config::MAX_COMMIT_SEQUENCES as usize);
        assert_eq!(
            c.commit(alg::SHA256, b"n", 256).unwrap_err(),
            TpmRc(rc::MEMORY)
        );
        // Spending one makes room again.
        c.use_counter(alg::SHA256, b"n", 0, 256).unwrap();
        assert!(c.commit(alg::SHA256, b"n", 256).is_ok());
    }

    #[test]
    fn a_counter_wraps_onto_a_free_slot_rather_than_a_used_one() {
        let mut c = commits();
        // Take one, leave it outstanding, then walk the counter all the way
        // round. The slot that is still in use must not be handed out again.
        let (_, kept) = c.commit(alg::SHA256, b"n", 256).unwrap();
        for _ in 0..config::MAX_COMMIT_SEQUENCES - 1 {
            let (_, got) = c.commit(alg::SHA256, b"n", 256).unwrap();
            assert_ne!(got, kept, "a slot still in use was handed out");
        }
    }

    #[test]
    fn a_generator_that_has_not_been_reset_produces_nothing() {
        let mut c = Commits::new();
        assert!(!c.is_ready());
        assert!(c.commit(alg::SHA256, b"n", 256).is_err());
    }
}
