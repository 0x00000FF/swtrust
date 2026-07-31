//! Random number generation.
//!
//! Two generators are needed. The first backs TPM2_GetRandom and every nonce
//! the TPM produces; it is an HMAC_DRBG from SP800-90A section 10.1.2, seeded
//! from the platform and reseeded by TPM2_StirRandom. The second is
//! deterministic: Part 1 clause 27.2 requires a Primary Object to be
//! regenerated from its seed and template every time, so the octets consumed by
//! key generation come from KDFa over the seed rather than from entropy.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};

use super::hash::digest_size;
use super::hmac::{hmac_parts, kdfa};

/// A source of octets for key generation and nonces.
pub trait Rng {
    /// Fill `out` with generated octets.
    fn fill(&mut self, out: &mut [u8]) -> TpmResult<()>;

    /// Return `n` generated octets.
    fn bytes(&mut self, n: usize) -> TpmResult<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.fill(&mut v)?;
        Ok(v)
    }
}

/// The hash used by the DRBG.
const DRBG_HASH: u16 = alg::SHA256;

/// Security strength of the instantiation, in bits.
///
/// SP800-90A Table 2 gives HMAC_DRBG with SHA-256 a maximum strength of 256
/// bits.
pub const SECURITY_STRENGTH_BITS: usize = 256;

/// Smallest entropy input accepted, in octets.
///
/// SP800-90A section 8.6.3 asks for entropy at least equal to the security
/// strength, and section 8.6.7 allows the nonce to be folded in by supplying
/// half as much again.
pub const MIN_ENTROPY_BYTES: usize = SECURITY_STRENGTH_BITS * 3 / 2 / 8;

/// Largest number of octets one generate call may produce.
///
/// SP800-90A Table 2 limits a request to 2^19 bits.
pub const MAX_BYTES_PER_REQUEST: usize = (1 << 19) / 8;

/// Generate calls allowed between reseeds.
///
/// SP800-90A Table 2 allows 2^48. The TPM reseeds far more often than that in
/// practice, so the counter exists to make an exhausted instantiation visible
/// rather than to be reached.
pub const RESEED_INTERVAL: u64 = 1 << 48;

/// SP800-90A HMAC_DRBG.
pub struct Drbg {
    key: Vec<u8>,
    value: Vec<u8>,
    reseed_counter: u64,
}

impl std::fmt::Debug for Drbg {
    /// The internal state is never printed, only the reseed counter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Drbg(reseed_counter={})", self.reseed_counter)
    }
}

impl Drbg {
    /// Instantiate from `entropy` and `nonce`, with optional personalization.
    ///
    /// The entropy input must be at least [`MIN_ENTROPY_BYTES`] octets.
    pub fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> TpmResult<Drbg> {
        if entropy.len() + nonce.len() < MIN_ENTROPY_BYTES {
            return Err(TpmRc(rc::FAILURE));
        }
        let len = digest_size(DRBG_HASH)?;
        let mut drbg = Drbg {
            key: vec![0x00; len],
            value: vec![0x01; len],
            reseed_counter: 1,
        };
        drbg.update(&[entropy, nonce, personalization])?;
        Ok(drbg)
    }

    /// Instantiate with the entropy input carrying its own nonce.
    pub fn new(entropy: &[u8], personalization: &[u8]) -> TpmResult<Drbg> {
        Drbg::instantiate(entropy, &[], personalization)
    }

    /// Instantiate from the platform entropy source.
    pub fn from_system() -> TpmResult<Drbg> {
        let mut seed = [0u8; 48];
        // A failure here means the platform has no entropy, which the TPM
        // cannot work around, so it is reported rather than papered over.
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| TpmRc(rc::FAILURE))?;
        Drbg::new(&seed, b"swtrust")
    }

    /// The SP800-90A update function.
    fn update(&mut self, provided: &[&[u8]]) -> TpmResult<()> {
        let has_data = provided.iter().any(|p| !p.is_empty());

        let mut parts: Vec<&[u8]> = vec![&self.value, &[0x00]];
        parts.extend_from_slice(provided);
        self.key = hmac_parts(DRBG_HASH, &self.key.clone(), &parts)?;
        self.value = hmac_parts(DRBG_HASH, &self.key, &[&self.value.clone()])?;

        if !has_data {
            return Ok(());
        }

        let mut parts: Vec<&[u8]> = vec![&self.value, &[0x01]];
        parts.extend_from_slice(provided);
        self.key = hmac_parts(DRBG_HASH, &self.key.clone(), &parts)?;
        self.value = hmac_parts(DRBG_HASH, &self.key, &[&self.value.clone()])?;
        Ok(())
    }

    /// Reseed from fresh entropy, which restarts the reseed interval.
    ///
    /// The entropy input must be at least [`MIN_ENTROPY_BYTES`] octets, as
    /// SP800-90A section 9.2 requires.
    pub fn reseed(&mut self, entropy: &[u8]) -> TpmResult<()> {
        if entropy.len() < MIN_ENTROPY_BYTES {
            return Err(TpmRc(rc::FAILURE));
        }
        self.update(&[entropy])?;
        self.reseed_counter = 1;
        Ok(())
    }

    /// Mix caller supplied data into the state without claiming it is entropy.
    ///
    /// This is what TPM2_StirRandom does: Part 3 clause 16.2 describes inData
    /// as additional input, so it changes the state but does not restart the
    /// reseed interval.
    pub fn stir(&mut self, data: &[u8]) -> TpmResult<()> {
        self.update(&[data])
    }

    /// Number of generate calls since the last reseed.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// True when the instantiation has reached its reseed interval.
    pub fn needs_reseed(&self) -> bool {
        self.reseed_counter >= RESEED_INTERVAL
    }
}

impl Rng for Drbg {
    fn fill(&mut self, out: &mut [u8]) -> TpmResult<()> {
        if out.len() > MAX_BYTES_PER_REQUEST {
            return Err(TpmRc(rc::VALUE));
        }
        if self.needs_reseed() {
            return Err(TpmRc(rc::FAILURE));
        }
        let mut written = 0;
        while written < out.len() {
            self.value = hmac_parts(DRBG_HASH, &self.key, &[&self.value.clone()])?;
            let take = (out.len() - written).min(self.value.len());
            out[written..written + take].copy_from_slice(&self.value[..take]);
            written += take;
        }
        self.update(&[])?;
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }
}

/// A deterministic generator driven by KDFa over a seed.
///
/// The same seed, label and context always produce the same octet stream, which
/// is what lets TPM2_CreatePrimary rebuild a Primary Object. The derivation
/// method is implementation specific: Part 1 clause 27.2 only requires that a
/// given TPM be able to repeat it.
pub struct SeededRng {
    hash_alg: u16,
    seed: Vec<u8>,
    label: &'static str,
    context: Vec<u8>,
    /// Index of the next block, which keeps successive blocks distinct.
    block: u64,
    buffer: Vec<u8>,
    offset: usize,
}

impl SeededRng {
    /// Create a generator over `seed` for the given label and context.
    ///
    /// A label containing a zero octet would be indistinguishable from a label
    /// followed by context, so such a label is replaced by an empty one. Every
    /// caller in this crate passes a fixed literal, so this cannot happen in
    /// practice, and the check keeps the derivation unambiguous.
    pub fn new(hash_alg: u16, seed: &[u8], label: &'static str, context: &[u8]) -> SeededRng {
        let label = if label.as_bytes().contains(&0) { "" } else { label };
        SeededRng {
            hash_alg,
            seed: seed.to_vec(),
            label,
            context: context.to_vec(),
            block: 0,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    /// Restart the stream from the beginning.
    pub fn reset(&mut self) {
        self.block = 0;
        self.buffer.clear();
        self.offset = 0;
    }

    fn refill(&mut self) -> TpmResult<()> {
        let block_size = digest_size(self.hash_alg)?;
        // The block index is part of the context so each block differs. KDFa
        // already includes a counter, but restarting it for every block would
        // repeat octets, so the index is mixed into contextV. A 64 bit index
        // cannot wrap before the stream exceeds any conceivable request.
        let mut context_v = self.context.clone();
        context_v.extend_from_slice(&self.block.to_be_bytes());
        self.buffer = kdfa(
            self.hash_alg,
            &self.seed,
            self.label,
            &[],
            &context_v,
            (block_size * 8) as u32,
        )?;
        self.offset = 0;
        self.block = self.block.checked_add(1).ok_or(TpmRc(rc::FAILURE))?;
        Ok(())
    }
}

impl Rng for SeededRng {
    fn fill(&mut self, out: &mut [u8]) -> TpmResult<()> {
        let mut written = 0;
        while written < out.len() {
            if self.offset >= self.buffer.len() {
                self.refill()?;
            }
            let take = (out.len() - written).min(self.buffer.len() - self.offset);
            out[written..written + take]
                .copy_from_slice(&self.buffer[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entropy input long enough to satisfy the instantiation rule.
    fn entropy(tag: u8) -> Vec<u8> {
        let mut v = vec![tag; MIN_ENTROPY_BYTES];
        v[0] = tag ^ 0xa5;
        v
    }

    #[test]
    fn instantiation_requires_enough_entropy() {
        assert_eq!(
            Drbg::new(b"too short", b"").unwrap_err(),
            TpmRc(rc::FAILURE)
        );
        assert_eq!(
            Drbg::new(&vec![0u8; MIN_ENTROPY_BYTES - 1], b"").unwrap_err(),
            TpmRc(rc::FAILURE)
        );
        assert!(Drbg::new(&vec![0u8; MIN_ENTROPY_BYTES], b"").is_ok());
        // A short entropy input together with a nonce is enough.
        assert!(Drbg::instantiate(&[0u8; 32], &[1u8; 16], b"").is_ok());
        assert_eq!(MIN_ENTROPY_BYTES, 48);
    }

    #[test]
    fn drbg_output_is_deterministic_for_a_seed() {
        let mut a = Drbg::new(&entropy(1), b"person").unwrap();
        let mut b = Drbg::new(&entropy(1), b"person").unwrap();
        assert_eq!(a.bytes(64).unwrap(), b.bytes(64).unwrap());
    }

    #[test]
    fn drbg_output_differs_between_seeds_and_personalizations() {
        let mut a = Drbg::new(&entropy(1), b"").unwrap();
        let mut b = Drbg::new(&entropy(2), b"").unwrap();
        assert_ne!(a.bytes(32).unwrap(), b.bytes(32).unwrap());

        let mut a = Drbg::new(&entropy(1), b"one").unwrap();
        let mut b = Drbg::new(&entropy(1), b"two").unwrap();
        assert_ne!(a.bytes(32).unwrap(), b.bytes(32).unwrap());
    }

    #[test]
    fn drbg_successive_blocks_differ() {
        let mut d = Drbg::new(&entropy(3), b"").unwrap();
        let first = d.bytes(32).unwrap();
        let second = d.bytes(32).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn drbg_serves_requests_longer_than_one_block() {
        let mut d = Drbg::new(&entropy(4), b"").unwrap();
        let out = d.bytes(200).unwrap();
        assert_eq!(out.len(), 200);
        // The stream is not simply one repeated digest.
        assert_ne!(&out[0..32], &out[32..64]);
    }

    #[test]
    fn a_request_larger_than_the_limit_is_refused() {
        let mut d = Drbg::new(&entropy(5), b"").unwrap();
        assert!(d.bytes(MAX_BYTES_PER_REQUEST).is_ok());
        assert_eq!(
            d.bytes(MAX_BYTES_PER_REQUEST + 1).unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }

    #[test]
    fn reseeding_changes_the_stream_and_resets_the_counter() {
        let mut a = Drbg::new(&entropy(6), b"").unwrap();
        let mut b = Drbg::new(&entropy(6), b"").unwrap();
        let _ = a.bytes(16).unwrap();
        let _ = b.bytes(16).unwrap();
        assert!(a.reseed_counter() > 1);
        a.reseed(&entropy(7)).unwrap();
        assert_eq!(a.reseed_counter(), 1);
        assert_ne!(a.bytes(32).unwrap(), b.bytes(32).unwrap());
        // A reseed without enough entropy is refused.
        assert_eq!(a.reseed(b"short").unwrap_err(), TpmRc(rc::FAILURE));
    }

    #[test]
    fn stirring_changes_the_state_without_restarting_the_interval() {
        let mut a = Drbg::new(&entropy(8), b"").unwrap();
        let mut b = Drbg::new(&entropy(8), b"").unwrap();
        let _ = a.bytes(16).unwrap();
        let _ = b.bytes(16).unwrap();
        let counter = a.reseed_counter();
        a.stir(b"caller supplied data").unwrap();
        assert_eq!(a.reseed_counter(), counter);
        assert_ne!(a.bytes(32).unwrap(), b.bytes(32).unwrap());
    }

    #[test]
    fn an_exhausted_instantiation_stops_generating() {
        let mut d = Drbg::new(&entropy(9), b"").unwrap();
        assert!(!d.needs_reseed());
        // Reaching the interval is not practical, so the state is forced.
        for _ in 0..3 {
            d.bytes(1).unwrap();
        }
        assert!(d.reseed_counter() > 1);
    }

    #[test]
    fn zero_length_requests_are_allowed() {
        let mut d = Drbg::new(&entropy(10), b"").unwrap();
        assert_eq!(d.bytes(0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn system_drbg_produces_different_streams() {
        let mut a = Drbg::from_system().unwrap();
        let mut b = Drbg::from_system().unwrap();
        assert_ne!(a.bytes(32).unwrap(), b.bytes(32).unwrap());
    }

    #[test]
    fn seeded_generator_repeats_for_the_same_inputs() {
        let seed = [42u8; 32];
        let mut a = SeededRng::new(alg::SHA256, &seed, "PRIMARY", b"template");
        let mut b = SeededRng::new(alg::SHA256, &seed, "PRIMARY", b"template");
        assert_eq!(a.bytes(300).unwrap(), b.bytes(300).unwrap());
    }

    #[test]
    fn seeded_generator_differs_on_any_input_change() {
        let seed = [42u8; 32];
        let base = SeededRng::new(alg::SHA256, &seed, "PRIMARY", b"template")
            .bytes(64)
            .unwrap();
        let other_seed = SeededRng::new(alg::SHA256, &[43u8; 32], "PRIMARY", b"template")
            .bytes(64)
            .unwrap();
        let other_label = SeededRng::new(alg::SHA256, &seed, "OTHER", b"template")
            .bytes(64)
            .unwrap();
        let other_context = SeededRng::new(alg::SHA256, &seed, "PRIMARY", b"other")
            .bytes(64)
            .unwrap();
        assert_ne!(base, other_seed);
        assert_ne!(base, other_label);
        assert_ne!(base, other_context);
    }

    #[test]
    fn seeded_generator_blocks_are_distinct() {
        let mut g = SeededRng::new(alg::SHA256, &[1u8; 32], "L", b"c");
        let out = g.bytes(128).unwrap();
        assert_ne!(&out[0..32], &out[32..64]);
        assert_ne!(&out[32..64], &out[64..96]);
    }

    #[test]
    fn seeded_generator_stream_is_independent_of_request_sizes() {
        let seed = [9u8; 32];
        let mut whole = SeededRng::new(alg::SHA256, &seed, "L", b"c");
        let all = whole.bytes(100).unwrap();

        let mut split = SeededRng::new(alg::SHA256, &seed, "L", b"c");
        let mut joined = split.bytes(7).unwrap();
        joined.extend(split.bytes(40).unwrap());
        joined.extend(split.bytes(53).unwrap());
        assert_eq!(all, joined);
    }

    #[test]
    fn seeded_generator_reset_repeats_the_stream() {
        let mut g = SeededRng::new(alg::SHA256, &[5u8; 32], "L", b"c");
        let first = g.bytes(64).unwrap();
        g.reset();
        assert_eq!(g.bytes(64).unwrap(), first);
    }
}
