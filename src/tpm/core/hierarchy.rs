//! Hierarchies and their seeds, Part 1 clauses 9 and 14.
//!
//! Each hierarchy owns a Primary Seed that every Primary Object under it is
//! derived from, a proof value that keys tickets and saved contexts, an
//! authorization value and an authorization policy. Changing a seed makes every
//! object and ticket under it useless, which is how TPM2_Clear and
//! TPM2_ChangeEPS take effect.

use crate::tpm::config;
use crate::tpm::constants::{alg, rc, rh};
use crate::tpm::crypto::rand::Rng;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::structures::base::TpmtHa;

/// One hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hierarchy {
    /// The Primary Seed, used to derive Primary Objects.
    pub seed: Vec<u8>,
    /// The proof value, used for tickets and context protection.
    pub proof: Vec<u8>,
    /// The authorization value.
    pub auth: Vec<u8>,
    /// The authorization policy, TPM_ALG_NULL when there is none.
    pub policy: TpmtHa,
    /// Cleared by TPM2_HierarchyControl.
    pub enabled: bool,
}

impl Hierarchy {
    /// A hierarchy with fresh random values and no authorization set.
    pub fn new(rng: &mut dyn Rng) -> TpmResult<Hierarchy> {
        Ok(Hierarchy {
            seed: rng.bytes(config::PRIMARY_SEED_SIZE)?,
            proof: rng.bytes(config::PRIMARY_SEED_SIZE)?,
            auth: Vec::new(),
            policy: TpmtHa::null(),
            enabled: true,
        })
    }

    /// Draw a new seed and proof, invalidating everything under the hierarchy.
    pub fn regenerate(&mut self, rng: &mut dyn Rng) -> TpmResult<()> {
        self.seed = rng.bytes(config::PRIMARY_SEED_SIZE)?;
        self.proof = rng.bytes(config::PRIMARY_SEED_SIZE)?;
        Ok(())
    }

    /// Give the hierarchy a new proof value while its seed stands.
    ///
    /// TPM2_Clear changes ehProof without changing the Endorsement Primary
    /// Seed, so the keys of that hierarchy stay reproducible while the tickets
    /// and saved contexts that named the old proof stop verifying.
    pub fn regenerate_proof(&mut self, rng: &mut dyn Rng) -> TpmResult<()> {
        self.proof = rng.bytes(config::PRIMARY_SEED_SIZE)?;
        Ok(())
    }

    /// Clear the authorization value and policy.
    pub fn clear_authorization(&mut self) {
        self.auth.clear();
        self.policy = TpmtHa::null();
    }

    /// True when an authorization value has been set.
    pub fn has_auth(&self) -> bool {
        !self.auth.is_empty()
    }

    /// True when a policy has been set.
    pub fn has_policy(&self) -> bool {
        self.policy.hash_alg != alg::NULL && !self.policy.digest.is_empty()
    }
}

/// The four hierarchies of Part 1 clause 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hierarchies {
    pub platform: Hierarchy,
    pub owner: Hierarchy,
    pub endorsement: Hierarchy,
    /// The NULL hierarchy, whose seed and proof are drawn afresh on every TPM
    /// Reset so nothing under it survives a reboot.
    pub null: Hierarchy,
    /// phEnableNV, which gates NV Indices created by the platform.
    pub platform_nv_enabled: bool,
}

impl Hierarchies {
    /// Manufacture a fresh set.
    pub fn new(rng: &mut dyn Rng) -> TpmResult<Hierarchies> {
        Ok(Hierarchies {
            platform: Hierarchy::new(rng)?,
            owner: Hierarchy::new(rng)?,
            endorsement: Hierarchy::new(rng)?,
            null: Hierarchy::new(rng)?,
            platform_nv_enabled: true,
        })
    }

    /// The hierarchy a permanent handle names.
    pub fn get(&self, handle: u32) -> TpmResult<&Hierarchy> {
        Ok(match handle {
            rh::PLATFORM => &self.platform,
            rh::OWNER => &self.owner,
            rh::ENDORSEMENT => &self.endorsement,
            rh::NULL => &self.null,
            _ => return Err(TpmRc(rc::VALUE)),
        })
    }

    /// The hierarchy a permanent handle names, for modification.
    pub fn get_mut(&mut self, handle: u32) -> TpmResult<&mut Hierarchy> {
        Ok(match handle {
            rh::PLATFORM => &mut self.platform,
            rh::OWNER => &mut self.owner,
            rh::ENDORSEMENT => &mut self.endorsement,
            rh::NULL => &mut self.null,
            _ => return Err(TpmRc(rc::VALUE)),
        })
    }

    /// True when `handle` names a hierarchy that is enabled.
    ///
    /// The NULL hierarchy is always enabled; Part 1 clause 9.4.3 gives no way
    /// to disable it.
    pub fn is_enabled(&self, handle: u32) -> bool {
        match handle {
            rh::NULL => true,
            rh::PLATFORM | rh::OWNER | rh::ENDORSEMENT => {
                self.get(handle).map(|h| h.enabled).unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Reset the volatile parts on a Startup(CLEAR).
    ///
    /// Every hierarchy is re-enabled because TPMA_STARTUP_CLEAR is cleared by a
    /// Startup(CLEAR). The NULL hierarchy gets a new seed and proof on a TPM
    /// Reset only: Part 1 clause 27.5 says "saved session contexts are not
    /// invalidated and may be reloaded after a TPM Restart or TPM Resume.
    /// Saved session contexts are invalidated on a TPM Reset", and clause
    /// 27.3.2 says sessions, sequences and Temporary Objects are protected
    /// under the NULL hierarchy, so changing nullProof on a restart would
    /// invalidate contexts that have to survive one.
    pub fn on_reset(&mut self, rng: &mut dyn Rng, full_reset: bool) -> TpmResult<()> {
        if full_reset {
            self.null.regenerate(rng)?;
            self.null.clear_authorization();
        }
        self.platform.enabled = true;
        self.owner.enabled = true;
        self.endorsement.enabled = true;
        self.platform_nv_enabled = true;
        // platformAuth and platformPolicy do not survive a reset.
        self.platform.clear_authorization();
        Ok(())
    }

    /// Apply TPM2_Clear.
    ///
    /// Part 3 clause 24.6.1 says the operation will "change the storage primary
    /// seed (SPS) to a new value from the TPM's random number generator (RNG)"
    /// and "change shProof and ehProof". The Endorsement Primary Seed is not in
    /// that list, so the endorsement hierarchy keeps its seed and its keys, and
    /// only its proof changes, which is what makes its tickets and saved
    /// contexts stop verifying.
    pub fn on_clear(&mut self, rng: &mut dyn Rng) -> TpmResult<()> {
        self.owner.regenerate(rng)?;
        self.owner.clear_authorization();
        self.endorsement.regenerate_proof(rng)?;
        self.endorsement.clear_authorization();
        // Part 3 clause 24.6.1 lists "SET shEnable and ehEnable" among what the
        // clear operation does, so a hierarchy that TPM2_HierarchyControl had
        // turned off comes back on.
        self.owner.enabled = true;
        self.endorsement.enabled = true;
        Ok(())
    }

    /// True when `handle` names one of the four hierarchies.
    pub fn is_hierarchy(handle: u32) -> bool {
        matches!(handle, rh::PLATFORM | rh::OWNER | rh::ENDORSEMENT | rh::NULL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::crypto::rand::Drbg;

    fn rng() -> Drbg {
        Drbg::new(&[0x77u8; 48], b"hierarchy").unwrap()
    }

    #[test]
    fn manufacture_gives_every_hierarchy_a_distinct_seed() {
        let mut r = rng();
        let h = Hierarchies::new(&mut r).unwrap();
        let seeds = [
            &h.platform.seed,
            &h.owner.seed,
            &h.endorsement.seed,
            &h.null.seed,
        ];
        for (i, a) in seeds.iter().enumerate() {
            assert_eq!(a.len(), config::PRIMARY_SEED_SIZE);
            for b in seeds.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        // Proofs are distinct from seeds.
        assert_ne!(h.owner.seed, h.owner.proof);
    }

    #[test]
    fn hierarchies_start_enabled_with_no_authorization() {
        let mut r = rng();
        let h = Hierarchies::new(&mut r).unwrap();
        for handle in [rh::PLATFORM, rh::OWNER, rh::ENDORSEMENT, rh::NULL] {
            assert!(h.is_enabled(handle));
            assert!(!h.get(handle).unwrap().has_auth());
            assert!(!h.get(handle).unwrap().has_policy());
        }
        assert!(h.platform_nv_enabled);
    }

    #[test]
    fn only_the_four_hierarchy_handles_resolve() {
        let mut r = rng();
        let h = Hierarchies::new(&mut r).unwrap();
        assert!(Hierarchies::is_hierarchy(rh::OWNER));
        assert!(!Hierarchies::is_hierarchy(rh::LOCKOUT));
        assert_eq!(h.get(rh::LOCKOUT).unwrap_err(), TpmRc(rc::VALUE));
        assert!(!h.is_enabled(rh::LOCKOUT));
    }

    #[test]
    fn disabling_a_hierarchy_is_visible() {
        let mut r = rng();
        let mut h = Hierarchies::new(&mut r).unwrap();
        h.get_mut(rh::OWNER).unwrap().enabled = false;
        assert!(!h.is_enabled(rh::OWNER));
        // The null hierarchy cannot be turned off.
        h.null.enabled = false;
        assert!(h.is_enabled(rh::NULL));
    }

    #[test]
    fn reset_renews_the_null_hierarchy_only() {
        let mut r = rng();
        let mut h = Hierarchies::new(&mut r).unwrap();
        let before = h.clone();
        h.get_mut(rh::OWNER).unwrap().enabled = false;
        h.on_reset(&mut r, true).unwrap();
        assert_ne!(h.null.seed, before.null.seed);
        assert_ne!(h.null.proof, before.null.proof);
        assert_eq!(h.owner.seed, before.owner.seed);
        assert_eq!(h.endorsement.seed, before.endorsement.seed);
        assert_eq!(h.platform.seed, before.platform.seed);
        // Every hierarchy is enabled again.
        assert!(h.is_enabled(rh::OWNER));
    }

    #[test]
    fn reset_drops_the_platform_authorization() {
        let mut r = rng();
        let mut h = Hierarchies::new(&mut r).unwrap();
        h.platform.auth = b"platform".to_vec();
        h.owner.auth = b"owner".to_vec();
        h.on_reset(&mut r, true).unwrap();
        assert!(!h.platform.has_auth());
        assert_eq!(h.owner.auth, b"owner");
    }

    #[test]
    fn clear_renews_the_storage_hierarchy_and_drops_authorizations() {
        let mut r = rng();
        let mut h = Hierarchies::new(&mut r).unwrap();
        let before = h.clone();
        h.owner.auth = b"owner".to_vec();
        h.endorsement.auth = b"endorsement".to_vec();
        h.platform.auth = b"platform".to_vec();
        h.on_clear(&mut r).unwrap();
        assert_ne!(h.owner.seed, before.owner.seed);
        assert!(!h.owner.has_auth());
        assert!(!h.endorsement.has_auth());
        // TPM2_Clear does not touch the endorsement seed or the platform.
        assert_eq!(h.endorsement.seed, before.endorsement.seed);
        assert_eq!(h.platform.auth, b"platform");
    }

    #[test]
    fn a_policy_is_only_set_when_it_has_a_digest() {
        let mut r = rng();
        let mut h = Hierarchies::new(&mut r).unwrap();
        h.owner.policy = TpmtHa::new(crate::tpm::constants::alg::SHA256, vec![1u8; 32]).unwrap();
        assert!(h.owner.has_policy());
        h.owner.clear_authorization();
        assert!(!h.owner.has_policy());
    }
}
