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

/// The four hierarchies of Part 1 clause 9, and the limited ones clause 41
/// derives from them.
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
    /// The secret a bootloader would hold, which both limited kinds derive
    /// from.
    ///
    /// Part 1 clause 41.6 gives every firmware-limited and SVN-limited
    /// hierarchy a seed and a proof "derived from the base hierarchy's primary
    /// seed / proof value, as well as the additional secret", and Table 43
    /// names the two additional secrets: the Firmware Secret and the Firmware
    /// SVN Secret. Clause 41.4 has both come from a bootloader that measured
    /// the firmware, this one standing in for what the bootloader keeps: it is
    /// drawn at manufacture and kept with the state.
    ///
    /// The Firmware Secret is not this value but a derivation of it that
    /// includes the code of the running image, so that clause 41.7's
    /// "cryptographically limited to the current firmware image" holds: another
    /// build of this TPM, given the same state, derives a different one. The
    /// Firmware SVN Secret is derived from this value alone, because clause
    /// 41.7 keeps SVN-limited objects "available to TPM firmware updates as
    /// long as those updates' SVNs are greater than or equal to the SVN".
    pub bootloader_secret: Vec<u8>,
    /// The code of the running image, which the Firmware Secret includes.
    ///
    /// This is what the pre-operational integrity test of FIPS 140-3 clause
    /// 10.3.1 computes over the executable, and it is not part of the state:
    /// the image the TPM is running decides it.
    pub firmware_code: Vec<u8>,
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
            bootloader_secret: rng.bytes(config::PRIMARY_SEED_SIZE)?,
            firmware_code: Vec::new(),
        })
    }

    /// The base hierarchy of a firmware-limited or SVN-limited handle.
    ///
    /// Part 1 Table 43 pairs each limited hierarchy with the one whose seed and
    /// proof it is derived from.
    pub fn base_of(handle: u32) -> Option<u32> {
        use crate::tpm::constants::hc;

        Some(match handle {
            rh::FW_OWNER => rh::OWNER,
            rh::FW_ENDORSEMENT => rh::ENDORSEMENT,
            rh::FW_PLATFORM => rh::PLATFORM,
            rh::FW_NULL => rh::NULL,
            h if (hc::SVN_OWNER_FIRST..=hc::SVN_OWNER_LAST).contains(&h) => rh::OWNER,
            h if (hc::SVN_ENDORSEMENT_FIRST..=hc::SVN_ENDORSEMENT_LAST).contains(&h) => {
                rh::ENDORSEMENT
            }
            h if (hc::SVN_PLATFORM_FIRST..=hc::SVN_PLATFORM_LAST).contains(&h) => rh::PLATFORM,
            h if (hc::SVN_NULL_FIRST..=hc::SVN_NULL_LAST).contains(&h) => rh::NULL,
            _ => return None,
        })
    }

    /// The security version number an SVN-limited handle names.
    pub fn svn_of(handle: u32) -> Option<u32> {
        use crate::tpm::constants::hc;

        for first in [
            hc::SVN_OWNER_FIRST,
            hc::SVN_ENDORSEMENT_FIRST,
            hc::SVN_PLATFORM_FIRST,
            hc::SVN_NULL_FIRST,
        ] {
            if (first..=first + 0xFFFF).contains(&handle) {
                return Some(handle - first);
            }
        }
        None
    }

    /// True when `handle` is a firmware-limited or SVN-limited value of
    /// TPMI_RH_HIERARCHY.
    ///
    /// Every such handle is a member of the type whatever version this
    /// firmware is: what a version above it lacks is the secret, which
    /// [`Hierarchies::limited_secret_available`] answers for.
    pub fn is_limited(handle: u32) -> bool {
        Self::base_of(handle).is_some()
    }

    /// True when the secret a limited hierarchy is derived from is there.
    ///
    /// The example in clause 41.4 has the hardware "reject the request if
    /// requestedSvn is > LATCHED_FW_SVN". Part 2 Table 18 gives that its own
    /// response code: TPM_RC_SVN_LIMITED is "the hierarchy is SVN-limited but
    /// the Firmware SVN Secret associated with the given SVN is unavailable".
    pub fn limited_secret_available(handle: u32) -> bool {
        match Self::svn_of(handle) {
            Some(svn) => svn <= config::FIRMWARE_SVN,
            None => true,
        }
    }

    /// The additional secret of Table 43, and the label that tells the two
    /// kinds of limited hierarchy apart.
    fn additional_secret(&self, handle: u32) -> TpmResult<(Vec<u8>, &'static str)> {
        match Self::svn_of(handle) {
            // Clause 41.4: the bootloader derives an SVN secret from its own
            // secret and hashes it down once for each version below the
            // maximum, so a lower version can be reached from a higher one and
            // not the other way about.
            Some(svn) => {
                let mut secret = crate::tpm::crypto::hmac::kdfa(
                    config::CONTEXT_INTEGRITY_HASH_ALG,
                    &self.bootloader_secret,
                    "SVN_SECRET",
                    &[],
                    &[],
                    (config::PRIMARY_SEED_SIZE * 8) as u32,
                )?;
                for _ in svn..=config::FIRMWARE_MAX_SVN {
                    secret = crate::tpm::crypto::hash::digest(
                        config::CONTEXT_INTEGRITY_HASH_ALG,
                        &secret,
                    )?;
                }
                Ok((secret, "H_SVN_SECRET"))
            }
            // Clause 41.7: a firmware-limited object is "cryptographically
            // limited to the current firmware image; if the image is upgraded
            // or downgraded, all firmware-objects that were limited to the
            // previously installed firmware image are lost", so the code of the
            // image goes into the secret.
            None => Ok((
                crate::tpm::crypto::hmac::kdfa(
                    config::CONTEXT_INTEGRITY_HASH_ALG,
                    &self.bootloader_secret,
                    "FW_SECRET",
                    &self.firmware_code,
                    &[],
                    (config::PRIMARY_SEED_SIZE * 8) as u32,
                )?,
                "H_FW_SECRET",
            )),
        }
    }

    /// The Primary Seed of a hierarchy, derived when the handle is a limited
    /// one.
    pub fn seed_of(&self, handle: u32) -> TpmResult<Vec<u8>> {
        self.derive(handle, "H_SEED_SECRET", |h| &h.seed)
    }

    /// The proof value of a hierarchy, derived when the handle is a limited
    /// one.
    pub fn proof_of(&self, handle: u32) -> TpmResult<Vec<u8>> {
        self.derive(handle, "H_PROOF_SECRET", |h| &h.proof)
    }

    /// Part 1 Equation 57: `value := KDFa(hashAlg, bSecret, bSecretLabel,
    /// aSecret, aSecretLabel, bits)`, where bSecret is the seed or proof of the
    /// base hierarchy and aSecret the Firmware or Firmware SVN Secret. The
    /// labels are the ones the note beside the equation says the Reference Code
    /// uses.
    fn derive(
        &self,
        handle: u32,
        base_label: &str,
        pick: impl Fn(&Hierarchy) -> &Vec<u8>,
    ) -> TpmResult<Vec<u8>> {
        if let Ok(h) = self.get(handle) {
            return Ok(pick(h).clone());
        }
        let base = Self::base_of(handle).ok_or(TpmRc(rc::VALUE))?;
        if !Self::limited_secret_available(handle) {
            return Err(TpmRc(rc::SVN_LIMITED));
        }
        let (additional, additional_label) = self.additional_secret(handle)?;
        let mut context_v = additional_label.as_bytes().to_vec();
        context_v.push(0);
        crate::tpm::crypto::hmac::kdfa(
            config::CONTEXT_INTEGRITY_HASH_ALG,
            pick(self.get(base)?),
            base_label,
            &additional,
            &context_v,
            (config::PRIMARY_SEED_SIZE * 8) as u32,
        )
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
            // A limited hierarchy is a derivation of its base, so it is there
            // exactly while the base is: Part 1 Table 43 pairs each one with
            // the hierarchy its seed and proof come from.
            h => match Self::base_of(h) {
                Some(base) if Self::is_limited(h) => self.is_enabled(base),
                _ => false,
            },
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

    /// Whether `handle` is a value of TPMI_RH_HIERARCHY, Part 2 Table 59.
    ///
    /// The table lists the four hierarchies above and, without making them
    /// conditional, the firmware-limited and SVN-limited ones. Part 2 clause
    /// 4.5 has an interface type "checked by the unmarshaling code", so a
    /// structure carrying one of those unmarshals here even though this TPM
    /// has no such hierarchy; what is done with it fails on its own terms.
    pub fn is_hierarchy_selector(handle: u32) -> bool {
        use crate::tpm::constants::hc;
        Self::is_hierarchy(handle)
            || matches!(
                handle,
                rh::FW_OWNER | rh::FW_PLATFORM | rh::FW_ENDORSEMENT | rh::FW_NULL
            )
            || (hc::SVN_OWNER_FIRST..=hc::SVN_OWNER_LAST).contains(&handle)
            || (hc::SVN_PLATFORM_FIRST..=hc::SVN_PLATFORM_LAST).contains(&handle)
            || (hc::SVN_ENDORSEMENT_FIRST..=hc::SVN_ENDORSEMENT_LAST).contains(&handle)
            || (hc::SVN_NULL_FIRST..=hc::SVN_NULL_LAST).contains(&handle)
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
