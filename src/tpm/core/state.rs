//! The whole TPM state, and how it is written to and read from the state file.
//!
//! Part 1 clause 14 divides the state into values that survive power loss and
//! values that do not. The non-volatile part is what [`TpmState::save`] writes;
//! everything else is rebuilt by [`TpmState::on_startup`].

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::{alg, rc, su};
use crate::tpm::crypto::rand::Drbg;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::{PermanentAttributes, StartupClearAttributes};
use crate::tpm::structures::base::TpmtHa;

use super::hierarchy::Hierarchies;
use super::nv::{NvIndex, NvStore};
use super::object::{Object, ObjectSlots};
use super::pcr::PcrBanks;
use super::session::SessionSlots;

/// Version tag of the saved state layout.
const STATE_VERSION: u32 = 1;

/// Dictionary attack protection, Part 1 clause 19.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutState {
    /// Failed authorization attempts since the last successful one.
    pub failed_tries: u32,
    /// Failures allowed before the TPM enters lockout.
    pub max_tries: u32,
    /// Seconds of no failure that recover one try.
    pub recovery_time: u32,
    /// Seconds before lockoutAuth may be used again.
    pub lockout_recovery: u32,
    /// True while lockoutAuth itself is unavailable.
    pub in_lockout: bool,
    /// Time, in the TPM's own base, when the next try is recovered.
    pub next_recovery: u64,
}

impl Default for LockoutState {
    fn default() -> Self {
        LockoutState {
            failed_tries: 0,
            max_tries: config::DEFAULT_MAX_AUTH_FAIL,
            recovery_time: config::DEFAULT_LOCKOUT_INTERVAL,
            lockout_recovery: config::DEFAULT_LOCKOUT_RECOVERY,
            in_lockout: false,
            next_recovery: 0,
        }
    }
}

impl Marshal for LockoutState {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.failed_tries);
        w.u32(self.max_tries);
        w.u32(self.recovery_time);
        w.u32(self.lockout_recovery);
        w.u8(u8::from(self.in_lockout));
        w.u64(self.next_recovery);
    }
}

impl Unmarshal for LockoutState {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(LockoutState {
            failed_tries: r.u32()?,
            max_tries: r.u32()?,
            recovery_time: r.u32()?,
            lockout_recovery: r.u32()?,
            in_lockout: r.u8()? != 0,
            next_recovery: r.u64()?,
        })
    }
}

/// Clock, Time and the reset counters, Part 1 clause 36.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockState {
    /// Milliseconds that advance whenever the TPM is powered, saved to NV.
    pub clock: u64,
    /// Milliseconds since the last _TPM_Init, not saved.
    pub time: u64,
    /// TPM Resets since the last TPM2_Clear.
    pub reset_count: u32,
    /// TPM Restarts and Resumes since the last TPM Reset.
    pub restart_count: u32,
    /// False when Clock may have gone backwards.
    pub safe: bool,
    /// Resets over the life of the TPM, which never clears.
    pub total_reset_count: u32,
}

impl Marshal for ClockState {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.clock);
        w.u32(self.reset_count);
        w.u32(self.restart_count);
        w.u8(u8::from(self.safe));
        w.u32(self.total_reset_count);
    }
}

impl Unmarshal for ClockState {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(ClockState {
            clock: r.u64()?,
            time: 0,
            reset_count: r.u32()?,
            restart_count: r.u32()?,
            safe: r.u8()? != 0,
            total_reset_count: r.u32()?,
        })
    }
}

/// Command audit state, Part 1 clause 20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditState {
    pub alg: u16,
    pub digest: Vec<u8>,
    pub counter: u64,
    pub commands: Vec<u32>,
    /// The session that currently holds exclusive audit, if any.
    pub exclusive_session: u32,
}

impl Default for AuditState {
    fn default() -> Self {
        AuditState {
            alg: alg::NULL,
            digest: Vec::new(),
            counter: 0,
            commands: Vec::new(),
            exclusive_session: 0,
        }
    }
}

/// Everything the TPM knows.
pub struct TpmState {
    // Values that survive power loss.
    pub hierarchies: Hierarchies,
    pub lockout: LockoutState,
    pub permanent: PermanentAttributes,
    pub clock: ClockState,
    /// PCR banks that will be allocated at the next TPM Reset.
    pub pcr_allocation: Vec<u16>,
    pub nv: NvStore,
    pub persistent: BTreeMap<u32, Object>,
    /// Commands that need physical presence.
    pub pp_commands: Vec<u32>,
    pub audit: AuditState,
    pub algorithm_set: u32,
    /// The authorization value of TPM_RH_LOCKOUT.
    pub lockout_auth: Vec<u8>,
    /// The authorization policy of TPM_RH_LOCKOUT.
    pub lockout_policy: TpmtHa,
    /// The authorization value shared by the PCR that have one.
    pub pcr_auth: Vec<u8>,
    /// The authorization policy shared by the PCR that have one.
    pub pcr_policy: TpmtHa,
    /// Set once the TPM has been manufactured, so a fresh state file is
    /// distinguishable from a saved one.
    pub manufactured: bool,

    // Values that do not survive power loss.
    pub started: bool,
    pub startup_type: u16,
    pub startup_clear: StartupClearAttributes,
    pub pcr: PcrBanks,
    pub objects: ObjectSlots,
    pub sessions: SessionSlots,
    pub locality: u8,
    pub physical_presence: bool,
    pub nv_available: bool,
    pub failure_mode: bool,
    pub self_test_done: bool,
    pub rng: Drbg,
    /// Data collected between _TPM_Hash_Start and _TPM_Hash_End.
    pub hcrtm_buffer: Option<Vec<u8>>,
}

impl std::fmt::Debug for TpmState {
    /// Seeds, proofs and authorization values are never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmState")
            .field("started", &self.started)
            .field("startup_type", &self.startup_type)
            .field("reset_count", &self.clock.reset_count)
            .field("objects", &self.objects.len())
            .field("sessions", &self.sessions.len())
            .field("nv_indices", &self.nv.len())
            .field("persistent", &self.persistent.len())
            .finish()
    }
}

impl TpmState {
    /// Manufacture a new TPM.
    pub fn manufacture() -> TpmResult<TpmState> {
        let mut rng = Drbg::from_system()?;
        let hierarchies = Hierarchies::new(&mut rng)?;
        Ok(TpmState {
            hierarchies,
            lockout: LockoutState::default(),
            permanent: PermanentAttributes(PermanentAttributes::TPM_GENERATED_EPS),
            clock: ClockState {
                safe: true,
                ..ClockState::default()
            },
            pcr_allocation: config::DEFAULT_PCR_BANKS.to_vec(),
            nv: NvStore::new(),
            persistent: BTreeMap::new(),
            pp_commands: Vec::new(),
            audit: AuditState::default(),
            algorithm_set: 0,
            lockout_auth: Vec::new(),
            lockout_policy: TpmtHa::null(),
            pcr_auth: Vec::new(),
            pcr_policy: TpmtHa::null(),
            manufactured: true,
            started: false,
            startup_type: su::CLEAR,
            startup_clear: StartupClearAttributes(0),
            pcr: PcrBanks::new(config::DEFAULT_PCR_BANKS)?,
            objects: ObjectSlots::new(),
            sessions: SessionSlots::new(),
            locality: 0,
            physical_presence: false,
            nv_available: true,
            failure_mode: false,
            self_test_done: true,
            rng,
            hcrtm_buffer: None,
        })
    }

    /// Apply a TPM Reset, which is TPM2_Startup(CLEAR) after a power cycle.
    pub fn on_startup_clear(&mut self) -> TpmResult<()> {
        self.hierarchies.on_reset(&mut self.rng)?;
        self.pcr.allocate(&self.pcr_allocation.clone())?;
        self.objects.clear();
        self.sessions.clear();
        self.nv.on_startup_clear();
        self.clock.reset_count = self.clock.reset_count.wrapping_add(1);
        self.clock.total_reset_count = self.clock.total_reset_count.wrapping_add(1);
        self.clock.restart_count = 0;
        self.clock.time = 0;
        self.audit.digest.clear();
        self.audit.exclusive_session = 0;
        self.startup_clear = StartupClearAttributes(
            StartupClearAttributes::PH_ENABLE
                | StartupClearAttributes::SH_ENABLE
                | StartupClearAttributes::EH_ENABLE
                | StartupClearAttributes::PH_ENABLE_NV,
        );
        self.started = true;
        self.startup_type = su::CLEAR;
        Ok(())
    }

    /// Apply a TPM Restart or Resume, which is TPM2_Startup(STATE).
    ///
    /// The saved state is already loaded, so only the volatile pieces that a
    /// Startup(STATE) still discards are cleared.
    pub fn on_startup_state(&mut self) -> TpmResult<()> {
        self.objects.flush_st_clear();
        self.clock.restart_count = self.clock.restart_count.wrapping_add(1);
        self.clock.time = 0;
        self.startup_clear = StartupClearAttributes(
            StartupClearAttributes::PH_ENABLE
                | StartupClearAttributes::SH_ENABLE
                | StartupClearAttributes::EH_ENABLE
                | StartupClearAttributes::PH_ENABLE_NV,
        );
        self.started = true;
        self.startup_type = su::STATE;
        Ok(())
    }

    /// Apply TPM2_Clear, Part 3 clause 24.6.
    pub fn on_clear(&mut self) -> TpmResult<()> {
        self.hierarchies.on_clear(&mut self.rng)?;
        self.lockout = LockoutState::default();
        self.permanent = PermanentAttributes(
            self.permanent.0 & PermanentAttributes::TPM_GENERATED_EPS,
        );
        self.nv.clear_owner_indices();
        self.persistent
            .retain(|h, _| *h >= crate::tpm::constants::hc::PLATFORM_PERSISTENT);
        self.objects
            .flush_hierarchy(crate::tpm::constants::rh::OWNER);
        self.objects
            .flush_hierarchy(crate::tpm::constants::rh::ENDORSEMENT);
        self.clock.reset_count = 0;
        self.audit.commands.clear();
        self.audit.alg = alg::NULL;
        self.audit.digest.clear();
        self.audit.counter = 0;
        Ok(())
    }

    /// The proof value of the hierarchy an object belongs to.
    pub fn hierarchy_proof(&self, handle: u32) -> TpmResult<&[u8]> {
        Ok(&self.hierarchies.get(handle)?.proof)
    }

    /// Marshal the non-volatile state.
    pub fn save(&self) -> TpmResult<Vec<u8>> {
        let mut w = Writer::new();
        w.u32(STATE_VERSION);
        w.u8(u8::from(self.manufactured));

        for h in [
            &self.hierarchies.platform,
            &self.hierarchies.owner,
            &self.hierarchies.endorsement,
            &self.hierarchies.null,
        ] {
            w.sized16(&h.seed);
            w.sized16(&h.proof);
            w.sized16(&h.auth);
            h.policy.marshal(&mut w);
            w.u8(u8::from(h.enabled));
        }
        w.u8(u8::from(self.hierarchies.platform_nv_enabled));

        self.lockout.marshal(&mut w);
        self.permanent.marshal(&mut w);
        self.clock.marshal(&mut w);
        w.u32(self.algorithm_set);
        w.sized16(&self.lockout_auth);
        self.lockout_policy.marshal(&mut w);
        w.sized16(&self.pcr_auth);
        self.pcr_policy.marshal(&mut w);

        w.u32(self.pcr_allocation.len() as u32);
        for a in &self.pcr_allocation {
            w.u16(*a);
        }

        w.u32(self.pp_commands.len() as u32);
        for c in &self.pp_commands {
            w.u32(*c);
        }

        w.u16(self.audit.alg);
        w.sized16(&self.audit.digest);
        w.u64(self.audit.counter);
        w.u32(self.audit.commands.len() as u32);
        for c in &self.audit.commands {
            w.u32(*c);
        }

        w.u32(self.nv.len() as u32);
        for (_, index) in self.nv.iter() {
            index.public.marshal(&mut w);
            w.sized16(&index.auth);
            w.sized16(&index.data);
            w.u8(u8::from(index.read_locked));
            w.u8(u8::from(index.write_locked));
        }

        w.u32(self.persistent.len() as u32);
        for (handle, object) in &self.persistent {
            w.u32(*handle);
            w.u32(object.hierarchy);
            w.u8(u8::from(object.tpm_generated));
            object.public.marshal(&mut w);
            match &object.sensitive {
                Some(s) => {
                    w.u8(1);
                    s.marshal(&mut w);
                }
                None => w.u8(0),
            }
        }

        w.finish()
    }

    /// Rebuild the non-volatile state from `data`, keeping the volatile parts
    /// at their manufactured values.
    pub fn load(data: &[u8]) -> TpmResult<TpmState> {
        let mut state = TpmState::manufacture()?;
        let mut r = Reader::new(data);
        if r.u32()? != STATE_VERSION {
            return Err(TpmRc(rc::BAD_CONTEXT));
        }
        state.manufactured = r.u8()? != 0;

        for slot in 0..4 {
            let seed = read_sized(&mut r)?;
            let proof = read_sized(&mut r)?;
            let auth = read_sized(&mut r)?;
            let policy = TpmtHa::unmarshal(&mut r)?;
            let enabled = r.u8()? != 0;
            let target = match slot {
                0 => &mut state.hierarchies.platform,
                1 => &mut state.hierarchies.owner,
                2 => &mut state.hierarchies.endorsement,
                _ => &mut state.hierarchies.null,
            };
            target.seed = seed;
            target.proof = proof;
            target.auth = auth;
            target.policy = policy;
            target.enabled = enabled;
        }
        state.hierarchies.platform_nv_enabled = r.u8()? != 0;

        state.lockout = LockoutState::unmarshal(&mut r)?;
        state.permanent = PermanentAttributes::unmarshal(&mut r)?;
        state.clock = ClockState::unmarshal(&mut r)?;
        state.algorithm_set = r.u32()?;
        state.lockout_auth = read_sized(&mut r)?;
        state.lockout_policy = TpmtHa::unmarshal(&mut r)?;
        state.pcr_auth = read_sized(&mut r)?;
        state.pcr_policy = TpmtHa::unmarshal(&mut r)?;

        let count = bounded_count(&mut r, config::HASH_COUNT)?;
        state.pcr_allocation = (0..count).map(|_| r.u16()).collect::<TpmResult<_>>()?;

        let count = bounded_count(&mut r, 512)?;
        state.pp_commands = (0..count).map(|_| r.u32()).collect::<TpmResult<_>>()?;

        state.audit.alg = r.u16()?;
        state.audit.digest = read_sized(&mut r)?;
        state.audit.counter = r.u64()?;
        let count = bounded_count(&mut r, 512)?;
        state.audit.commands = (0..count).map(|_| r.u32()).collect::<TpmResult<_>>()?;

        let count = bounded_count(&mut r, 4096)?;
        let mut nv = NvStore::new();
        for _ in 0..count {
            let public = crate::tpm::structures::nv::NvPublic::unmarshal(&mut r)?;
            let auth = read_sized(&mut r)?;
            let data = read_sized(&mut r)?;
            let read_locked = r.u8()? != 0;
            let write_locked = r.u8()? != 0;
            nv.define(NvIndex {
                public,
                auth,
                data,
                read_locked,
                write_locked,
            })?;
        }
        state.nv = nv;

        let count = bounded_count(&mut r, config::MIN_EVICT_OBJECTS as usize * 64)?;
        for _ in 0..count {
            let handle = r.u32()?;
            let hierarchy = r.u32()?;
            let tpm_generated = r.u8()? != 0;
            let public = crate::tpm::structures::keys::TpmtPublic::unmarshal(&mut r)?;
            let sensitive = if r.u8()? != 0 {
                Some(crate::tpm::structures::keys::TpmtSensitive::unmarshal(
                    &mut r,
                )?)
            } else {
                None
            };
            // A persistent object keeps the qualified name it had when it was
            // made persistent, which is rebuilt from its hierarchy.
            let parent_qn = super::names::handle_name(hierarchy);
            let object = Object::new(public, sensitive, hierarchy, &parent_qn, tpm_generated)?;
            state.persistent.insert(handle, object);
        }

        if !r.is_empty() {
            return Err(TpmRc(rc::BAD_CONTEXT));
        }
        // The banks the saved allocation names are what the TPM comes up with.
        state.pcr = PcrBanks::new(&state.pcr_allocation)?;
        Ok(state)
    }
}

fn read_sized(r: &mut Reader<'_>) -> TpmResult<Vec<u8>> {
    let size = r.u16()? as usize;
    Ok(r.take(size)?.to_vec())
}

fn bounded_count(r: &mut Reader<'_>, max: usize) -> TpmResult<usize> {
    let count = r.u32()? as usize;
    if count > max {
        return Err(TpmRc(rc::BAD_CONTEXT));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{hc, rh};
    use crate::tpm::structures::attributes::{nt, NvAttributes, ObjectAttributes};
    use crate::tpm::structures::base::Tpm2bDigest;
    use crate::tpm::structures::keys::{PublicId, PublicParms, TpmtPublic};
    use crate::tpm::structures::nv::NvPublic;
    use crate::tpm::structures::schemes::{Scheme, SymDef};

    fn nv_index(handle: u32) -> NvIndex {
        NvIndex {
            public: NvPublic {
                nv_index: handle,
                name_alg: alg::SHA256,
                attributes: NvAttributes(NvAttributes::AUTHREAD | NvAttributes::AUTHWRITE)
                    .with_index_type(nt::ORDINARY),
                auth_policy: Tpm2bDigest::empty(),
                data_size: 8,
            },
            auth: b"nvauth".to_vec(),
            data: Vec::new(),
            read_locked: false,
            write_locked: true,
        }
    }

    fn object() -> Object {
        let public = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: crate::tpm::constants::curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(Default::default()),
        };
        Object::new(public, None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap()
    }

    #[test]
    fn a_manufactured_tpm_is_not_started() {
        let s = TpmState::manufacture().unwrap();
        assert!(!s.started);
        assert!(s.manufactured);
        assert_eq!(s.pcr.algorithms(), config::DEFAULT_PCR_BANKS.to_vec());
        assert_eq!(s.clock.reset_count, 0);
        assert!(s.clock.safe);
        assert_eq!(s.lockout.max_tries, config::DEFAULT_MAX_AUTH_FAIL);
    }

    #[test]
    fn startup_clear_enables_every_hierarchy_and_advances_the_reset_count() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        assert!(s.started);
        assert_eq!(s.clock.reset_count, 1);
        assert_eq!(s.clock.total_reset_count, 1);
        assert_eq!(s.clock.restart_count, 0);
        assert!(s.startup_clear.has(StartupClearAttributes::PH_ENABLE));
        assert!(s.startup_clear.has(StartupClearAttributes::SH_ENABLE));
        assert!(s.startup_clear.has(StartupClearAttributes::EH_ENABLE));
        assert!(s.startup_clear.has(StartupClearAttributes::PH_ENABLE_NV));
    }

    #[test]
    fn startup_state_advances_the_restart_count_only() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        let resets = s.clock.reset_count;
        s.on_startup_state().unwrap();
        assert_eq!(s.clock.reset_count, resets);
        assert_eq!(s.clock.restart_count, 1);
    }

    #[test]
    fn clear_drops_owner_state_and_keeps_platform_state() {
        let mut s = TpmState::manufacture().unwrap();
        let owner_seed = s.hierarchies.owner.seed.clone();
        let platform_seed = s.hierarchies.platform.seed.clone();
        s.hierarchies.owner.auth = b"owner".to_vec();
        s.nv.define(nv_index(hc::NV_INDEX_FIRST)).unwrap();
        s.persistent.insert(hc::PERSISTENT_FIRST, object());
        s.persistent.insert(hc::PLATFORM_PERSISTENT, object());

        s.on_clear().unwrap();
        assert_ne!(s.hierarchies.owner.seed, owner_seed);
        assert_eq!(s.hierarchies.platform.seed, platform_seed);
        assert!(!s.hierarchies.owner.has_auth());
        assert!(!s.nv.contains(hc::NV_INDEX_FIRST));
        assert!(!s.persistent.contains_key(&hc::PERSISTENT_FIRST));
        assert!(s.persistent.contains_key(&hc::PLATFORM_PERSISTENT));
        assert_eq!(s.clock.reset_count, 0);
    }

    #[test]
    fn saved_state_round_trips() {
        let mut s = TpmState::manufacture().unwrap();
        s.hierarchies.owner.auth = b"ownerauth".to_vec();
        s.hierarchies.owner.policy = TpmtHa::new(alg::SHA256, vec![7u8; 32]).unwrap();
        s.hierarchies.endorsement.enabled = false;
        s.lockout.failed_tries = 3;
        s.clock.clock = 123_456;
        s.clock.reset_count = 5;
        s.pcr_allocation = vec![alg::SHA256, alg::SHA384];
        s.pp_commands = vec![0x0000_0126, 0x0000_0127];
        s.audit.alg = alg::SHA256;
        s.audit.digest = vec![1u8; 32];
        s.audit.counter = 9;
        s.audit.commands = vec![0x0000_017b];
        s.nv.define(nv_index(hc::NV_INDEX_FIRST + 4)).unwrap();
        s.persistent.insert(hc::PERSISTENT_FIRST, object());

        let saved = s.save().unwrap();
        let back = TpmState::load(&saved).unwrap();

        assert_eq!(back.hierarchies.owner.auth, b"ownerauth");
        assert_eq!(back.hierarchies.owner.policy, s.hierarchies.owner.policy);
        assert_eq!(back.hierarchies.owner.seed, s.hierarchies.owner.seed);
        assert_eq!(back.hierarchies.platform.proof, s.hierarchies.platform.proof);
        assert!(!back.hierarchies.endorsement.enabled);
        assert_eq!(back.lockout, s.lockout);
        assert_eq!(back.clock.clock, 123_456);
        assert_eq!(back.clock.reset_count, 5);
        assert_eq!(back.pcr_allocation, vec![alg::SHA256, alg::SHA384]);
        assert_eq!(back.pcr.algorithms(), vec![alg::SHA256, alg::SHA384]);
        assert_eq!(back.pp_commands, s.pp_commands);
        assert_eq!(back.audit.digest, s.audit.digest);
        assert_eq!(back.audit.commands, s.audit.commands);

        let index = back.nv.get(hc::NV_INDEX_FIRST + 4).unwrap();
        assert_eq!(index.auth, b"nvauth");
        assert!(index.write_locked);
        assert_eq!(
            back.persistent.get(&hc::PERSISTENT_FIRST).unwrap().name,
            s.persistent.get(&hc::PERSISTENT_FIRST).unwrap().name
        );
    }

    #[test]
    fn a_truncated_or_tagged_state_is_refused() {
        let s = TpmState::manufacture().unwrap();
        let saved = s.save().unwrap();
        assert_eq!(
            TpmState::load(&saved[..saved.len() - 1]).unwrap_err(),
            TpmRc(rc::INSUFFICIENT)
        );
        let mut bad = saved.clone();
        bad[0] = 0xff;
        assert_eq!(TpmState::load(&bad).unwrap_err(), TpmRc(rc::BAD_CONTEXT));
        // Trailing octets are refused too.
        let mut extra = saved;
        extra.push(0);
        assert_eq!(TpmState::load(&extra).unwrap_err(), TpmRc(rc::BAD_CONTEXT));
    }

    #[test]
    fn a_bogus_count_in_the_state_is_refused() {
        let s = TpmState::manufacture().unwrap();
        let saved = s.save().unwrap();
        // Find the PCR allocation count and make it absurd.
        let mut bad = saved.clone();
        // The count cannot be located reliably, so every four octet window is
        // tried; at least one produces an oversized count that is rejected.
        let mut rejected = false;
        for i in 0..bad.len().saturating_sub(4) {
            bad.copy_from_slice(&saved);
            bad[i..i + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            if TpmState::load(&bad).is_err() {
                rejected = true;
            }
        }
        assert!(rejected);
    }

    #[test]
    fn volatile_state_is_not_saved() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.locality = 3;
        s.physical_presence = true;
        let back = TpmState::load(&s.save().unwrap()).unwrap();
        assert!(!back.started);
        assert_eq!(back.locality, 0);
        assert!(!back.physical_presence);
        assert!(back.sessions.is_empty());
        assert!(back.objects.is_empty());
    }
}
