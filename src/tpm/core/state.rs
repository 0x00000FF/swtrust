//! The whole TPM state, and how it is written to and read from the state file.
//!
//! Part 1 clause 14 divides the state into values that survive power loss and
//! values that do not. The non-volatile part is what [`TpmState::save`] writes;
//! everything else is rebuilt by [`TpmState::on_startup`].

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::{rc, rh, su};
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
///
/// Version 2 added the platform profile byte after the tag. A version 1 file
/// was written before the profile existed, which was always the legacy one, so
/// it is still read rather than being thrown away: a TPM whose state a caller
/// depends on should not lose it because this build learned a new field.
///
/// Version 9 wrote which registers of each bank are allocated, which Part 1
/// clause 14.8 chooses per register rather than per bank.
///
/// Version 8 wrote TPMA_STARTUP_CLEAR, which carries the Read-Only mode Part 1
/// clause 42.2 keeps across a TPM Resume.
///
/// Version 7 wrote the highest value a counter Index has held, which Part 3
/// clause 31.2 keeps for the lifetime of the TPM.
///
/// Version 6 wrote the object context counter beside the session one, which
/// Part 1 clause 27.2.2 keeps apart.
///
/// Version 5 replaced the counter that stood for resetValue in Part 1
/// Equation 52 with the random form the equation offers beside it.
///
/// Version 4 added the saved session contexts, which Part 1 clause 27.5 keeps
/// across a TPM Restart and a TPM Resume, both of which pass through a power
/// cycle.
///
/// Version 3 added the clearCount of Part 1 Equation 52 to the clock.
///
/// One build wrote the profile byte while still tagging the record version 1.
/// It was never released, so version 1 means the layout that came before the
/// byte and nothing else. A file of the other shape can only have been written
/// by a developer running that build, and is not one this reads.
const STATE_VERSION: u32 = 9;
/// Version 8 named whole PCR banks where Part 1 clause 14.8 allocates per
/// register.
const STATE_VERSION_WITHOUT_PCR_BITS: u32 = 8;
/// Version 7 did not record TPMA_STARTUP_CLEAR, so Read-Only mode was lost
/// whenever the state went through a file.
const STATE_VERSION_WITHOUT_STARTUP_CLEAR: u32 = 7;
/// Version 6 did not record how far a counter Index had come before it was
/// undefined.
const STATE_VERSION_WITHOUT_COUNTER_FLOOR: u32 = 6;
/// Version 5 kept one context counter where Part 1 clause 27.2.2 has two.
const STATE_VERSION_WITHOUT_OBJECT_COUNTER: u32 = 5;
/// Version 4 counted TPM Resets rather than drawing a value for each one.
const STATE_VERSION_WITHOUT_RESET_VALUE: u32 = 4;
/// The version each field arrived in. A gate written against STATE_VERSION
/// moves every time the version is bumped, which is how a version 3 file with
/// a persistent object came to be read one octet out of place, so each field
/// names its own version instead.
const FIRST_WITH_CLEAR_COUNT: u32 = 3;
const FIRST_WITH_SESSIONS: u32 = 4;
const FIRST_WITH_PERSISTENT_STATE_CLEAR: u32 = 4;
const FIRST_WITH_RESET_VALUE: u32 = 5;
const FIRST_WITH_OBJECT_COUNTER: u32 = 6;
const FIRST_WITH_COUNTER_FLOOR: u32 = 7;
const FIRST_WITH_STARTUP_CLEAR: u32 = 8;
const FIRST_WITH_PCR_BITS: u32 = 9;
/// Version 3 did not record which session contexts had been saved.
const STATE_VERSION_WITHOUT_SESSIONS: u32 = 3;
/// Version 2 recorded the profile but not the clearCount of Part 1 Equation 52.
const STATE_VERSION_WITHOUT_CLEAR_COUNT: u32 = 2;
const STATE_VERSION_WITHOUT_PROFILE: u32 = 1;

/// Dictionary attack protection, Part 1 clause 19.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutState {
    /// The failedTries of Part 1 clause 16.8.2.
    ///
    /// It counts every authorization failure of a protected entity. Clause
    /// 16.8.4 gives the three ways it goes down: TPM2_DictionaryAttackLockReset
    /// sets it to zero, the TPM decrements it by one every recoveryTime, and it
    /// is set to zero when the owner changes. A successful authorization is not
    /// among them, and treating one as though it were would let a guess be
    /// followed by a success on some entity of the attacker's own.
    pub failed_tries: u32,
    /// Failures allowed before the TPM enters lockout.
    pub max_tries: u32,
    /// Seconds of no failure that recover one try.
    pub recovery_time: u32,
    /// Seconds before lockoutAuth may be used again.
    pub lockout_recovery: u32,
    /// The special lockout of Part 1 clause 16.8.5, which an authorization
    /// failure against lockoutAuth enters "regardless of the setting of
    /// failedTries and maxTries". Lockout mode itself is not a flag: clause
    /// 16.8.3 says the TPM is in it "while failedTries is equal to maxTries",
    /// so it is read from the counters rather than stored beside them.
    pub in_lockout: bool,
    /// Time, in the TPM's own base, when the next try is recovered.
    pub next_recovery: u64,
    /// Time, in the TPM's own base, when the special lockout ends. Zero while
    /// clause 16.8.5's "next TPM2_Startup()" is what ends it instead.
    pub lockout_until: u64,
}

impl LockoutState {
    /// Lockout mode, Part 1 clause 16.8.3: "the TPM is in Lockout mode while
    /// failedTries is equal to maxTries". Part 3 clause 25.3.1 adds that a
    /// maxTries of zero puts the TPM in lockout outright.
    pub fn locked_out(&self) -> bool {
        self.max_tries == 0 || self.failed_tries >= self.max_tries
    }

    /// True when the dictionary attack logic is switched off, which Part 3
    /// clause 25.3.1 does with a recovery time of zero: "authorizations are
    /// checked but authorization failures will not cause the TPM to enter
    /// lockout".
    pub fn protection_off(&self) -> bool {
        self.recovery_time == 0
    }

    /// Let the counters down as Time passes.
    ///
    /// Part 1 clause 16.8.2 decrements failedTries "by one after recoveryTime
    /// seconds", and clause 16.8.5 leaves the special lockout after
    /// lockoutRecovery. Part 3 clause 25.3.1 measures both "with respect to the
    /// Time and not Clock", so they go with the timer that a power cycle
    /// restarts.
    pub fn on_time(&mut self, time: u64) {
        // A caller that sends nothing for several intervals has had that many
        // go by; the clause takes one off after each, not one however many
        // passed.
        let interval = self.recovery_time as u64 * 1000;
        if !self.protection_off() && interval > 0 {
            while self.failed_tries > 0 && time >= self.next_recovery {
                self.failed_tries -= 1;
                self.next_recovery = self.next_recovery.saturating_add(interval);
            }
            if self.failed_tries == 0 {
                self.next_recovery = 0;
            }
        }
        if self.in_lockout && self.lockout_until != 0 && time >= self.lockout_until {
            self.in_lockout = false;
            self.lockout_until = 0;
        }
    }

    /// Start the timers again against a Time that has just gone back to zero.
    ///
    /// Part 3 clause 25.3.1 measures both against Time, which every startup
    /// restarts, so a deadline recorded in the last epoch means nothing in
    /// this one. Clause 16.8.5 says of a lockoutRecovery of zero that "the TPM
    /// will not exit this state until the next TPM2_Startup()", which is where
    /// the special lockout ends instead.
    pub fn on_startup(&mut self) {
        self.next_recovery = if self.failed_tries > 0 {
            self.recovery_time as u64 * 1000
        } else {
            0
        };
        if self.in_lockout {
            if self.lockout_recovery == 0 {
                self.in_lockout = false;
                self.lockout_until = 0;
            } else {
                self.lockout_until = self.lockout_recovery as u64 * 1000;
            }
        }
    }
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
            lockout_until: 0,
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
            // Both deadlines are in Time, which a power cycle restarts, so a
            // record carries neither. on_startup puts them back against the
            // Time this epoch begins with, and ends a special lockout whose
            // interval is zero, which Part 1 clause 16.8.5 leaves to "the next
            // TPM2_Startup()".
            lockout_until: 0,
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
    /// The clearCount of Part 1 Equation 52: "a counter value that is
    /// incremented on each TPM Restart and may be incremented or set to zero on
    /// TPM Reset". It is its own counter because restartCount also advances on
    /// a TPM Resume, and Part 2 clause 8.3.3.3 says a saved context of an
    /// stClear object is invalidated on TPM2_Startup(TPM_SU_CLEAR) rather than
    /// on a resume.
    pub clear_count: u32,
    /// The resetValue of Part 1 Equation 52.
    ///
    /// The equation allows "either a counter value that increments on each TPM
    /// Reset and is not reset over the lifetime of the TPM; or a random value
    /// that changes on each TPM Reset and has the size of the digest produced
    /// by vendorAlg". A counter of any fixed width eventually repeats, and a
    /// repeated prefix would let a context from before the wrap verify again,
    /// so the random form is used.
    pub reset_value: Vec<u8>,
    /// False when Clock may have gone backwards.
    pub safe: bool,
    /// Resets over the life of the TPM, which never clears.
    pub total_reset_count: u32,
    /// Identifies the run of Time the TPM is in.
    ///
    /// Time restarts from zero at every _TPM_Init, so a timeout expressed in
    /// Time only means something within one epoch. Part 3 clause 23.2.2 uses
    /// this to expire an authorization whose epoch has passed.
    pub time_epoch: u64,
    /// Milliseconds since the copy of Clock in NV was last brought up to date.
    ///
    /// Part 2 clause 10.10.2 lets Clock have a volatile component so long as
    /// the non-volatile one is refreshed at least every 2^22 milliseconds, and
    /// Part 1 Table 39 lets clockSafe become SET again once that rollover has
    /// happened. This is the volatile part, so it is not saved.
    pub nv_elapsed: u64,
}

impl Marshal for ClockState {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.clock);
        w.u32(self.reset_count);
        w.u32(self.restart_count);
        w.u32(self.clear_count);
        w.sized16(&self.reset_value);
        w.u8(u8::from(self.safe));
        w.u32(self.total_reset_count);
        w.u64(self.time_epoch);
    }
}

impl Unmarshal for ClockState {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        ClockState::read(r, true, true)
    }
}

impl ClockState {
    /// Read the counters, with `has_clear_count` false for a record written
    /// before that one was kept. A file from then names contexts that this
    /// build would no longer verify anyway, so starting the counter at zero
    /// loses nothing a caller had.
    fn read(
        r: &mut Reader<'_>,
        has_clear_count: bool,
        has_reset_value: bool,
    ) -> TpmResult<ClockState> {
        let clock = r.u64()?;
        let reset_count = r.u32()?;
        let restart_count = r.u32()?;
        let clear_count = if has_clear_count { r.u32()? } else { 0 };
        // A record from before the value was drawn names contexts this build
        // would no longer verify, which is what a TPM Reset does to them
        // anyway, so an empty one stands until the next reset draws one.
        let reset_value = if has_reset_value {
            let size = r.u16()? as usize;
            r.take(size)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(ClockState {
            clock,
            time: 0,
            reset_count,
            restart_count,
            clear_count,
            reset_value,
            safe: r.u8()? != 0,
            total_reset_count: r.u32()?,
            time_epoch: r.u64()?,
            nv_elapsed: 0,
        })
    }
}

/// Command audit state, Part 1 clause 32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditState {
    pub alg: u16,
    pub digest: Vec<u8>,
    pub counter: u64,
    pub commands: Vec<u32>,
    /// The session that currently holds exclusive audit, or
    /// TPM_RH_UNASSIGNED when no session does.
    pub exclusive_session: u32,
}

impl Default for AuditState {
    /// The values a manufactured TPM starts with.
    ///
    /// Part 3 clause 21.1 always audits TPM2_SetCommandCodeAuditStatus, and
    /// the audit hash starts as the one the TPM protects contexts with.
    fn default() -> Self {
        AuditState {
            alg: config::CONTEXT_INTEGRITY_HASH_ALG,
            digest: Vec::new(),
            counter: 0,
            commands: vec![crate::tpm::constants::cc::SetCommandCodeAuditStatus],
            exclusive_session: rh::UNASSIGNED,
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
    /// The allocation the next _TPM_Init will put in place, as the registers
    /// each bank has. Part 1 clause 14.8 allocates per register, and Part 3
    /// clause 22.5.1 keeps the change "for use during the next _TPM_Init
    /// operation".
    pub pcr_allocation: Vec<(u16, Vec<bool>)>,
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
    /// The argument of the last TPM2_Shutdown, or `su::NONE` while the TPM is
    /// running. It decides which of the three startup sequences of Part 1
    /// clause 12.2 the next TPM2_Startup performs.
    pub shutdown_type: u16,

    // Values that do not survive power loss.
    pub started: bool,
    pub startup_clear: StartupClearAttributes,
    /// Set by TPM2_PCR_Allocate and cleared by the next _TPM_Init.
    ///
    /// Part 3 clause 22.5.1: "after this command, TPM2_Shutdown() is only
    /// allowed to have a startupType equal to TPM_SU_CLEAR until after the next
    /// _TPM_Init", and the note beside it says that holds "even if this command
    /// does not cause the PCR allocation to change". It is volatile, because a
    /// shutdown that could record it is the one the rule forbids.
    pub pcr_allocation_pending: bool,
    pub pcr: PcrBanks,
    pub objects: ObjectSlots,
    pub sessions: SessionSlots,
    pub locality: u8,
    pub physical_presence: bool,
    pub nv_available: bool,
    pub failure_mode: bool,
    pub self_test_done: bool,
    /// Digest of the running image from the pre-operational integrity test,
    /// reported by TPM2_GetTestResult.
    pub test_digest: Vec<u8>,
    /// The self test that failed, if one did. TPM2_GetTestResult reports it in
    /// place of the digest so a failure says which test it was.
    pub test_failure: Option<String>,
    pub rng: Drbg,
    /// Outstanding split ECC operations, Part 1 clause 44.2. The nonce behind
    /// them is chosen at each TPM Reset, so a commit lives no longer than that.
    pub commits: crate::tpm::core::commit::Commits,
    /// True once the TPM has been through a TPM2_Startup.
    ///
    /// Part 1 clause 33.3.1 clears the Clock safety flag "after a non-orderly
    /// shutdown". A TPM that has been manufactured and never started has had
    /// no shutdown of any kind, so this tells the two apart. It is not reset
    /// by TPM2_Clear, because a Clear happens while the TPM is running and
    /// Clock can have been reported since.
    pub ever_started: bool,
    /// The authenticated countdown timer, Part 1 clause 40.
    ///
    /// The PC Client Platform TPM Profile 1.07 clause 5.1.2 asks a TPM that
    /// implements TPM2_ACT_SetTimeout for one instance, so there is one.
    pub act: crate::tpm::core::act::Act,
    /// Data collected between _TPM_Hash_Start and _TPM_Hash_End.
    pub hcrtm_buffer: Option<Vec<u8>>,
    /// Set by the running command to keep itself out of the command audit.
    ///
    /// Part 3 clause 21.1 audits TPM2_SetCommandCodeAuditStatus except when it
    /// is used to change the audit algorithm, which the changed algorithm is
    /// itself the evidence of.
    pub command_audit_suppressed: bool,
}

impl std::fmt::Debug for TpmState {
    /// Seeds, proofs and authorization values are never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmState")
            .field("started", &self.started)
            .field("shutdown_type", &self.shutdown_type)
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
            pcr_allocation: PcrBanks::whole_banks(config::DEFAULT_PCR_BANKS),
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
            shutdown_type: su::NONE,
            started: false,
            startup_clear: StartupClearAttributes(0),
            pcr_allocation_pending: false,
            pcr: PcrBanks::new(&PcrBanks::whole_banks(config::DEFAULT_PCR_BANKS))?,
            objects: ObjectSlots::new(),
            sessions: SessionSlots::new(),
            locality: 0,
            physical_presence: false,
            nv_available: true,
            failure_mode: false,
            self_test_done: true,
            commits: crate::tpm::core::commit::Commits::new(),
            ever_started: false,
            act: crate::tpm::core::act::Act::default(),
            test_digest: Vec::new(),
            test_failure: None,
            rng,
            hcrtm_buffer: None,
            command_audit_suppressed: false,
        })
    }

    /// Apply TPM2_Startup(TPM_SU_CLEAR).
    ///
    /// Part 1 clause 12.2 makes this a TPM Restart when the previous shutdown
    /// was TPM2_Shutdown(TPM_SU_STATE) and a TPM Reset otherwise. Both clear
    /// the same volatile state; they differ in which of the two reset counters
    /// moves, and a Reset that followed no shutdown at all also has to repair
    /// the NV data that only lived in RAM.
    pub fn on_startup_clear(&mut self) -> TpmResult<()> {
        let restart = self.shutdown_type == su::STATE;
        let disorderly = self.shutdown_type == su::NONE;
        // Taken before the counters below are raised, because it asks what the
        // TPM had done before this startup, not after it. An older record has
        // no such flag, so the counters stand in for it: a TPM that has been
        // through a startup has raised one of them. Clock is not used, because
        // it has already moved on by the time this runs.
        let ever_started =
            self.ever_started || self.clock.reset_count > 0 || self.clock.restart_count > 0;
        self.hierarchies.on_reset(&mut self.rng, !restart)?;
        self.pcr.allocate(&self.pcr_allocation.clone())?;
        if !restart {
            self.pcr.reset_update_counter();
        }
        self.objects.clear();
        // Only a TPM Reset invalidates a saved session context; a TPM Restart
        // flushes what is in memory and leaves the saved ones reloadable.
        if restart {
            self.sessions.flush_loaded();
        } else {
            self.sessions.clear();
        }
        self.nv.on_startup_clear_with(disorderly);
        self.clock.clear_count = self.clock.clear_count.wrapping_add(1);
        if !restart {
            // Part 1 Equation 52 wants a value that "changes on each TPM Reset
            // and has the size of the digest produced by vendorAlg". Drawing
            // one is what makes every saved context stop verifying, which
            // clause 27.3.2 says a TPM Reset alone does.
            use crate::tpm::crypto::rand::Rng;
            let size = crate::tpm::crypto::hash::digest_size(
                config::CONTEXT_INTEGRITY_HASH_ALG,
            )?;
            self.clock.reset_value = self.rng.bytes(size)?;
        }
        if restart {
            self.clock.restart_count = self.clock.restart_count.wrapping_add(1);
        } else {
            self.clock.reset_count = self.clock.reset_count.wrapping_add(1);
            self.clock.total_reset_count = self.clock.total_reset_count.wrapping_add(1);
            self.clock.restart_count = 0;
        }
        self.clock.time = 0;
        self.clock.nv_elapsed = 0;
        // Part 1 clause 33.3.1: other values written to NV on an orderly
        // shutdown "will be advanced to a known safe value on the next startup.
        // However, Clock is not advanced because power outages would cause the
        // clock to be advanced to a time in the future and it could not be
        // adjusted back to an accurate value. To indicate that a value reported
        // in Clock may be a repeat of a previously reported value, a flag
        // (safe) is CLEAR after a non-orderly shutdown."
        //
        // So the repeat is allowed and reported rather than avoided. A TPM that
        // has never been through a startup has had no shutdown of any kind, and
        // so no non-orderly one, which is what the flag taken above tells apart.
        if disorderly && ever_started {
            self.clock.safe = false;
        }
        // Part 1 clause 34.4 lists the command audit digest among the values a
        // TPM Reset returns to their initialization value. A TPM Restart keeps
        // it, which is what clause 32 means by preserving it over an orderly
        // shutdown.
        if !restart {
            self.audit.digest.clear();
        }
        self.audit.exclusive_session = rh::UNASSIGNED;
        // Part 1 Table 41 puts the commit values in the state reset data, which
        // clause 34.4.4 restores on a Startup of any type and initializes only
        // on a TPM Reset. A TPM Restart therefore keeps them, so an
        // outstanding split operation survives an orderly shutdown.
        if !restart {
            self.commits.reset(&mut self.rng)?;
        }
        // Clause 40.2: "On TPM Reset or TPM Restart, all ACT timeouts are set
        // to zero with no side effects (no event triggered)", and the policy
        // goes back to an Empty Policy.
        self.act.on_reset();
        self.lockout.on_startup();
        self.begin_operation(!disorderly, false);
        Ok(())
    }

    /// Let `millis` of powered time pass.
    ///
    /// Part 1 clause 37.2 advances Clock whenever the TPM is powered and Time
    /// since the last _TPM_Init, and clause 40.2 counts the ACT down once per
    /// second over the same period. The transport calls this before each
    /// command, which is the only moment the TPM is asked anything.
    pub fn advance_time(&mut self, millis: u64) -> bool {
        if millis == 0 {
            return false;
        }
        self.clock.clock = self.clock.clock.saturating_add(millis);
        self.clock.time = self.clock.time.saturating_add(millis);
        self.act.advance(millis);
        self.lockout.on_time(self.clock.time);

        // Part 2 clause 10.10.2 requires the copy of Clock in NV to be brought
        // up to date at least every TPM_PT_CLOCK_UPDATE milliseconds. Part 1
        // Table 39 says clockSafe, once CLEAR, "is not SET until the RAM value
        // of Clock rolls over", which is that same moment.
        self.clock.nv_elapsed = self.clock.nv_elapsed.saturating_add(millis);
        if self.clock.nv_elapsed >= u64::from(config::NV_CLOCK_UPDATE_INTERVAL) {
            self.clock.nv_elapsed = 0;
            self.clock.safe = true;
            return true;
        }
        false
    }

    /// Apply TPM2_Startup(TPM_SU_STATE), which is a TPM Resume.
    ///
    /// The saved state is already loaded, so only the volatile pieces that a
    /// Resume still discards are cleared.
    pub fn on_startup_state(&mut self) -> TpmResult<()> {
        // Part 3 clause 9.3.3: on any TPM2_Startup "all transient contexts
        // (objects, sessions, and sequences) shall be flushed from TPM
        // memory". A resume restores what was saved, not what was loaded, and
        // the command can be reached without the platform cycling the power.
        self.objects.clear();
        // Clause 27.5 flushes the sessions in TPM memory on any startup and
        // leaves the saved ones reloadable after a resume.
        self.sessions.flush_loaded();
        // Part 1 clause 8.6.2 keeps the Resume PCR and puts every other
        // register back to its initial value. The NV STCLEAR locks are not
        // touched, because they go away on a TPM Reset or a TPM Restart only.
        self.pcr.on_resume();
        self.clock.restart_count = self.clock.restart_count.wrapping_add(1);
        self.clock.time = 0;
        // The commit values came back with the state file, so a resume keeps
        // them. Only a TPM Reset initializes them, per clause 34.4.4. A state
        // file written before they were recorded has none, and a TPM with no
        // nonce can do nothing at all, so that case takes a fresh one.
        if !self.commits.is_ready() {
            self.commits.reset(&mut self.rng)?;
        }
        // Clause 40.2 preserves ACT timeouts across a TPM Resume, and Part 2
        // Table 46 copies each signaled into its preserveSignaled so a caller
        // can tell that a reset may have been caused by a timer expiring.
        self.act.on_resume();
        self.lockout.on_startup();
        self.begin_operation(true, true);
        Ok(())
    }

    /// Put the TPM into the running state that every TPM2_Startup reaches.
    ///
    /// `orderly` says the startup was preceded by a matching TPM2_Shutdown,
    /// which is what TPMA_STARTUP_CLEAR.orderly reports. The recorded shutdown
    /// type goes back to `su::NONE` so a power loss from here is seen as the
    /// disorderly shutdown that it is.
    fn begin_operation(&mut self, orderly: bool, keep_read_only: bool) {
        // Clause 22.5.1 lifts the restriction "after the next _TPM_Init".
        self.pcr_allocation_pending = false;
        let mut attributes = StartupClearAttributes::PH_ENABLE
            | StartupClearAttributes::SH_ENABLE
            | StartupClearAttributes::EH_ENABLE
            | StartupClearAttributes::PH_ENABLE_NV;
        if orderly {
            attributes |= StartupClearAttributes::ORDERLY;
        }
        // Part 1 clause 42.2: "a TPM exits Read-Only mode if the TPM receives a
        // TPM2_Startup() for TPM Reset or TPM Restart. However Read-Only mode
        // will remain enabled during TPM Resume."
        if keep_read_only && self.startup_clear.has(StartupClearAttributes::READ_ONLY) {
            attributes |= StartupClearAttributes::READ_ONLY;
        }
        self.startup_clear = StartupClearAttributes(attributes);
        self.started = true;
        self.ever_started = true;
        self.shutdown_type = su::NONE;
        // Time started again from zero, so this is a new epoch and any
        // timeout recorded against the previous one has passed.
        self.clock.time_epoch = self.clock.time_epoch.wrapping_add(1);
    }

    /// Record that RAM backed NV data has moved away from what NV holds.
    ///
    /// TPMA_STARTUP_CLEAR.orderly stays SET only while the two agree, so any
    /// write to an Index with TPMA_NV_ORDERLY clears it.
    pub fn nv_is_no_longer_orderly(&mut self) {
        self.startup_clear =
            self.startup_clear.without(StartupClearAttributes::ORDERLY);
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
        // Part 2 clause 10.10.2: "TPM2_Clear() will set Clock to zero." Clause
        // 10.10.3 and clause 10.10.4 reset both counters, and clause 10.10.1
        // has safe "Set to YES on TPM2_Clear()", which it can be because a
        // Clock of zero repeats nothing.
        self.clock.clock = 0;
        self.clock.nv_elapsed = 0;
        self.clock.reset_count = 0;
        self.clock.restart_count = 0;
        self.clock.safe = true;
        // Clause 24.6.1 ends its list with "increment pcrUpdateCounter", and
        // the note beside it explains why: it lets an application build a
        // policy session that TPM2_Clear invalidates.
        self.pcr.bump_update_counter();
        // Part 1 clause 32 resets only the audit counter here. The selected
        // algorithm, the list of audited commands and the digest all survive
        // TPM2_Clear.
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
        // Which profile made this state. The algorithm set decides what PCR
        // banks exist and what keys and Names could have been made, so a file
        // written by one profile does not describe a TPM running the other.
        w.u8(u8::from(crate::tpm::profile::is_strict()));
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
        // The shutdown type is saved so a reload can tell whether the previous
        // shutdown was orderly, which decides how the orderly NV values come
        // back.
        w.u16(self.shutdown_type);

        w.u32(self.pcr_allocation.len() as u32);
        for (a, bits) in &self.pcr_allocation {
            w.u16(*a);
            // The registers of the bank, as the bit array a TPMS_PCR_SELECTION
            // carries.
            let octets = (config::IMPLEMENTATION_PCR as usize).div_ceil(8);
            let mut raw = vec![0u8; octets];
            for (i, set) in bits.iter().enumerate() {
                if *set {
                    raw[i / 8] |= 1 << (i % 8);
                }
            }
            w.u8(octets as u8);
            w.bytes(&raw);
        }
        // A TPM Resume restores the Resume PCR, so their values have to come
        // back with the rest of the state.
        self.pcr.marshal_values(&mut w);
        w.u32(self.pcr.update_counter());

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

        // Part 3 clause 31.2 wants a counter to start past every value an
        // Index of that Name has held "over the lifetime of the TPM", so the
        // high water mark outlives the power as well as the Index.
        w.u64(self.nv.counter_floor());
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
            // The stateClear property of Part 1 clause 30.4.2 comes from the
            // object's ancestors as much as from itself, and they are gone by
            // the time the record is read, so it is written down.
            w.u8(u8::from(object.state_clear));
            object.public.marshal(&mut w);
            match &object.sensitive {
                Some(s) => {
                    w.u8(1);
                    s.marshal(&mut w);
                }
                None => w.u8(0),
            }
        }

        // Part 1 Table 41 puts the commit nonce, counter and array in the
        // state reset data, which clause 34.4.4 saves on any Shutdown(STATE)
        // and restores on the next Startup of any type. A TPM that has not
        // been started has none, and writes none, so the block is either
        // absent or complete and never half there.
        // The block is written whenever anything follows it, so that what comes
        // after starts at a known place. A TPM with no commit values writes an
        // empty nonce, which is the same thing an absent block used to say.
        let (random, count, used) = self.commits.parts();
        if self.commits.is_ready() {
            w.sized16(random);
            w.u64(count);
            w.sized16(used);
        } else {
            w.sized16(&[]);
            w.u64(0);
            w.sized16(&[]);
        }

        // Part 1 clause 40.2 saves the ACT timeout on Shutdown(TPM_SU_STATE):
        // the whole of it when TPM2_ACT_SetTimeout has been used since the last
        // startup, and half otherwise, which stops a caller extending the timer
        // for ever by shutting down and starting up again.
        w.u32(self.act.timeout());
        w.u8(u8::from(self.act.signaled()));
        w.u16(self.act.policy.hash_alg);
        w.sized16(&self.act.policy.digest);
        w.u8(u8::from(self.ever_started));
        // Part 1 clause 42.2 keeps Read-Only mode across a TPM Resume, which
        // goes through this file, so the attributes go with it.
        w.u32(self.startup_clear.0);

        // Part 1 clause 27.5 keeps a saved session context across a TPM Restart
        // and a TPM Resume, and both of those go through a power cycle, so the
        // record of which handles were assigned goes with the state.
        let saved = self.sessions.saved_contexts();
        w.u32(saved.len() as u32);
        for (handle, id) in &saved {
            w.u32(*handle);
            w.u64(*id);
        }
        w.u64(self.sessions.context_counter());
        w.u64(self.sessions.object_counter());

        w.finish()
    }

    /// Rebuild the non-volatile state from `data`, keeping the volatile parts
    /// at their manufactured values.
    pub fn load(data: &[u8]) -> TpmResult<TpmState> {
        let mut state = TpmState::manufacture()?;
        let mut r = Reader::new(data);
        let version = r.u32()?;
        if !matches!(
            version,
            STATE_VERSION
                | STATE_VERSION_WITHOUT_PCR_BITS
                | STATE_VERSION_WITHOUT_STARTUP_CLEAR
                | STATE_VERSION_WITHOUT_COUNTER_FLOOR
                | STATE_VERSION_WITHOUT_OBJECT_COUNTER
                | STATE_VERSION_WITHOUT_RESET_VALUE
                | STATE_VERSION_WITHOUT_SESSIONS
                | STATE_VERSION_WITHOUT_CLEAR_COUNT
                | STATE_VERSION_WITHOUT_PROFILE
        ) {
            return Err(TpmRc(rc::BAD_CONTEXT));
        }
        // A TPM does not change which algorithms it has, so a file from the
        // other profile is refused rather than reinterpreted. Silently loading
        // it would leave keys and PCR banks the running TPM cannot reproduce.
        // A file from before the profile existed was written by a TPM that had
        // the legacy algorithms, because that is all there was.
        let written_strict = if version != STATE_VERSION_WITHOUT_PROFILE {
            // Only zero and one are profiles. Taking anything else as strict
            // would accept a file whose remaining fields cannot be trusted.
            match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(TpmRc(rc::BAD_CONTEXT)),
            }
        } else {
            false
        };
        if written_strict != crate::tpm::profile::is_strict() {
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
        state.clock = ClockState::read(
            &mut r,
            version >= FIRST_WITH_CLEAR_COUNT,
            version >= FIRST_WITH_RESET_VALUE,
        )?;
        // Part 1 Equation 52 wants a value of the vendor digest size, and a
        // record from before it was drawn carries none. No startup short of a
        // reset would fill one, so it is drawn here.
        //
        // A context saved by the build that wrote such a record cannot be
        // loaded by this one in any case: the confidentiality construction
        // changed at the same time, and clause 27.3.1 now puts the size field
        // of the sensitive area under the cipher where that build left it
        // outside. Reading a state file written by another build is not a
        // state change of one running TPM, which is what clause 27.3.2 is
        // about; it is the same situation as a field upgrade, after which a
        // TPM does not undertake to load what it saved before.
        if state.clock.reset_value.is_empty() {
            use crate::tpm::crypto::rand::Rng;
            let size =
                crate::tpm::crypto::hash::digest_size(config::CONTEXT_INTEGRITY_HASH_ALG)?;
            state.clock.reset_value = state.rng.bytes(size)?;
        }
        state.algorithm_set = r.u32()?;
        state.lockout_auth = read_sized(&mut r)?;
        state.lockout_policy = TpmtHa::unmarshal(&mut r)?;
        state.pcr_auth = read_sized(&mut r)?;
        state.pcr_policy = TpmtHa::unmarshal(&mut r)?;
        state.shutdown_type = r.u16()?;

        let count = bounded_count(&mut r, config::HASH_COUNT)?;
        let mut saved_allocation: Vec<(u16, Vec<bool>)> = Vec::with_capacity(count);
        for _ in 0..count {
            let hash_alg = r.u16()?;
            let bits = if version >= FIRST_WITH_PCR_BITS {
                let octets = r.u8()? as usize;
                let raw = r.take(octets)?.to_vec();
                (0..config::IMPLEMENTATION_PCR as usize)
                    .map(|i| raw.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0))
                    .collect()
            } else {
                // A record from before the bits were written named whole banks.
                vec![true; config::IMPLEMENTATION_PCR as usize]
            };
            saved_allocation.push((hash_alg, bits));
        }
        // A file written when this TPM still allocated a bank it no longer
        // implements names that bank here, and the bank is dropped rather than
        // brought back. The values that follow are self describing and a bank
        // with nowhere to go is discarded as they are read, so the record still
        // lines up.
        state.pcr_allocation = saved_allocation
            .into_iter()
            .filter(|(a, _)| config::implemented_pcr_banks().contains(a))
            .collect();
        // Dropping every bank would leave a TPM with no PCR at all, so the
        // allocation a manufactured TPM has is used instead.
        if state.pcr_allocation.is_empty() {
            state.pcr_allocation = PcrBanks::whole_banks(config::DEFAULT_PCR_BANKS);
        }
        // The banks the allocation names are what the TPM comes up with, then
        // the saved register values go back into them.
        state.pcr = PcrBanks::new(&state.pcr_allocation)?;
        state.pcr.unmarshal_values(&mut r)?;
        let saved_update_counter = r.u32()?;

        let count = bounded_count(&mut r, 512)?;
        state.pp_commands = (0..count).map(|_| r.u32()).collect::<TpmResult<_>>()?;

        state.audit.alg = r.u16()?;
        state.audit.digest = read_sized(&mut r)?;
        state.audit.counter = r.u64()?;
        let count = bounded_count(&mut r, 512)?;
        state.audit.commands = (0..count).map(|_| r.u32()).collect::<TpmResult<_>>()?;

        // A record from before this was written down knows only the counters it
        // still holds, which the store works out for itself as they load. One
        // whose highest counter had already been undefined cannot say so, and
        // there is nowhere else to look: a counter of that Name defined again
        // under this build starts from the highest that is left. Part 3 clause
        // 31.2 asks for more than that, and only a record that carries the mark
        // can give it.
        let counter_floor = if version >= FIRST_WITH_COUNTER_FLOOR {
            r.u64()?
        } else {
            0
        };
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
        nv.set_counter_floor(counter_floor);
        state.nv = nv;

        let count = bounded_count(&mut r, config::MIN_EVICT_OBJECTS as usize * 64)?;
        for _ in 0..count {
            let handle = r.u32()?;
            let hierarchy = r.u32()?;
            let tpm_generated = r.u8()? != 0;
            // A record from before the property was written down says nothing
            // about the ancestors of the object it holds, so only the object's
            // own attribute is left to go on, which is read below.
            // Version 4 is where this byte was added, not version 3: the
            // record that bumped the version to 3 wrote the clearCount and
            // nothing here, so reading one from a version 3 file would take
            // the first octet of the public area instead.
            let recorded_state_clear = if version >= FIRST_WITH_PERSISTENT_STATE_CLEAR {
                Some(r.u8()? != 0)
            } else {
                None
            };
            let public = crate::tpm::structures::keys::TpmtPublic::unmarshal(&mut r)?;
            let sensitive = if r.u8()? != 0 {
                Some(crate::tpm::structures::keys::TpmtSensitive::unmarshal(
                    &mut r,
                )?)
            } else {
                None
            };
            // The file is the record of whatever build wrote it, so an
            // object that comes back has to pass what TPM2_Load would apply to
            // it today rather than be trusted for having been saved.
            super::object::validate_restored(&public, sensitive.as_ref())?;
            // Part 3 clause 28.5.1 rule 1.2 refuses to make an object
            // persistent when "the stClear is SET in the object or in an
            // ancestor key", so an object that has the property was never
            // allowed to be here. A file that says otherwise describes a TPM
            // this one cannot be, and is refused the way any other record that
            // cannot be trusted is.
            let state_clear = recorded_state_clear.unwrap_or_else(|| {
                public
                    .object_attributes
                    .has(crate::tpm::structures::attributes::ObjectAttributes::ST_CLEAR)
            });
            if state_clear {
                return Err(TpmRc(rc::BAD_CONTEXT));
            }
            // A persistent object keeps the qualified name it had when it was
            // made persistent, which is rebuilt from its hierarchy.
            let parent_qn = super::names::handle_name(hierarchy);
            let object = Object::new(public, sensitive, hierarchy, &parent_qn, tpm_generated)?;
            state.persistent.insert(handle, object);
        }

        // The commit values were added to the record after the first files
        // were written, so a file that ends here is one from before and is
        // read as having none. Startup then takes a fresh nonce rather than
        // refusing to load a state that is otherwise good.
        if !r.is_empty() {
            let commit_random = read_sized(&mut r)?;
            let commit_count = r.u64()?;
            let commit_used = read_sized(&mut r)?;
            // The nonce and the array have one shape each, so a block of any
            // other size is a damaged file rather than an older one. Accepting
            // a short nonce would leave the TPM deriving commit values from
            // less material than clause 44.2.3 asks for.
            // An empty nonce says the TPM had no commit values when it was
            // written. Anything else has one shape, so a block of another size
            // is a damaged file rather than an older one. Accepting a short
            // nonce would leave the TPM deriving commit values from less
            // material than clause 44.2.3 asks for.
            if commit_random.is_empty() && commit_used.is_empty() {
                // A TPM with no commit values has no counter either, so a
                // count beside the empty buffers is a damaged record.
                if commit_count != 0 {
                    return Err(TpmRc(rc::BAD_CONTEXT));
                }
            } else {
                if commit_random.len() != config::COMMIT_NONCE_BYTES
                    || commit_used.len() != config::MAX_COMMIT_SEQUENCES as usize / 8
                {
                    return Err(TpmRc(rc::BAD_CONTEXT));
                }
                state
                    .commits
                    .restore(commit_random, commit_count, commit_used);
            }
        }

        // The ACT block follows the commit block. A file written before it
        // existed ends here and starts its timer at zero, which is where a TPM
        // Reset puts it anyway.
        if !r.is_empty() {
            let timeout = r.u32()?;
            // The signal is one bit written as an octet, so anything other
            // than the two values it can take is a damaged record.
            let signaled = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(TpmRc(rc::BAD_CONTEXT)),
            };
            let policy_alg = r.u16()?;
            let policy_digest = read_sized(&mut r)?;
            state.act.restore(timeout, signaled);
            state.act.policy = TpmtHa::new(policy_alg, policy_digest)?;
            // The flag was added after the timer block, so a record can carry
            // the timer without it. Such a record was written by a build that
            // had already been running, and reading it as started is the
            // careful way round: it costs one update interval of the clock
            // being reported unsafe, never the other way about.
            state.ever_started = if r.is_empty() {
                true
            } else {
                match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(TpmRc(rc::BAD_CONTEXT)),
                }
            };
        }

        if version >= FIRST_WITH_STARTUP_CLEAR && !r.is_empty() {
            state.startup_clear =
                crate::tpm::structures::attributes::StartupClearAttributes(r.u32()?);
        }

        // Part 1 clause 27.5 keeps a saved session context across a TPM Restart
        // and a TPM Resume. A record from before this was written down names
        // none, so a session saved by that build is not reloadable, which is
        // what a TPM Reset would have done to it anyway.
        // Like the blocks before it, a record that ends here is read as having
        // none rather than being refused.
        if version >= FIRST_WITH_SESSIONS && !r.is_empty() {
            let count = bounded_count(&mut r, config::MAX_ACTIVE_SESSIONS as usize)?;
            let mut saved = Vec::with_capacity(count);
            for _ in 0..count {
                let handle = r.u32()?;
                let id = r.u64()?;
                saved.push((handle, id));
            }
            let counter = r.u64()?;
            // Clause 27.2.2 has two counters. A record from before the second
            // was written down advanced one value for both, and there is no
            // way to take that apart: the saved list names the sessions that
            // are still outstanding, not the numbers the ones that are gone
            // consumed. Winding the session counter back to the newest saved
            // session would hand a number out twice, and a spent context of
            // that number would be taken as the current one, which is the
            // replay clause 27.5 forbids. So the counter stands where it was
            // for both, and the tracking is dropped: a session context from
            // that build no longer loads, which is what the specification
            // already says of one whose tracking the TPM has lost.
            let (saved, counter, object_counter) = if version >= FIRST_WITH_OBJECT_COUNTER {
                (saved, counter, r.u64()?)
            } else {
                (Vec::new(), counter, counter)
            };
            state
                .sessions
                .restore_saved_contexts(saved, counter, object_counter);
        }

        if !r.is_empty() {
            return Err(TpmRc(rc::BAD_CONTEXT));
        }
        state.pcr.set_update_counter(saved_update_counter);
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
    use crate::tpm::constants::{alg, hc, rh};
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
    fn the_failure_counter_comes_down_with_time() {
        // Part 1 clause 16.8.2 decrements failedTries "by one after
        // recoveryTime seconds", and Part 3 clause 25.3.1 measures that
        // "with respect to the Time and not Clock".
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.recovery_time = 10;
        s.lockout.failed_tries = 2;
        s.lockout.next_recovery = 10_000;

        s.advance_time(9_000);
        assert_eq!(s.lockout.failed_tries, 2, "it came down too soon");
        s.advance_time(1_000);
        assert_eq!(s.lockout.failed_tries, 1, "it did not come down");
        s.advance_time(10_000);
        assert_eq!(s.lockout.failed_tries, 0);
        s.advance_time(10_000);
        assert_eq!(s.lockout.failed_tries, 0, "it went below zero");
    }

    #[test]
    fn every_interval_that_passes_takes_one_off() {
        // Part 1 clause 16.8.2 makes recoveryTime "the rate at which
        // failedTries is decremented", so three intervals without a failure
        // take three off rather than one.
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.recovery_time = 10;
        s.lockout.failed_tries = 5;
        s.lockout.next_recovery = 10_000;
        s.advance_time(30_000);
        assert_eq!(s.lockout.failed_tries, 2, "only one interval was counted");
    }

    #[test]
    fn a_startup_starts_the_lockout_timers_against_the_new_time() {
        // Part 3 clause 25.3.1 measures both timers against Time, which a
        // startup restarts, so a deadline from the last epoch means nothing.
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.recovery_time = 10;
        s.lockout.failed_tries = 1;
        s.lockout.next_recovery = 900_000; // far into the epoch that just ended
        s.on_startup_clear().unwrap();
        assert_eq!(s.lockout.next_recovery, 10_000, "the deadline was not rebased");
        s.advance_time(10_000);
        assert_eq!(s.lockout.failed_tries, 0);
    }

    #[test]
    fn read_only_mode_survives_the_record_and_a_resume() {
        // Part 1 clause 42.2: "a TPM exits Read-Only mode if the TPM receives a
        // TPM2_Startup() for TPM Reset or TPM Restart. However Read-Only mode
        // will remain enabled during TPM Resume." A resume goes through the
        // state file, so the mode has to be in it.
        use crate::tpm::structures::attributes::StartupClearAttributes;
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.startup_clear = StartupClearAttributes(
            s.startup_clear.0 | StartupClearAttributes::READ_ONLY,
        );
        s.shutdown_type = su::STATE;
        let saved = s.save().unwrap();

        let mut back = TpmState::load(&saved).unwrap();
        assert!(
            back.startup_clear.has(StartupClearAttributes::READ_ONLY),
            "the record did not carry the mode"
        );
        back.on_startup_state().unwrap();
        assert!(
            back.startup_clear.has(StartupClearAttributes::READ_ONLY),
            "a resume left the mode"
        );

        let mut back = TpmState::load(&saved).unwrap();
        back.on_startup_clear().unwrap();
        assert!(
            !back.startup_clear.has(StartupClearAttributes::READ_ONLY),
            "a restart kept the mode"
        );
    }

    #[test]
    fn a_special_lockout_survives_the_record_and_ends_on_its_own() {
        // Part 1 clause 16.8.5 keeps the state until the TPM has been powered
        // for lockoutRecovery, and clause 25.3.1 measures that against Time,
        // which a power cycle restarts. So the record carries the state and the
        // startup gives it a deadline in the epoch it is about to run in.
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.lockout_recovery = 5;
        s.lockout.in_lockout = true;
        s.lockout.lockout_until = 5_000;
        let saved = s.save().unwrap();

        let mut back = TpmState::load(&saved).unwrap();
        assert!(back.lockout.in_lockout, "the record did not carry it");
        back.on_startup_clear().unwrap();
        assert!(back.lockout.in_lockout, "the startup ended it too soon");
        assert_eq!(back.lockout.lockout_until, 5_000, "it was left without a deadline");
        back.advance_time(5_000);
        assert!(!back.lockout.in_lockout, "it never ended");
    }

    #[test]
    fn a_startup_ends_a_special_lockout_that_has_no_interval() {
        // Part 1 clause 16.8.5: with lockoutRecovery zero "the TPM will not
        // exit this state until the next TPM2_Startup()".
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.lockout_recovery = 0;
        s.lockout.in_lockout = true;
        s.on_startup_clear().unwrap();
        assert!(!s.lockout.in_lockout, "a startup did not end it");

        // With an interval it starts again against the new Time instead.
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.lockout_recovery = 5;
        s.lockout.in_lockout = true;
        s.on_startup_clear().unwrap();
        assert!(s.lockout.in_lockout, "a startup ended it too soon");
        assert_eq!(s.lockout.lockout_until, 5_000);
    }

    #[test]
    fn the_special_lockout_ends_after_its_own_interval() {
        // Part 1 clause 16.8.5: the TPM leaves the special lockout "after the
        // TPM is powered for a configurable time period (lockoutRecovery)".
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.lockout_recovery = 5;
        s.lockout.in_lockout = true;
        s.lockout.lockout_until = 5_000;
        s.advance_time(4_000);
        assert!(s.lockout.in_lockout, "it ended too soon");
        s.advance_time(1_000);
        assert!(!s.lockout.in_lockout, "it did not end");
    }

    #[test]
    fn a_recovery_time_of_zero_switches_the_protection_off() {
        // Part 3 clause 25.3.1: with a recovery time of zero "DA protection is
        // disabled. Authorizations are checked but authorization failures will
        // not cause the TPM to enter lockout."
        let mut s = TpmState::manufacture().unwrap();
        s.lockout.recovery_time = 0;
        assert!(s.lockout.protection_off());
        crate::tpm::commands::dispatch::record_failure(&mut s, true).unwrap();
        assert_eq!(s.lockout.failed_tries, 0, "a failure was counted");
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
        s.shutdown_type = su::STATE;
        s.on_startup_state().unwrap();
        assert_eq!(s.clock.reset_count, resets);
        assert_eq!(s.clock.restart_count, 1);
    }

    #[test]
    fn a_startup_clear_after_a_state_shutdown_is_a_restart() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        assert_eq!(s.clock.reset_count, 1);

        // TPM Restart keeps the reset count and moves the restart count.
        s.shutdown_type = su::STATE;
        s.on_startup_clear().unwrap();
        assert_eq!(s.clock.reset_count, 1);
        assert_eq!(s.clock.total_reset_count, 1);
        assert_eq!(s.clock.restart_count, 1);

        // TPM Reset moves the reset count and puts the restart count back.
        s.shutdown_type = su::CLEAR;
        s.on_startup_clear().unwrap();
        assert_eq!(s.clock.reset_count, 2);
        assert_eq!(s.clock.total_reset_count, 2);
        assert_eq!(s.clock.restart_count, 0);
    }

    #[test]
    fn the_orderly_bit_follows_the_previous_shutdown() {
        let mut s = TpmState::manufacture().unwrap();
        // A fresh TPM has seen no shutdown at all.
        s.on_startup_clear().unwrap();
        assert!(!s.startup_clear.has(StartupClearAttributes::ORDERLY));
        assert_eq!(s.shutdown_type, su::NONE);

        s.shutdown_type = su::CLEAR;
        s.on_startup_clear().unwrap();
        assert!(s.startup_clear.has(StartupClearAttributes::ORDERLY));

        // A write to RAM backed NV data puts the bit back down.
        s.nv_is_no_longer_orderly();
        assert!(!s.startup_clear.has(StartupClearAttributes::ORDERLY));
    }

    #[test]
    fn a_resume_keeps_the_resume_pcr_and_resets_the_rest() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.pcr
            .extend(0, 0, &[(alg::SHA256, vec![1u8; 32])])
            .unwrap();
        s.pcr
            .extend(23, 3, &[(alg::SHA256, vec![2u8; 32])])
            .unwrap();
        let saved = s.pcr.read(alg::SHA256, 0).unwrap().to_vec();
        assert!(s.pcr.read(alg::SHA256, 23).unwrap().iter().any(|v| *v != 0));

        s.shutdown_type = su::STATE;
        s.on_startup_state().unwrap();
        // PCR 0 is a Resume PCR, so it keeps its value.
        assert_eq!(s.pcr.read(alg::SHA256, 0).unwrap(), saved);
        // PCR 23 is not, so it goes back to its initial value.
        assert!(s.pcr.read(alg::SHA256, 23).unwrap().iter().all(|v| *v == 0));
        // PCR 17 starts at ones, so that is where it returns to.
        assert!(s
            .pcr
            .read(alg::SHA256, 17)
            .unwrap()
            .iter()
            .all(|v| *v == 0xff));
    }

    #[test]
    fn a_resume_keeps_the_nv_locks_that_a_reset_would_drop() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();

        let mut public = crate::tpm::structures::nv::NvPublic {
            nv_index: hc::NV_INDEX_FIRST,
            name_alg: alg::SHA256,
            attributes: crate::tpm::structures::attributes::NvAttributes(
                crate::tpm::structures::attributes::NvAttributes::AUTHREAD
                    | crate::tpm::structures::attributes::NvAttributes::AUTHWRITE
                    | crate::tpm::structures::attributes::NvAttributes::READ_STCLEAR,
            ),
            auth_policy: crate::tpm::structures::base::Tpm2bDigest::empty(),
            data_size: 8,
        };
        public.attributes = public.attributes.with(
            crate::tpm::structures::attributes::NvAttributes::WRITE_STCLEAR,
        );
        s.nv
            .define(crate::tpm::core::nv::NvIndex {
                public,
                auth: Vec::new(),
                data: Vec::new(),
                read_locked: false,
                write_locked: false,
            })
            .unwrap();
        s.nv.get_mut(hc::NV_INDEX_FIRST)
            .unwrap()
            .set_read_lock(true);

        // A TPM Resume leaves the lock alone.
        s.shutdown_type = su::STATE;
        s.on_startup_state().unwrap();
        assert!(s.nv.get(hc::NV_INDEX_FIRST).unwrap().read_locked);

        // A TPM Reset drops it.
        s.shutdown_type = su::CLEAR;
        s.on_startup_clear().unwrap();
        assert!(!s.nv.get(hc::NV_INDEX_FIRST).unwrap().read_locked);
    }

    #[test]
    fn the_command_audit_digest_survives_a_restart_but_not_a_reset() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.audit.digest = vec![7u8; 32];

        s.shutdown_type = su::STATE;
        s.on_startup_clear().unwrap();
        assert_eq!(s.audit.digest, vec![7u8; 32], "a TPM Restart keeps it");

        s.shutdown_type = su::CLEAR;
        s.on_startup_clear().unwrap();
        assert!(s.audit.digest.is_empty(), "a TPM Reset drops it");
    }

    #[test]
    fn the_pcr_values_survive_a_save_and_load() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.pcr
            .extend(0, 0, &[(alg::SHA256, vec![3u8; 32])])
            .unwrap();
        let expected = s.pcr.read(alg::SHA256, 0).unwrap().to_vec();
        let counter = s.pcr.update_counter();

        let saved = s.save().unwrap();
        let loaded = TpmState::load(&saved).unwrap();
        assert_eq!(loaded.pcr.read(alg::SHA256, 0).unwrap(), expected);
        assert_eq!(loaded.pcr.update_counter(), counter);
    }

    #[test]
    fn the_shutdown_type_survives_a_save_and_load() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.shutdown_type = su::STATE;
        let saved = s.save().unwrap();
        let loaded = TpmState::load(&saved).unwrap();
        assert_eq!(loaded.shutdown_type, su::STATE);
    }

    #[test]
    fn a_startup_updates_the_pcr_counter_only_when_the_registers_change() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.pcr
            .extend(0, 0, &[(alg::SHA256, vec![1u8; 32])])
            .unwrap();
        assert_eq!(s.pcr.update_counter(), 1);

        // A TPM Resume keeps the registers, so the counter carries over.
        s.shutdown_type = su::STATE;
        s.on_startup_state().unwrap();
        assert_eq!(s.pcr.update_counter(), 1);

        // A TPM Reset puts the registers back, so the counter starts again.
        s.shutdown_type = su::CLEAR;
        s.on_startup_clear().unwrap();
        assert_eq!(s.pcr.update_counter(), 0);
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

    /// A file from a TPM that allocated a bank this one no longer implements
    /// still loads, and comes back without it.
    ///
    /// The record is built by hand rather than by saving, because the point is
    /// a file this build can no longer produce.
    #[test]
    fn a_state_file_naming_a_bank_that_is_gone_still_loads() {
        let mut s = TpmState::manufacture().unwrap();
        s.hierarchies.owner.auth = b"ownerauth".to_vec();
        let saved = s.save().unwrap();

        // Find the allocation, which is a count followed by that many
        // algorithms, and put SM3-256 in front of what is there. The
        // profile lists it as optional and this build does not have it.
        // An entry is the algorithm and the registers it has, as the octets a
        // TPMS_PCR_SELECTION carries.
        fn entry(w: &mut Writer, hash_alg: u16) {
            w.u16(hash_alg);
            w.u8(3);
            w.bytes(&[0xff, 0xff, 0xff]);
        }

        let mut w = Writer::new();
        w.u32(2);
        entry(&mut w, alg::SM3_256);
        entry(&mut w, alg::SHA256);
        let replacement = w.finish().unwrap();

        let mut w = Writer::new();
        w.u32(config::DEFAULT_PCR_BANKS.len() as u32);
        for a in config::DEFAULT_PCR_BANKS {
            entry(&mut w, *a);
        }
        let current = w.finish().unwrap();

        let at = saved
            .windows(current.len())
            .position(|c| c == current.as_slice())
            .expect("the allocation is in the record");
        let mut older = saved[..at].to_vec();
        older.extend_from_slice(&replacement);
        older.extend_from_slice(&saved[at + current.len()..]);

        let back = TpmState::load(&older).expect("a file naming SM3-256 was refused");
        assert_eq!(back.hierarchies.owner.auth, b"ownerauth");
        assert!(
            !back.pcr_allocation.iter().any(|(a, _)| *a == alg::SM3_256),
            "a bank the TPM does not implement must not come back"
        );
        assert!(back.pcr_allocation.iter().any(|(a, _)| *a == alg::SHA256));
    }

    /// Part 2 clause 10.10.1 says safe means "no value of Clock greater than
    /// the current value of Clock has been previously reported by the TPM", and
    /// Part 1 Table 39 has clockSafe CLEAR when a Startup is not orderly and
    /// SET again once the RAM value of Clock rolls over.
    #[test]
    fn a_startup_that_was_not_orderly_says_the_clock_is_not_safe() {
        let mut s = TpmState::manufacture().unwrap();

        // The first startup of a TPM that has never been powered reported no
        // Clock at all, so it cannot be behind one and stays safe.
        s.on_startup_clear().unwrap();
        assert!(s.clock.safe, "the first startup has nothing to be behind");

        // Time passes and the TPM loses power without a shutdown.
        s.advance_time(5_000);
        let before = s.clock.clock;
        s.shutdown_type = su::NONE;
        s.on_startup_clear().unwrap();
        assert!(!s.clock.safe, "a startup that was not orderly is not safe");
        // Clause 33.3.1 says Clock is not moved on: "power outages would cause
        // the clock to be advanced to a time in the future and it could not be
        // adjusted back to an accurate value". The repeat is reported by safe
        // instead of being avoided.
        assert_eq!(s.clock.clock, before, "Clock must not be advanced");

        // It becomes safe again when the value rolls over.
        assert!(!s.advance_time(u64::from(config::NV_CLOCK_UPDATE_INTERVAL) - 1));
        assert!(!s.clock.safe);
        assert!(s.advance_time(1), "the rollover is reported to the caller");
        assert!(s.clock.safe);
    }

    /// A record written before the started flag existed still loads, and is
    /// read the careful way round.
    #[test]
    fn a_record_with_a_timer_but_no_started_flag_still_loads() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.act.set_timeout(90);
        let saved = s.save().unwrap();

        // The flag comes just before the saved session block, so a build that
        // wrote neither produced this.
        let older = &saved[..saved.len() - 1 - SESSION_BLOCK];
        let back = TpmState::load(older).expect("a record without the flag was refused");
        assert_eq!(back.act.timeout(), 90, "the timer still comes back");
        assert!(
            back.ever_started,
            "a record with no flag is read as having been started"
        );
    }

    /// An orderly shutdown keeps the promise, because nothing was lost.
    #[test]
    fn an_orderly_shutdown_leaves_the_clock_safe() {
        let mut s = TpmState::manufacture().unwrap();
        s.on_startup_clear().unwrap();
        s.advance_time(5_000);
        s.shutdown_type = su::CLEAR;
        s.clock.safe = true;
        s.on_startup_clear().unwrap();
        assert!(s.clock.safe);
    }

    /// Octets the timer block occupies when the policy is empty: the
    /// timeout, the signal, the policy algorithm and an empty digest.
    const ACT_BLOCK: usize = 4 + 1 + 2 + 2 + 1;
    /// A saved session block with nothing in it: the count and the two
    /// counters Part 1 clause 27.2.2 keeps apart, with TPMA_STARTUP_CLEAR
    /// ahead of it.
    const SESSION_BLOCK: usize = 4 + (4 + 8 + 8);

    #[test]
    fn a_state_file_without_the_commit_values_still_loads() {
        // The commit values were appended to the record after the first files
        // were written. One of those ends where they would start, and it holds
        // hierarchy seeds and persistent objects that must not be thrown away
        // because of a field that did not exist when it was saved.
        let mut s = TpmState::manufacture().unwrap();
        s.hierarchies.owner.auth = b"ownerauth".to_vec();
        s.persistent.insert(hc::PERSISTENT_FIRST, object());
        // Give it commit values so the block is written and can be cut off
        // again, which is what a file from before them looks like.
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[0x5eu8; 48], b"t").unwrap();
        s.commits.reset(&mut rng).unwrap();
        let saved = s.save().unwrap();

        // Cut the record back to where the trailing blocks begin: the commit
        // nonce, counter and array, and after them the timer.
        let (random, _, used) = s.commits.parts();
        let tail = 2 + random.len() + 8 + 2 + used.len() + ACT_BLOCK + SESSION_BLOCK;
        let older = &saved[..saved.len() - tail];

        let back = TpmState::load(older).expect("an older state file was refused");
        assert_eq!(back.hierarchies.owner.auth, b"ownerauth");
        assert!(back.persistent.contains_key(&hc::PERSISTENT_FIRST));
        // It carries no commit values, so a startup takes a fresh nonce.
        assert!(!back.commits.is_ready());
    }

    #[test]
    fn a_commit_block_of_the_wrong_shape_is_refused() {
        // A file that ends where the block would start is an older one. A file
        // that has a block of some other size is a damaged one, and taking it
        // would leave the TPM deriving commit values from less material than
        // clause 44.2.3 asks for.
        let s = TpmState::manufacture().unwrap();
        let saved = s.save().unwrap();
        // A manufactured TPM has no commit values, so its own block is two
        // empty buffers and a zero counter. Strip that and the timer to get
        // back to where a block would start.
        let base = saved[..saved.len() - (2 + 8 + 2 + ACT_BLOCK + SESSION_BLOCK)].to_vec();

        for (random, used) in [(1usize, 16usize), (64, 1), (1, 1), (63, 16), (64, 15)] {
            let mut bad = base.clone();
            bad.extend_from_slice(&(random as u16).to_be_bytes());
            bad.extend_from_slice(&vec![0xaa; random]);
            bad.extend_from_slice(&0u64.to_be_bytes());
            bad.extend_from_slice(&(used as u16).to_be_bytes());
            bad.extend_from_slice(&vec![0x00; used]);
            assert_eq!(
                TpmState::load(&bad).unwrap_err(),
                TpmRc(rc::BAD_CONTEXT),
                "a block of {random} and {used} octets was accepted"
            );
        }

        // The right shape is taken.
        let mut good = base;
        good.extend_from_slice(&(config::COMMIT_NONCE_BYTES as u16).to_be_bytes());
        good.extend_from_slice(&vec![0xaa; config::COMMIT_NONCE_BYTES]);
        good.extend_from_slice(&0u64.to_be_bytes());
        let used_len = config::MAX_COMMIT_SEQUENCES as usize / 8;
        good.extend_from_slice(&(used_len as u16).to_be_bytes());
        good.extend_from_slice(&vec![0x00; used_len]);
        assert!(TpmState::load(&good).unwrap().commits.is_ready());
    }

    #[test]
    fn the_commit_values_survive_a_save_and_load() {
        let mut s = TpmState::manufacture().unwrap();
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[0x9au8; 48], b"t").unwrap();
        s.commits.reset(&mut rng).unwrap();
        let (r, counter) = s.commits.next(alg::SHA256, b"n", 256).unwrap();
        s.commits.take(counter);

        let back = TpmState::load(&s.save().unwrap()).unwrap();
        assert!(back.commits.is_ready());
        assert_eq!(back.commits.outstanding(), 1);
        // The same counter gives the same value, which is what makes the split
        // operation survive.
        let mut back = back;
        assert_eq!(
            back.commits.use_counter(alg::SHA256, b"n", counter, 256).unwrap(),
            r
        );
    }

    /// A restricted signing key whose scheme is TPM_ALG_NULL, which Part 3
    /// clause 18.1 forbids and no build accepts today.
    fn key_no_build_should_accept() -> Object {
        let public = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::RESTRICTED,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::null(),
                curve_id: crate::tpm::constants::curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(Default::default()),
        };
        Object::new(public, None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap()
    }

    #[test]
    fn a_record_from_each_older_version_still_loads_field_for_field() {
        // Each version added a field in a different place, so a file from one
        // of them has to be read with that version's layout and not with this
        // one's. The records below are built the way those builds wrote them.
        let mut s = TpmState::manufacture().unwrap();
        s.hierarchies.owner.auth = b"ownerauth".to_vec();
        s.persistent.insert(hc::PERSISTENT_FIRST, object());
        // Values that appear nowhere else, so the counters can be found in the
        // record rather than reached by an offset that a later field would
        // silently invalidate.
        s.clock.reset_count = 0x1122_3344;
        s.clock.restart_count = 0x5566_7788;
        s.clock.clear_count = 0x99aa_bbcc;
        s.nv.set_counter_floor(0xaabb_ccdd_eeff_0011);
        let current = s.save().unwrap();

        // Version 8 named whole banks, without the registers each has.
        let mut v8 = current.clone();
        v8[..4].copy_from_slice(&8u32.to_be_bytes());
        {
            // Each entry loses the octet count and the three octets after it.
            let mut out = Vec::with_capacity(v8.len());
            let count_at =
                position_of(&v8, &(config::DEFAULT_PCR_BANKS.len() as u32).to_be_bytes());
            out.extend_from_slice(&v8[..count_at + 4]);
            let mut at = count_at + 4;
            for _ in 0..config::DEFAULT_PCR_BANKS.len() {
                out.extend_from_slice(&v8[at..at + 2]);
                at += 2 + 1 + 3;
            }
            out.extend_from_slice(&v8[at..]);
            v8 = out;
        }
        let back = TpmState::load(&v8).expect("a version 8 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
        assert!(
            back.pcr_allocation.iter().all(|(_, bits)| bits.iter().all(|b| *b)),
            "a record naming whole banks came back with less"
        );

        // Version 7 did not write TPMA_STARTUP_CLEAR.
        let mut v7 = v8.clone();
        v7[..4].copy_from_slice(&7u32.to_be_bytes());
        let sessions_at = v7.len() - (4 + 8 + 8);
        v7.drain(sessions_at - 4..sessions_at);
        let back = TpmState::load(&v7).expect("a version 7 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");

        // Version 6 did not write the counter high water mark.
        let mut v6 = v7.clone();
        v6[..4].copy_from_slice(&6u32.to_be_bytes());
        let floor_at = position_of(&v6, &0xaabb_ccdd_eeff_0011u64.to_be_bytes());
        v6.drain(floor_at..floor_at + 8);
        let back = TpmState::load(&v6).expect("a version 6 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
        assert_eq!(
            back.nv.counter_floor(),
            0,
            "a record with no mark starts without one"
        );

        // Version 5 kept one context counter where there are now two.
        let mut v5 = v6.clone();
        v5[..4].copy_from_slice(&5u32.to_be_bytes());
        v5.truncate(v5.len() - 8);
        let back = TpmState::load(&v5).expect("a version 5 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");

        // Version 4 counted resets rather than drawing a value for each one.
        let mut v4 = v5.clone();
        v4[..4].copy_from_slice(&4u32.to_be_bytes());
        let value_at = position_of_clear_count(&v5) + 4;
        let value_len = 2 + u16::from_be_bytes([v5[value_at], v5[value_at + 1]]) as usize;
        v4.drain(value_at..value_at + value_len);
        let back = TpmState::load(&v4).expect("a version 4 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
        assert_eq!(
            back.clock.reset_value.len(),
            32,
            "a record with no reset value has one drawn for it"
        );
        assert_eq!(
            back.sessions.object_counter(),
            s.sessions.object_counter(),
            "the one counter such a record carries becomes the object one"
        );

        // Version 3 wrote neither the saved session block nor the stateClear
        // byte of a persistent object.
        let mut v3 = v4.clone();
        v3[..4].copy_from_slice(&3u32.to_be_bytes());
        let at = position_of_persistent_flag(&v4);
        v3.remove(at);
        v3.truncate(v3.len() - (4 + 8));
        let back = TpmState::load(&v3).expect("a version 3 record was refused");
        assert_eq!(back.hierarchies.owner.auth, b"ownerauth");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
        assert_eq!(back.clock.clear_count, 0x99aa_bbcc);

        // Version 2 wrote neither the clearCount of the clock nor either of
        // those, and version 1 also wrote no profile byte.
        let mut v2 = v3.clone();
        v2[..4].copy_from_slice(&2u32.to_be_bytes());
        let clear_at = position_of_clear_count(&v3);
        v2.drain(clear_at..clear_at + 4);
        let back = TpmState::load(&v2).expect("a version 2 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
        assert_eq!(back.clock.clear_count, 0, "a record with none starts at zero");

        let mut v1 = v2.clone();
        v1[..4].copy_from_slice(&1u32.to_be_bytes());
        v1.remove(4); // the profile byte
        let back = TpmState::load(&v1).expect("a version 1 record was refused");
        assert_eq!(back.persistent.len(), 1, "the persistent object was lost");
    }

    /// Where a distinctive block of octets sits in a record.
    fn position_of(saved: &[u8], needle: &[u8]) -> usize {
        saved
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the block was not found")
    }

    /// Where the clearCount of the clock sits, found by the two counters that
    /// come before it.
    fn position_of_clear_count(saved: &[u8]) -> usize {
        let mut needle = 0x1122_3344u32.to_be_bytes().to_vec();
        needle.extend_from_slice(&0x5566_7788u32.to_be_bytes());
        let at = saved
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the clock counters were not found");
        at + needle.len()
    }

    /// Where the stateClear byte of the first persistent object sits.
    ///
    /// The record reaches it after the count, the handle, the hierarchy and the
    /// tpmGenerated flag, all of which are fixed width, so the byte is found by
    /// walking to the count rather than by guessing an offset.
    fn position_of_persistent_flag(saved: &[u8]) -> usize {
        // The count is the first place the value one appears as a u32 followed
        // by the handle this test uses, which is enough to find it here.
        let needle: Vec<u8> = 1u32
            .to_be_bytes()
            .iter()
            .chain(hc::PERSISTENT_FIRST.to_be_bytes().iter())
            .copied()
            .collect();
        let at = saved
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the persistent block was not found");
        at + needle.len() + 4 + 1
    }

    #[test]
    fn a_version_5_record_keeps_its_counter_and_drops_its_tracking() {
        // Version 5 moved one counter for both kinds of context. Neither half
        // can be recovered from it: winding the session counter back would
        // hand a number out twice, and leaving it where it is puts an old
        // saved session outside the window. The counter is kept, because
        // reusing a number would let a spent context pass as the current one,
        // and the tracking goes.
        let mut s = TpmState::manufacture().unwrap();
        let session = crate::tpm::core::session::Session::new(
            hc::HMAC_SESSION_FIRST,
            crate::tpm::constants::se::HMAC,
            alg::SHA256,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap();
        let handle = s.sessions.insert(session).unwrap();
        s.sessions.save(handle).unwrap();
        // Every object context that build saved moved the same value.
        for _ in 0..100_000 {
            s.sessions.next_object_id();
        }
        s.nv.set_counter_floor(0x1234_5678_9abc_def0);
        s.startup_clear = crate::tpm::structures::attributes::StartupClearAttributes(0x0a0b_0c0d);
        let mut saved = s.save().unwrap();
        // Version 5 wrote neither TPMA_STARTUP_CLEAR nor the counter mark, and
        // named whole PCR banks without the registers each has.
        let flags_at = position_of(&saved, &0x0a0b_0c0du32.to_be_bytes());
        saved.drain(flags_at..flags_at + 4);
        {
            let count_at =
                position_of(&saved, &(config::DEFAULT_PCR_BANKS.len() as u32).to_be_bytes());
            let mut out = saved[..count_at + 4].to_vec();
            let mut at = count_at + 4;
            for _ in 0..config::DEFAULT_PCR_BANKS.len() {
                out.extend_from_slice(&saved[at..at + 2]);
                at += 2 + 1 + 3;
            }
            out.extend_from_slice(&saved[at..]);
            saved = out;
        }

        // A version 5 record carried one context counter, the one this build
        // keeps for objects, and no counter high water mark.
        let mut v5 = saved.clone();
        v5[..4].copy_from_slice(&5u32.to_be_bytes());
        let counter = s.sessions.object_counter();
        let floor_at = position_of(&v5, &0x1234_5678_9abc_def0u64.to_be_bytes());
        v5.drain(floor_at..floor_at + 8);
        v5.truncate(v5.len() - 8);
        let at = v5.len() - 8;
        v5[at..].copy_from_slice(&counter.to_be_bytes());

        let back = TpmState::load(&v5).unwrap();
        assert_eq!(
            back.sessions.object_counter(),
            counter,
            "the object counter did not take the value the record carried"
        );
        assert!(
            !back.sessions.at_context_gap(),
            "a record with no tracking left reports a gap"
        );
        assert_eq!(
            back.sessions.context_counter(),
            counter,
            "the session counter moved, which would hand a number out twice"
        );
    }

    #[test]
    fn a_state_file_naming_an_unknown_profile_is_refused() {
        let s = TpmState::manufacture().unwrap();
        let mut saved = s.save().unwrap();
        // The profile byte follows the version. Only zero and one name one, so
        // anything else means the rest of the record cannot be placed.
        assert_eq!(saved[4], 0);
        saved[4] = 2;
        assert_eq!(TpmState::load(&saved).unwrap_err(), TpmRc(rc::BAD_CONTEXT));
    }

    /// An RSA key whose modulus is shorter than the keyBits beside it says,
    /// which Part 2 Table 195 makes a contradiction and TPM2_Load refuses.
    fn key_whose_modulus_disagrees() -> Object {
        use crate::tpm::structures::base::Tpm2bPublicKeyRsa;
        let public = TpmtPublic {
            object_type: alg::RSA,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Rsa {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::RSASSA, alg::SHA256),
                key_bits: 2048,
                exponent: 0,
            },
            unique: PublicId::Rsa(Tpm2bPublicKeyRsa::new(vec![0xff; 128]).unwrap()),
        };
        Object::new(public, None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap()
    }

    #[test]
    fn a_persistent_key_whose_material_disagrees_is_refused_on_load() {
        // The restoration path applies what TPM2_Load would apply today, not
        // just the rules every public area shares.
        let mut s = TpmState::manufacture().unwrap();
        s.persistent
            .insert(hc::PERSISTENT_FIRST, key_whose_modulus_disagrees());
        let saved = s.save().unwrap();
        assert_eq!(TpmState::load(&saved).unwrap_err(), TpmRc(rc::KEY_SIZE));
    }

    #[test]
    fn a_persistent_object_an_older_build_accepted_is_refused_on_load() {
        // The file is the record of another build's rules, not of this one, so
        // what it holds is checked on the way back in.
        let mut s = TpmState::manufacture().unwrap();
        s.persistent
            .insert(hc::PERSISTENT_FIRST, key_no_build_should_accept());
        let saved = s.save().unwrap();
        assert_eq!(TpmState::load(&saved).unwrap_err(), TpmRc(rc::SCHEME));
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
        s.pcr_allocation = PcrBanks::whole_banks(&[alg::SHA256, alg::SHA384]);
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
        assert_eq!(
            back.pcr_allocation,
            PcrBanks::whole_banks(&[alg::SHA256, alg::SHA384])
        );
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
        // Two octets, not one: the last octet of the record is the started
        // flag, which a build that came before it did not write, so a record
        // one octet short is an older one rather than a damaged one.
        assert_eq!(
            TpmState::load(&saved[..saved.len() - 2]).unwrap_err(),
            TpmRc(rc::INSUFFICIENT)
        );
        let mut bad = saved.clone();
        bad[0] = 0xff;
        assert_eq!(TpmState::load(&bad).unwrap_err(), TpmRc(rc::BAD_CONTEXT));
        // Trailing octets are refused too. Which code says so depends on
        // where the surplus falls: one octet after a record that carries no
        // commit values looks like the start of that block and runs out, and
        // anything longer is surplus after it.
        let mut extra = saved;
        extra.push(0);
        assert!(TpmState::load(&extra).is_err());
    }

    #[test]
    fn a_bogus_count_in_the_state_is_refused() {
        let s = TpmState::manufacture().unwrap();
        let saved = s.save().unwrap();
        // The PCR allocation is a count followed by that many algorithms, so it
        // can be found rather than guessed at. Spraying a large value over
        // every window instead would pass on a corrupted version tag and say
        // nothing at all about the bound on this count.
        let mut w = Writer::new();
        w.u32(config::DEFAULT_PCR_BANKS.len() as u32);
        for a in config::DEFAULT_PCR_BANKS {
            w.u16(*a);
            w.u8(3);
            w.bytes(&[0xff, 0xff, 0xff]);
        }
        let allocation = w.finish().unwrap();
        // The record holds seeds and proofs taken from the generator, so the
        // same octets could in principle turn up elsewhere. Requiring exactly
        // one occurrence means the test is looking at the allocation and not at
        // some other field that happened to match.
        let found: Vec<usize> = saved
            .windows(allocation.len())
            .enumerate()
            .filter(|(_, c)| *c == allocation.as_slice())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(found.len(), 1, "the allocation was not found exactly once");
        let at = found[0];

        // One more bank than the TPM can hold is refused by the bound, not by
        // the read running out, because the algorithms that follow are there.
        let mut bad = saved.clone();
        bad[at..at + 4].copy_from_slice(&(config::HASH_COUNT as u32 + 1).to_be_bytes());
        assert_eq!(TpmState::load(&bad).unwrap_err(), TpmRc(rc::BAD_CONTEXT));

        // And a count that would take the reader far past the end.
        let mut bad = saved;
        bad[at..at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(TpmState::load(&bad).unwrap_err(), TpmRc(rc::BAD_CONTEXT));
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
