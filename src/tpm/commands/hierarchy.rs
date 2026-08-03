//! Hierarchy and dictionary attack administration, Part 3 clauses 24 and 25.

use crate::tpm::constants::{alg, rc, rh};
use crate::tpm::core::state::TpmState;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::Unmarshal;
use crate::tpm::structures::attributes::{PermanentAttributes, StartupClearAttributes};
use crate::tpm::structures::base::{Tpm2bDigest, TpmtHa};
use crate::tpm::structures::lists::TpmlCc;

use super::dispatch::{Request, Response};
use super::execute::respond;
use super::management::is_pp_eligible;

/// Read a TPMI_YES_NO parameter.
fn yes_no(value: u8) -> TpmResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TpmRc(rc::VALUE)),
    }
}

/// TPM2_HierarchyControl, Part 3 clause 24.3.
pub fn hierarchy_control(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let enable = r.u32()?;
    let new_state = yes_no(r.u8()?).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    // Only the platform may turn a hierarchy back on, and only the platform
    // may control phEnable or phEnableNV.
    let platform_only = matches!(enable, rh::PLATFORM | rh::PLATFORM_NV) || new_state;
    if platform_only && auth_handle != rh::PLATFORM {
        return Err(TpmRc(rc::AUTH_TYPE).with_handle(1));
    }
    match enable {
        rh::PLATFORM => {
            state.hierarchies.platform.enabled = new_state;
            state
                .startup_clear
                .set(StartupClearAttributes::PH_ENABLE, new_state);
            if !new_state {
                state.objects.flush_hierarchy(rh::PLATFORM);
            }
        }
        rh::OWNER => {
            if auth_handle != rh::PLATFORM && auth_handle != rh::OWNER {
                return Err(TpmRc(rc::AUTH_TYPE).with_handle(1));
            }
            state.hierarchies.owner.enabled = new_state;
            state
                .startup_clear
                .set(StartupClearAttributes::SH_ENABLE, new_state);
            if !new_state {
                state.objects.flush_hierarchy(rh::OWNER);
            }
        }
        rh::ENDORSEMENT => {
            if auth_handle != rh::PLATFORM && auth_handle != rh::ENDORSEMENT {
                return Err(TpmRc(rc::AUTH_TYPE).with_handle(1));
            }
            state.hierarchies.endorsement.enabled = new_state;
            state
                .startup_clear
                .set(StartupClearAttributes::EH_ENABLE, new_state);
            if !new_state {
                state.objects.flush_hierarchy(rh::ENDORSEMENT);
            }
        }
        rh::PLATFORM_NV => {
            state.hierarchies.platform_nv_enabled = new_state;
            state
                .startup_clear
                .set(StartupClearAttributes::PH_ENABLE_NV, new_state);
        }
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
    respond(|_| Ok(()))
}

/// TPM2_SetPrimaryPolicy, Part 3 clause 24.4.
pub fn set_primary_policy(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let policy = Tpm2bDigest::unmarshal(&mut r)?;
    let hash_alg = r.u16()?;
    r.expect_end()?;

    if hash_alg == alg::NULL {
        if !policy.is_empty() {
            return Err(TpmRc(rc::SIZE).with_parameter(1));
        }
    } else {
        let size = crate::tpm::crypto::hash::digest_size(hash_alg)
            .map_err(|_| TpmRc(rc::HASH).with_parameter(2))?;
        if policy.len() != size {
            return Err(TpmRc(rc::SIZE).with_parameter(1));
        }
    }
    let value = TpmtHa::new(hash_alg, policy.as_slice().to_vec())?;

    match auth_handle {
        rh::LOCKOUT => state.lockout_policy = value,
        rh::PLATFORM | rh::OWNER | rh::ENDORSEMENT => {
            state.hierarchies.get_mut(auth_handle)?.policy = value;
        }
        // Part 3 clause 24.3.1: "On TPMs implementing Authenticated Countdown
        // Timers (ACT), this command may also be used to set the authorization
        // policy for an ACT." This TPM has the one instance the platform
        // profile asks for.
        rh::ACT_0 => state.act.policy = value,
        _ => return Err(TpmRc(rc::VALUE).with_handle(1)),
    }
    respond(|_| Ok(()))
}

/// TPM2_ChangePPS, Part 3 clause 24.5.
pub fn change_pps(state: &mut TpmState, _request: &Request) -> TpmResult<Response> {
    state.hierarchies.platform.regenerate(&mut state.rng)?;
    state.hierarchies.platform.clear_authorization();
    state.objects.flush_hierarchy(rh::PLATFORM);
    // Everything the platform owns goes away with its seed.
    state
        .persistent
        .retain(|h, _| *h < crate::tpm::constants::hc::PLATFORM_PERSISTENT);
    state.pcr_allocation = crate::tpm::config::DEFAULT_PCR_BANKS.to_vec();
    respond(|_| Ok(()))
}

/// TPM2_ChangeEPS, Part 3 clause 24.6.
pub fn change_eps(state: &mut TpmState, _request: &Request) -> TpmResult<Response> {
    state.hierarchies.endorsement.regenerate(&mut state.rng)?;
    state.hierarchies.endorsement.clear_authorization();
    state.objects.flush_hierarchy(rh::ENDORSEMENT);
    // The seed is no longer the one the manufacturer put in.
    state.permanent = state
        .permanent
        .without(PermanentAttributes::TPM_GENERATED_EPS);
    respond(|_| Ok(()))
}

/// TPM2_Clear, Part 3 clause 24.7.
pub fn clear(state: &mut TpmState, _request: &Request) -> TpmResult<Response> {
    if state.permanent.has(PermanentAttributes::DISABLE_CLEAR) {
        return Err(TpmRc(rc::DISABLED));
    }
    state.on_clear()?;
    state.lockout_auth.clear();
    state.lockout_policy = TpmtHa::null();
    respond(|_| Ok(()))
}

/// TPM2_ClearControl, Part 3 clause 24.8.
pub fn clear_control(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let disable = yes_no(r.u8()?).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;

    // Only the platform may re-enable TPM2_Clear.
    if !disable && auth_handle != rh::PLATFORM {
        return Err(TpmRc(rc::AUTH_TYPE).with_handle(1));
    }
    state
        .permanent
        .set(PermanentAttributes::DISABLE_CLEAR, disable);
    respond(|_| Ok(()))
}

/// TPM2_HierarchyChangeAuth, Part 3 clause 24.9.
pub fn hierarchy_change_auth(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let new_auth = Tpm2bDigest::unmarshal(&mut r)?;
    r.expect_end()?;

    // Part 3 clause 24.9.2 bounds a new authorization value by the digest size
    // of the hash the hierarchy uses.
    if new_auth.len() > crate::tpm::structures::base::MAX_DIGEST_SIZE {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    let value = new_auth.as_slice().to_vec();
    match auth_handle {
        rh::LOCKOUT => state.lockout_auth = value,
        rh::PLATFORM | rh::OWNER | rh::ENDORSEMENT => {
            state.hierarchies.get_mut(auth_handle)?.auth = value;
        }
        _ => return Err(TpmRc(rc::VALUE).with_handle(1)),
    }
    respond(|_| Ok(()))
}

/// TPM2_DictionaryAttackLockReset, Part 3 clause 25.3.
pub fn dictionary_attack_lock_reset(
    state: &mut TpmState,
    _request: &Request,
) -> TpmResult<Response> {
    state.lockout.failed_tries = 0;
    state.lockout.in_lockout = false;
    respond(|_| Ok(()))
}

/// TPM2_DictionaryAttackParameters, Part 3 clause 25.4.
pub fn dictionary_attack_parameters(
    state: &mut TpmState,
    request: &Request,
) -> TpmResult<Response> {
    let mut r = request.reader();
    let max_tries = r.u32()?;
    let recovery_time = r.u32()?;
    let lockout_recovery = r.u32()?;
    r.expect_end()?;

    state.lockout.max_tries = max_tries;
    state.lockout.recovery_time = recovery_time;
    state.lockout.lockout_recovery = lockout_recovery;
    // Setting the parameters also clears the counter.
    state.lockout.failed_tries = 0;
    // Part 3 clause 25.3.1 makes a maximum of zero a way to put the TPM in
    // lockout outright, so no DA protected entity can be used until the
    // parameters are set again.
    state.lockout.in_lockout = max_tries == 0;
    respond(|_| Ok(()))
}

/// TPM2_PP_Commands, Part 3 clause 26.2.
pub fn pp_commands(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let set = TpmlCc::unmarshal(&mut r)?;
    let clear = TpmlCc::unmarshal(&mut r)?;
    r.expect_end()?;

    // Part 3 clause 26.2.1 discards a command that cannot be gated rather than
    // failing, and processes setList first so a command in both lists ends up
    // not requiring physical presence.
    for code in &set.items {
        if !is_pp_eligible(*code) {
            continue;
        }
        if !state.pp_commands.contains(code) {
            state.pp_commands.push(*code);
        }
    }
    for code in &clear.items {
        state.pp_commands.retain(|c| c != code);
    }
    state.pp_commands.sort_unstable();
    respond(|_| Ok(()))
}

/// TPM2_SetAlgorithmSet, Part 3 clause 26.3.
pub fn set_algorithm_set(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let algorithm_set = r.u32()?;
    r.expect_end()?;
    state.algorithm_set = algorithm_set;
    respond(|_| Ok(()))
}

/// TPM2_ReadOnlyControl, Part 3 clause 26.4.
pub fn read_only_control(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let read_only = yes_no(r.u8()?).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    state
        .startup_clear
        .set(StartupClearAttributes::READ_ONLY, read_only);
    respond(|_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::cc;
    use crate::tpm::marshal::Writer;

    #[test]
    fn yes_no_only_accepts_zero_and_one() {
        assert!(!yes_no(0).unwrap());
        assert!(yes_no(1).unwrap());
        assert_eq!(yes_no(2).unwrap_err(), TpmRc(rc::VALUE));
    }

    /// A command buffer with a password authorization and these parameters.
    fn authorized(code: u32, handle: u32, parameters: &[u8]) -> Vec<u8> {
        let mut auth = Writer::new();
        auth.u32(rh::RS_PW);
        auth.u16(0);
        auth.u8(0x01);
        auth.u16(0);
        let auth = auth.finish().unwrap();

        let mut body = Writer::new();
        body.u32(handle);
        body.u32(auth.len() as u32);
        body.bytes(&auth);
        body.bytes(parameters);
        let body = body.finish().unwrap();

        let mut w = Writer::new();
        w.u16(crate::tpm::constants::st::SESSIONS);
        w.u32((10 + body.len()) as u32);
        w.u32(code);
        w.bytes(&body);
        w.finish().unwrap()
    }

    fn response_code(buf: &[u8]) -> u32 {
        u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]])
    }

    #[test]
    fn a_maximum_of_zero_tries_puts_the_tpm_in_lockout() {
        let mut state = TpmState::manufacture().unwrap();
        state.on_startup_clear().unwrap();

        // Part 3 clause 25.3.1 accepts zero and reads it as lockout, rather
        // than refusing it.
        let mut p = Writer::new();
        p.u32(0); // newMaxTries
        p.u32(100); // newRecoveryTime
        p.u32(200); // lockoutRecovery
        let buf = authorized(
            cc::DictionaryAttackParameters,
            rh::LOCKOUT,
            &p.finish().unwrap(),
        );
        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert!(state.lockout.in_lockout);
        assert_eq!(state.lockout.max_tries, 0);
        assert_eq!(state.lockout.recovery_time, 100);
        assert_eq!(state.lockout.lockout_recovery, 200);

        // Being in lockout, the TPM now refuses this command itself, because
        // Part 1 clause 16.8.3 exempts only TPM2_DictionaryAttackLockReset.
        let mut p = Writer::new();
        p.u32(5);
        p.u32(100);
        p.u32(200);
        let buf = authorized(
            cc::DictionaryAttackParameters,
            rh::LOCKOUT,
            &p.finish().unwrap(),
        );
        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        assert_eq!(response_code(&r), rc::LOCKOUT);

        // That reset is the way back out, and the parameters can be set again.
        let reset = authorized(cc::DictionaryAttackLockReset, rh::LOCKOUT, &[]);
        let r = crate::tpm::commands::execute::run(&mut state, 0, &reset);
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert!(!state.lockout.in_lockout);

        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert!(!state.lockout.in_lockout);
        assert_eq!(state.lockout.max_tries, 5);
    }

    #[test]
    fn physical_presence_discards_a_command_it_cannot_gate() {
        let mut state = TpmState::manufacture().unwrap();
        state.on_startup_clear().unwrap();
        state.physical_presence = true;

        // TPM2_Clear can be gated, TPM2_GetRandom cannot. Part 3 clause
        // 26.2.1 discards the second rather than failing the command.
        let mut p = Writer::new();
        p.u32(2);
        p.u32(cc::Clear);
        p.u32(cc::GetRandom);
        p.u32(0); // empty clearList
        let buf = authorized(cc::PP_Commands, rh::PLATFORM, &p.finish().unwrap());
        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert_eq!(state.pp_commands, vec![cc::Clear]);

        // A command in both lists ends up not requiring physical presence,
        // because setList is processed first.
        let mut p = Writer::new();
        p.u32(1);
        p.u32(cc::ClearControl);
        p.u32(1);
        p.u32(cc::ClearControl);
        let buf = authorized(cc::PP_Commands, rh::PLATFORM, &p.finish().unwrap());
        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert_eq!(state.pp_commands, vec![cc::Clear]);
    }
}
