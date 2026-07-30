//! The command execution pipeline.
//!
//! [`run`] takes a command buffer and produces a response buffer. It applies
//! the checks Part 3 clause 5 lists in order, calls the command, then builds
//! the response with the session area and any parameter encryption.

use crate::tpm::constants::{cc, rc, st};
use crate::tpm::core::session;
use crate::tpm::core::state::TpmState;
use crate::tpm::device::{error_response, HEADER_SIZE};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::Writer;

use super::dispatch::{self, Request, Response};

/// Run one command buffer and produce the response buffer.
pub fn run(state: &mut TpmState, locality: u8, command: &[u8]) -> Vec<u8> {
    match execute(state, locality, command) {
        Ok(buf) => buf,
        Err(e) => error_response(e),
    }
}

fn execute(state: &mut TpmState, locality: u8, command: &[u8]) -> TpmResult<Vec<u8>> {
    let mut request = dispatch::parse(state, command, locality)?;

    // Part 1 clause 12.3: before TPM2_Startup only TPM2_Startup is accepted,
    // and in failure mode only the two commands that report the failure are.
    if state.failure_mode && !dispatch::allowed_in_failure_mode(request.code) {
        return Err(TpmRc(rc::FAILURE));
    }
    if !state.started && !dispatch::allowed_before_startup(request.code) {
        return Err(TpmRc(rc::INITIALIZE));
    }
    if state.started && request.code == cc::Startup {
        return Err(TpmRc(rc::INITIALIZE));
    }

    // A command that needs physical presence must have it asserted.
    if state.pp_commands.contains(&request.code) && !state.physical_presence {
        return Err(TpmRc(rc::PP));
    }

    // Every handle that carries an authorization is checked in order.
    let mut names: Vec<Vec<u8>> = Vec::with_capacity(request.handles.len());
    for h in &request.handles {
        names.push(dispatch::handle_name(state, *h)?);
    }

    // While the TPM is in lockout, no authorization value that the dictionary
    // attack counter protects may be used, and neither may lockoutAuth. Part 1
    // clause 19.8.3 keeps the exempt entities usable so the platform can still
    // recover the TPM.
    if state.lockout.in_lockout {
        for index in 0..request.info.auth_handles as usize {
            let Ok(handle) = request.handle(index) else {
                continue;
            };
            if handle == crate::tpm::constants::rh::LOCKOUT {
                return Err(TpmRc(rc::LOCKOUT));
            }
            if let Ok(entity) = dispatch::entity(state, handle) {
                if entity.uses_lockout {
                    return Err(TpmRc(rc::LOCKOUT));
                }
            }
        }
    }

    // Part 3 clause 5.6 checks each authorization before clause 5.7 decrypts a
    // parameter, and Part 1 clause 18.4 computes cpHash over the parameters as
    // they arrived, so the encrypted form is what the HMAC covers.
    let mut auth_values: Vec<Vec<u8>> = Vec::with_capacity(request.sessions.len());
    for index in 0..request.info.auth_handles as usize {
        if index >= request.sessions.len() {
            return Err(TpmRc(rc::AUTH_MISSING).with_session(index + 1));
        }
        let handle = request.handle(index)?;
        let entity = dispatch::entity(state, handle).map_err(|e| e.with_handle(index + 1))?;
        let session_handle = request.sessions[index].handle;
        let auth_hash = if session_handle == crate::tpm::constants::rh::RS_PW {
            crate::tpm::constants::alg::SHA256
        } else {
            state.sessions.get(session_handle)?.auth_hash
        };
        let name_refs: Vec<&[u8]> = names.iter().map(|n| n.as_slice()).collect();
        let cp = session::cp_hash(auth_hash, request.code, &name_refs, &request.parameters)?;
        dispatch::check_authorization(state, &request, index, &entity, &cp)?;
        auth_values.push(entity.auth.clone());
    }

    dispatch::decrypt_parameters(state, &mut request)?;

    let response = super::run_command(state, &request)?;

    // The response nonces are rolled forward before the response parameter is
    // encrypted, because Part 1 clause 21.3 keys that encryption with the new
    // nonceTPM.
    let nonces = if request.tag == st::SESSIONS {
        dispatch::roll_response_nonces(state, &request)?
    } else {
        Vec::new()
    };

    let mut parameters = response.parameters.clone();
    dispatch::encrypt_parameters(state, &request, &mut parameters)?;

    let mut body = Writer::new();
    if let Some(h) = response.handle {
        body.u32(h);
    }
    if request.tag == st::SESSIONS {
        body.u32(parameters.len() as u32);
    }
    body.bytes(&parameters);
    if request.tag == st::SESSIONS {
        let area = dispatch::build_response_sessions(
            state,
            &request,
            rc::SUCCESS,
            &parameters,
            &nonces,
            &auth_values,
        )?;
        body.bytes(&area);
    }
    let body = body.finish()?;

    dispatch::close_sessions(state, &request);
    flush_if_needed(state, &request);

    let mut w = Writer::with_capacity(HEADER_SIZE + body.len());
    w.u16(request.tag);
    w.u32((HEADER_SIZE + body.len()) as u32);
    w.u32(rc::SUCCESS);
    w.bytes(&body);
    w.finish()
}

/// Drop the handle a command with the flushed attribute was given.
fn flush_if_needed(state: &mut TpmState, request: &Request) {
    if !request.info.flushed {
        return;
    }
    // The flushed handle is the sequence or object handle, which is the last
    // handle in the handle area for every command with the attribute.
    if let Some(handle) = request.handles.last() {
        let _ = state.objects.remove(*handle);
    }
}

/// Build a response from a closure that writes the parameters.
pub fn respond<F>(f: F) -> TpmResult<Response>
where
    F: FnOnce(&mut Writer) -> TpmResult<()>,
{
    let mut w = Writer::new();
    f(&mut w)?;
    Response::from_writer(w)
}

/// Build a response that leads with a handle.
pub fn respond_with_handle<F>(handle: u32, f: F) -> TpmResult<Response>
where
    F: FnOnce(&mut Writer) -> TpmResult<()>,
{
    let mut w = Writer::new();
    f(&mut w)?;
    Response::with_handle(handle, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::su;
    use crate::tpm::marshal::Writer;

    fn startup(su_type: u16) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(st::NO_SESSIONS);
        w.u32(12);
        w.u32(cc::Startup);
        w.u16(su_type);
        w.finish().unwrap()
    }

    fn get_random(bytes: u16) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(st::NO_SESSIONS);
        w.u32(12);
        w.u32(cc::GetRandom);
        w.u16(bytes);
        w.finish().unwrap()
    }

    fn response_code(buf: &[u8]) -> u32 {
        u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]])
    }

    #[test]
    fn only_startup_is_accepted_before_startup() {
        let mut state = TpmState::manufacture().unwrap();
        let r = run(&mut state, 0, &get_random(8));
        assert_eq!(response_code(&r), rc::INITIALIZE);

        let r = run(&mut state, 0, &startup(su::CLEAR));
        assert_eq!(response_code(&r), rc::SUCCESS);
        assert!(state.started);
    }

    #[test]
    fn startup_twice_is_refused() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let r = run(&mut state, 0, &startup(su::CLEAR));
        assert_eq!(response_code(&r), rc::INITIALIZE);
    }

    #[test]
    fn failure_mode_leaves_only_the_reporting_commands() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        state.failure_mode = true;
        let r = run(&mut state, 0, &get_random(8));
        assert_eq!(response_code(&r), rc::FAILURE);

        let mut w = Writer::new();
        w.u16(st::NO_SESSIONS);
        w.u32(10);
        w.u32(cc::GetTestResult);
        let r = run(&mut state, 0, &w.finish().unwrap());
        assert_eq!(response_code(&r), rc::SUCCESS);
    }

    #[test]
    fn an_unknown_command_is_reported() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let mut w = Writer::new();
        w.u16(st::NO_SESSIONS);
        w.u32(10);
        w.u32(0x0000_0123);
        let r = run(&mut state, 0, &w.finish().unwrap());
        assert_eq!(response_code(&r), rc::COMMAND_CODE);
    }

    #[test]
    fn a_command_needing_physical_presence_is_gated() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        state.pp_commands.push(cc::GetRandom);
        let r = run(&mut state, 0, &get_random(8));
        assert_eq!(response_code(&r), rc::PP);
        state.physical_presence = true;
        let r = run(&mut state, 0, &get_random(8));
        assert_eq!(response_code(&r), rc::SUCCESS);
    }
}
