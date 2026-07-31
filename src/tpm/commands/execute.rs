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

    // Part 3 clause 5.5 checks that the sessions ask for a consistent set of
    // things before any of them is used.
    dispatch::check_session_attributes(&request)?;

    // Part 3 clause 5.6 checks each authorization before clause 5.7 decrypts a
    // parameter, and Part 1 clause 18.4 computes cpHash over the parameters as
    // they arrived, so the encrypted form is what the HMAC covers.
    let mut contexts: Vec<dispatch::AuthContext> = Vec::with_capacity(request.sessions.len());
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
        contexts.push(dispatch::AuthContext {
            name: entity.name.clone(),
            auth: entity.auth.clone(),
        });
    }
    let auth_values: Vec<Vec<u8>> = contexts.iter().map(|c| c.auth.clone()).collect();

    // A session past the authorization handles carries no authorization, but
    // if it asks to encrypt or decrypt a parameter, or to audit, it still has
    // to prove it knows the session key. Part 1 clause 19.6.3 requires the
    // HMAC on every such session.
    for index in request.info.auth_handles as usize..request.sessions.len() {
        let name_refs: Vec<&[u8]> = names.iter().map(|n| n.as_slice()).collect();
        dispatch::check_unauthorized_session(state, &request, index, &name_refs)?;
    }

    // Part 1 clause 17.3 evaluates the exclusive status before the command
    // runs, so a command that asks for it and does not have it never executes.
    dispatch::check_audit_session(state, &request)?;

    // The audit digests cover the command parameters as they arrived, so a
    // copy is kept before the first one is decrypted.
    let command_parameters = request.parameters.clone();
    dispatch::decrypt_parameters(state, &mut request, &auth_values)?;

    state.command_audit_suppressed = false;
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
    dispatch::encrypt_parameters(state, &request, &mut parameters, &auth_values)?;

    // Part 1 clause 17.1 and clause 32 update the audit digests only once the
    // command has succeeded and the response has been built.
    dispatch::update_audit(state, &request, &names, &command_parameters, &parameters)?;

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
            &contexts,
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
    use crate::tpm::constants::{alg, rh, se, su};
    use crate::tpm::core::session::Session;
    use crate::tpm::structures::schemes::SymDef;
    use crate::tpm::marshal::{Marshal, Writer};
    use crate::tpm::structures::attributes::SessionAttributes;
    use crate::tpm::structures::base::{Tpm2bAuth, Tpm2bNonce};
    use crate::tpm::structures::capability::AuthCommand;

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

    /// An unbound, unsalted HMAC session, which Part 1 clause 16.6.16 lets
    /// authorize with an empty HMAC.
    fn load_hmac_session(state: &mut TpmState) -> u32 {
        let handle = state.sessions.allocate_handle(se::HMAC).unwrap();
        let s = Session::new(
            handle,
            se::HMAC,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap();
        state.sessions.insert(s).unwrap()
    }

    /// A command with no handles carrying one session with these attributes.
    fn audited(code: u32, handle: u32, attributes: u8, parameters: &[u8]) -> Vec<u8> {
        let auth = AuthCommand {
            session_handle: handle,
            nonce: Tpm2bNonce::new(vec![0u8; 32]).unwrap(),
            session_attributes: SessionAttributes(attributes),
            hmac: Tpm2bAuth::empty(),
        }
        .to_bytes();

        let mut body = Writer::new();
        body.u32(auth.len() as u32);
        body.bytes(&auth);
        body.bytes(parameters);
        let body = body.finish().unwrap();

        let mut w = Writer::new();
        w.u16(st::SESSIONS);
        w.u32((HEADER_SIZE + body.len()) as u32);
        w.u32(code);
        w.bytes(&body);
        w.finish().unwrap()
    }

    /// TPM2_GetRandom carrying one session with the given attributes.
    fn get_random_audited(handle: u32, attributes: u8) -> Vec<u8> {
        audited(cc::GetRandom, handle, attributes, &[0x00, 0x08])
    }

    /// TPM2_GetTestResult, whose response is the same every time it runs.
    fn get_test_result_audited(handle: u32, attributes: u8) -> Vec<u8> {
        audited(cc::GetTestResult, handle, attributes, &[])
    }

    /// The session attributes the TPM echoed in the first response session.
    fn response_session_attributes(buf: &[u8]) -> u8 {
        // header, parameterSize, the sized random buffer, then the session.
        let parameter_size =
            u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]) as usize;
        let session = &buf[14 + parameter_size..];
        let nonce_size = u16::from_be_bytes([session[0], session[1]]) as usize;
        session[2 + nonce_size]
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
    fn an_audit_session_records_the_command_and_becomes_exclusive() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let handle = load_hmac_session(&mut state);

        let attributes = SessionAttributes::CONTINUE_SESSION | SessionAttributes::AUDIT;
        let r = run(&mut state, 0, &get_random_audited(handle, attributes));
        assert_eq!(response_code(&r), rc::SUCCESS);

        let s = state.sessions.get(handle).unwrap();
        assert!(s.audit.is_audit);
        assert_eq!(s.audit.digest.len(), 32);
        assert_eq!(state.audit.exclusive_session, handle);
        // Part 1 clause 17.2 reports the exclusive status the session reached.
        assert_eq!(
            response_session_attributes(&r) & SessionAttributes::AUDIT_EXCLUSIVE,
            SessionAttributes::AUDIT_EXCLUSIVE
        );

        // A second audited command extends the same digest.
        let first = s.audit.digest.clone();
        run(&mut state, 0, &get_random_audited(handle, attributes));
        assert_ne!(state.sessions.get(handle).unwrap().audit.digest, first);
    }

    #[test]
    fn an_unaudited_command_takes_the_exclusive_status_away() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let handle = load_hmac_session(&mut state);
        let attributes = SessionAttributes::CONTINUE_SESSION | SessionAttributes::AUDIT;
        run(&mut state, 0, &get_random_audited(handle, attributes));
        assert_eq!(state.audit.exclusive_session, handle);

        // TPM2_GetRandom is auditable, so running it without the session ends
        // the exclusive run.
        run(&mut state, 0, &get_random(8));
        assert_eq!(state.audit.exclusive_session, rh::UNASSIGNED);

        // Asking for exclusivity that the session no longer has fails the
        // command, and Part 1 clause 17.3 leaves the session alone.
        let exclusive = attributes | SessionAttributes::AUDIT_EXCLUSIVE;
        let r = run(&mut state, 0, &get_random_audited(handle, exclusive));
        assert_eq!(response_code(&r), rc::EXCLUSIVE);
        assert!(state.sessions.get(handle).unwrap().audit.is_audit);
    }

    #[test]
    fn a_policy_session_may_not_audit() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let handle = state.sessions.allocate_handle(se::POLICY).unwrap();
        let s = Session::new(
            handle,
            se::POLICY,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap();
        state.sessions.insert(s).unwrap();

        let attributes = SessionAttributes::CONTINUE_SESSION | SessionAttributes::AUDIT;
        let r = run(&mut state, 0, &get_random_audited(handle, attributes));
        assert_eq!(
            response_code(&r),
            TpmRc(rc::ATTRIBUTES).with_session(1).0
        );
    }

    #[test]
    fn audit_reset_starts_the_digest_again() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let handle = load_hmac_session(&mut state);
        let attributes = SessionAttributes::CONTINUE_SESSION | SessionAttributes::AUDIT;
        run(&mut state, 0, &get_test_result_audited(handle, attributes));
        let first = state.sessions.get(handle).unwrap().audit.digest.clone();
        run(&mut state, 0, &get_test_result_audited(handle, attributes));
        assert_ne!(state.sessions.get(handle).unwrap().audit.digest, first);

        // TPM2_GetTestResult answers the same way every time, so a reset puts
        // the digest back to what the first audit of it produced.
        let reset = attributes | SessionAttributes::AUDIT_RESET;
        run(&mut state, 0, &get_test_result_audited(handle, reset));
        assert_eq!(state.sessions.get(handle).unwrap().audit.digest, first);
    }

    #[test]
    fn command_audit_records_the_selected_commands_only() {
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        assert!(state.audit.digest.is_empty());
        assert_eq!(state.audit.counter, 0);

        // TPM2_GetRandom is not in the list a manufactured TPM starts with.
        run(&mut state, 0, &get_random(8));
        assert!(state.audit.digest.is_empty());

        state.audit.commands.push(cc::GetRandom);
        run(&mut state, 0, &get_random(8));
        assert_eq!(state.audit.digest.len(), 32);
        // Part 1 clause 32 counts the log that just started.
        assert_eq!(state.audit.counter, 1);

        // A second command extends the same log without counting again.
        let first = state.audit.digest.clone();
        run(&mut state, 0, &get_random(8));
        assert_ne!(state.audit.digest, first);
        assert_eq!(state.audit.counter, 1);
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
