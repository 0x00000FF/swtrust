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
    // Part 1 clause 12.3: in failure mode only the two commands that report
    // the failure are accepted, and Part 3 clause 10.4.1 adds that "if the TPM
    // is in Failure mode, then tag is required to be TPM_ST_NO_SESSIONS or the
    // TPM shall return TPM_RC_FAILURE". Both are settled from the header
    // alone, before the session area is parsed: a TPM in failure mode has no
    // working session logic, so it must not answer for one.
    if state.failure_mode {
        let header = crate::tpm::device::parse_header(command)?;
        if !dispatch::allowed_in_failure_mode(header.code)
            || header.tag != crate::tpm::constants::st::NO_SESSIONS
        {
            return Err(TpmRc(rc::FAILURE));
        }
    }
    let mut request = dispatch::parse(state, command, locality)?;

    if !state.started && !dispatch::allowed_before_startup(request.code) {
        return Err(TpmRc(rc::INITIALIZE));
    }
    // Part 1 clause 34.7.2.2: "When an external device is used for
    // non-volatile storage, that device may not always be accessible to the
    // TPM command execution engine. When the memory is not accessible,
    // operations that require update of NV will return TPM_RC_NV_UNAVAILABLE."
    // The answer comes before the command runs, so nothing changes that the
    // file cannot be told about.
    // Part 3 clause 4.2.6 adds to the commands the table marks: "Any command
    // that uses authorization may cause a write to NV if there is an
    // authorization failure", which Part 1 clause 7.4 counts as NV state. A
    // command carrying an authorization session is therefore one that may
    // require an NV update, whatever its own decoration says.
    let writes_nv = super::table::lookup(request.code)
        .map(|i| i.nv)
        .unwrap_or(false)
        || request.info.auth_handles > 0;
    if (!state.nv_available || state.nv_write_failed) && writes_nv {
        return Err(TpmRc(rc::NV_UNAVAILABLE));
    }
    if state.started && request.code == cc::Startup {
        return Err(TpmRc(rc::INITIALIZE));
    }

    // A command that needs physical presence must have it asserted. Part 3
    // clause 26.2.1 says TPM2_PP_Commands always does, whatever the list that
    // command itself maintains happens to hold. For the rest, the list makes a
    // command need it only "when the handle associated with the authorization
    // is TPM_RH_PLATFORM", so a command that several hierarchies may authorize
    // is gated on the one the caller named.
    // The platform handle is not always the first: TPM2_NV_UndefineSpaceSpecial
    // names the Index first and the platform second, and both carry
    // authorization.
    let auth_handles = request.info.auth_handles as usize;
    let listed = state.pp_commands.contains(&request.code)
        && request
            .handles
            .iter()
            .take(auth_handles)
            .any(|h| *h == crate::tpm::constants::rh::PLATFORM);
    if (request.code == cc::PP_Commands || listed) && !state.physical_presence {
        return Err(TpmRc(rc::PP));
    }

    // A command whose schematic has no parameters is refused here rather than
    // after it has run, so a malformed buffer cannot change anything.
    if super::handles::takes_no_parameters(request.code) && !request.parameters.is_empty() {
        return Err(TpmRc(rc::SIZE));
    }

    // Part 3 clause 5.4 refuses a handle whose value the command syntax does
    // not allow, before anything is done with the entity it names.
    for (index, handle) in request.handles.iter().enumerate() {
        if let Some(kind) = dispatch::handle_kind(request.code, index) {
            if !dispatch::handle_allows(kind, *handle) {
                return Err(TpmRc(rc::VALUE).with_handle(index + 1));
            }
        }
    }

    // Part 1 clause 42.2 item 2: "a device supporting Read-Only mode must
    // reject any affected command before performing authorization checks", and
    // clause 42.3 says such a command "will have no effect on the TPM state".
    if state
        .startup_clear
        .has(crate::tpm::structures::attributes::StartupClearAttributes::READ_ONLY)
    {
        if super::table::refused_when_read_only(request.code) {
            return Err(TpmRc(rc::READ_ONLY));
        }
        if super::table::read_only_needs_a_volatile_index(request.code) {
            let handle = request.handle(1).or_else(|_| request.handle(0))?;
            let index = state.nv.get(handle).map_err(|e| e.with_handle(1))?;
            let volatile = index
                .public
                .attributes
                .has(crate::tpm::structures::attributes::NvAttributes::ORDERLY)
                && index
                    .public
                    .attributes
                    .has(crate::tpm::structures::attributes::NvAttributes::CLEAR_STCLEAR);
            if !volatile {
                return Err(TpmRc(rc::READ_ONLY));
            }
        }
        // Table 207 marks TPM2_PolicySecret not permitted when its
        // authorization entity is a PIN Index, because the authorization moves
        // that Index's counter.
        if request.code == cc::PolicySecret {
            let handle = request.handle(0)?;
            if crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
                if let Ok(index) = state.nv.get(handle) {
                    if matches!(
                        index.public.attributes.index_type(),
                        crate::tpm::structures::attributes::nt::PIN_FAIL
                            | crate::tpm::structures::attributes::nt::PIN_PASS
                    ) {
                        return Err(TpmRc(rc::READ_ONLY));
                    }
                }
            }
        }
    }

    // Every handle that carries an authorization is checked in order.
    // Part 3 clause 5.3 resolves the handle area before the command runs, so a
    // handle that names nothing is reported from here. Part 2 clause 6.6.2 puts
    // the handle number in the N field, and this is where the number is known.
    let mut names: Vec<Vec<u8>> = Vec::with_capacity(request.handles.len());
    for (index, h) in request.handles.iter().enumerate() {
        dispatch::check_handle_available(state, *h).map_err(|e| e.with_handle(index + 1))?;
        names.push(dispatch::handle_name(state, *h).map_err(|e| e.with_handle(index + 1))?);
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

    // Part 2 clause 6.6 defines TPM_RC_FAILURE as commands not being accepted
    // because of a TPM failure, and Part 1 Figure 7 makes that the answer of a
    // TPM in failure mode. A command that answers it has therefore found
    // something the TPM cannot carry on from: a failed pair-wise consistency
    // test on a key it just generated, an exhausted generator, or a library
    // call that should not fail. The TPM enters failure mode so no further
    // cryptographic output is produced, which is what clause 10.1.1.1 of the
    // FIPS 140-3 guidance requires of any self test failure.
    let response = match super::run_command(state, &request) {
        Ok(response) => response,
        Err(e) => {
            if e.value() == rc::FAILURE {
                state.failure_mode = true;
                state.self_test_done = false;
                if state.test_failure.is_none() {
                    state.test_failure = Some("conditional self test".to_string());
                }
            }
            return Err(e);
        }
    };

    // Every command calls Reader::expect_end once it has read its parameters,
    // so surplus octets are refused before anything changes. This catches a
    // command that did not, where the only harm is that the response code
    // arrives after the action rather than before it.
    request.end_of_parameters()?;

    // The response nonces are rolled forward before the response parameter is
    // encrypted, because Part 1 clause 21.3 keys that encryption with the new
    // nonceTPM.
    let nonces = if request.tag == st::SESSIONS {
        dispatch::roll_response_nonces(state, &request)?
    } else {
        Vec::new()
    };

    // Part 3 clause 24.6.1: "if this command is authorized using lockoutAuth,
    // the HMAC in the response shall use the new lockoutAuth value (that is,
    // the Empty Buffer) when computing the response HMAC." Every other command
    // answers with the value it was authorized by, which is the one taken
    // before it ran.
    let mut contexts = contexts;
    if request.code == crate::tpm::constants::cc::Clear
        && request.handle(0) == Ok(crate::tpm::constants::rh::LOCKOUT)
    {
        if let Some(first) = contexts.first_mut() {
            first.auth.clear();
        }
    }
    // Part 3 clause 24.8.1 says of TPM2_HierarchyChangeAuth that "the response
    // HMAC is computed using the new authValue", which the command has just
    // written into the hierarchy.
    if request.code == crate::tpm::constants::cc::HierarchyChangeAuth {
        if let (Some(first), Ok(handle)) = (contexts.first_mut(), request.handle(0)) {
            if let Ok(entity) = dispatch::entity(state, handle) {
                first.auth = entity.auth;
            }
        }
    }

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

/// Drop the sequence a command with the flushed attribute was given.
///
/// Every command that carries TPMA_CC.flushed completes a sequence, so the
/// context that goes away is the sequence object. Where its handle sits in the
/// handle area differs by command.
fn flush_if_needed(state: &mut TpmState, request: &Request) {
    if !request.info.flushed {
        return;
    }
    let index = match request.code {
        // TPM2_EventSequenceComplete names the PCR first.
        cc::EventSequenceComplete => 1,
        _ => 0,
    };
    if let Some(handle) = request.handles.get(index) {
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
    fn a_command_answering_tpm_rc_failure_enters_failure_mode() {
        // Part 2 clause 6.6 defines TPM_RC_FAILURE as commands not being
        // accepted because of a TPM failure, so a command that answers it has
        // found something the TPM cannot carry on from. Clause 10.1.1.1 of the
        // FIPS 140-3 guidance requires that to stop further cryptographic
        // output, which is what a conditional self test failure relies on.
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        assert!(!state.failure_mode);

        // An exhausted generator is a failure the caller can reach.
        state.rng.set_reseed_counter(u64::MAX);
        let r = run(&mut state, 0, &get_random(8));
        assert_eq!(response_code(&r), rc::FAILURE);
        assert!(state.failure_mode, "failure mode was not entered");
        assert!(!state.self_test_done);
        assert!(state.test_failure.is_some());

        // Nothing cryptographic runs afterwards, and reporting still does.
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
        assert_eq!(
            state.audit.digest.len(),
            crate::tpm::crypto::hash::digest_size(state.audit.alg).unwrap()
        );
        // Part 1 clause 32 counts the log that just started.
        assert_eq!(state.audit.counter, 1);

        // A second command extends the same log without counting again.
        let first = state.audit.digest.clone();
        run(&mut state, 0, &get_random(8));
        assert_ne!(state.audit.digest, first);
        assert_eq!(state.audit.counter, 1);
    }

    #[test]
    fn flushing_an_audit_session_by_alias_clears_its_exclusivity() {
        // Part 1 clause 17.2 gives up exclusivity when the session that held
        // it is flushed, and Part 3 clause 28.4.1 lets that flush name the
        // session with any upper octet.
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let handle = load_hmac_session(&mut state);
        let attributes = SessionAttributes::CONTINUE_SESSION | SessionAttributes::AUDIT;
        run(&mut state, 0, &get_random_audited(handle, attributes));
        assert_eq!(state.audit.exclusive_session, handle);

        let aliased = 0x2000_0000 | (handle & 0x00FF_FFFF);
        let mut p = Writer::new();
        p.u32(aliased);
        let mut w = Writer::new();
        let body = p.finish().unwrap();
        w.u16(st::NO_SESSIONS);
        w.u32((HEADER_SIZE + body.len()) as u32);
        w.u32(cc::FlushContext);
        w.bytes(&body);
        let r = run(&mut state, 0, &w.finish().unwrap());
        assert_eq!(response_code(&r), rc::SUCCESS, "FlushContext -> {:08x}", response_code(&r));
        assert_eq!(
            state.audit.exclusive_session, rh::UNASSIGNED,
            "the flushed session still holds exclusivity"
        );
    }

    #[test]
    fn a_failed_authorization_still_counts_against_the_lockout() {
        // Part 3 clause 5.6 leaves the TPM unchanged when a command fails,
        // except for the dictionary attack counter. The command action runs
        // against a copy, so this checks that the counter is not rolled back
        // with it.
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        state.lockout_auth = b"secret".to_vec();

        let mut auth = Writer::new();
        auth.u32(rh::RS_PW);
        auth.u16(0);
        auth.u8(0x01);
        auth.u16(5);
        auth.bytes(b"wrong");
        let auth = auth.finish().unwrap();

        let mut body = Writer::new();
        body.u32(rh::LOCKOUT);
        body.u32(auth.len() as u32);
        body.bytes(&auth);
        let body = body.finish().unwrap();

        let mut w = Writer::new();
        w.u16(st::SESSIONS);
        w.u32((HEADER_SIZE + body.len()) as u32);
        w.u32(cc::DictionaryAttackLockReset);
        w.bytes(&body);
        let buf = w.finish().unwrap();

        assert_eq!(state.lockout.failed_tries, 0);
        let r = run(&mut state, 0, &buf);
        assert_eq!(response_code(&r) & 0x03f, rc::AUTH_FAIL & 0x03f);
        assert_eq!(
            state.lockout.failed_tries, 1,
            "the failure count was rolled back with the command"
        );
    }

    #[test]
    fn a_failed_command_leaves_the_state_alone() {
        // Everything other than the failure count is unchanged, which is the
        // rest of what Part 3 clause 5.6 asks for.
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        let before = state.pcr.read(alg::SHA256, 0).unwrap().to_vec();
        let counter = state.pcr.update_counter();

        // TPM2_PCR_Extend with a digest that is too short for the bank fails
        // after the command has begun reading its parameters.
        let mut auth = Writer::new();
        auth.u32(rh::RS_PW);
        auth.u16(0);
        auth.u8(0x01);
        auth.u16(0);
        let auth = auth.finish().unwrap();

        let mut params = Writer::new();
        params.u32(1);
        params.u16(alg::SHA256);
        params.bytes(&[0x11u8; 20]);
        let params = params.finish().unwrap();

        let mut body = Writer::new();
        body.u32(crate::tpm::constants::hc::PCR_FIRST);
        body.u32(auth.len() as u32);
        body.bytes(&auth);
        body.bytes(&params);
        let body = body.finish().unwrap();

        let mut w = Writer::new();
        w.u16(st::SESSIONS);
        w.u32((HEADER_SIZE + body.len()) as u32);
        w.u32(cc::PCR_Extend);
        w.bytes(&body);
        let r = run(&mut state, 0, &w.finish().unwrap());
        assert_ne!(response_code(&r), rc::SUCCESS);
        assert_eq!(state.pcr.read(alg::SHA256, 0).unwrap(), before);
        assert_eq!(state.pcr.update_counter(), counter);
    }

    #[test]
    fn a_command_needing_physical_presence_is_gated() {
        // Part 3 clause 26.2.1 makes a listed command require physical
        // presence "when the handle associated with the authorization is
        // TPM_RH_PLATFORM", so the same command authorized by another
        // hierarchy is not gated.
        let mut state = TpmState::manufacture().unwrap();
        run(&mut state, 0, &startup(su::CLEAR));
        state.pp_commands.push(cc::ClearControl);

        let clear_control = |handle: u32| -> Vec<u8> {
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
            body.u8(0); // disable
            let body = body.finish().unwrap();

            let mut w = Writer::new();
            w.u16(st::SESSIONS);
            w.u32((HEADER_SIZE + body.len()) as u32);
            w.u32(cc::ClearControl);
            w.bytes(&body);
            w.finish().unwrap()
        };

        let r = run(&mut state, 0, &clear_control(rh::PLATFORM));
        assert_eq!(response_code(&r), rc::PP);
        // TPM_RH_LOCKOUT also authorizes this command, and the list does not
        // reach it. Whatever else that authorization has to satisfy, physical
        // presence is not part of it.
        let r = run(&mut state, 0, &clear_control(rh::LOCKOUT));
        assert_ne!(response_code(&r), rc::PP);

        state.physical_presence = true;
        let r = run(&mut state, 0, &clear_control(rh::PLATFORM));
        assert_eq!(response_code(&r), rc::SUCCESS);
    }

    #[test]
    fn only_the_commands_the_schematics_mark_may_be_gated() {
        // Part 3 clause 4.2.5: TPM_RH_PLATFORM+{PP} says "Physical Presence
        // may be required when platformAuth/platformPolicy is provided. The
        // commands with this notation may be in the setList or clearList of
        // TPM2_PP_Commands()."
        use crate::tpm::commands::management::is_pp_eligible;

        for code in [
            cc::ChangePPS,
            cc::NV_DefineSpace,
            cc::Clear,
            cc::ClearControl,
            cc::CreatePrimary,
            cc::CreateLoaded,
            cc::HierarchyChangeAuth,
            cc::SetPrimaryPolicy,
            cc::NV_UndefineSpaceSpecial,
            cc::SetCommandCodeAuditStatus,
            cc::PCR_Allocate,
            cc::ClockSet,
        ] {
            assert!(is_pp_eligible(code), "{code:#010x} carries +{{PP}}");
        }

        // A command whose schematic has no such notation, one with no handle
        // at all, and one this TPM does not have. TPM2_PP_Commands carries the
        // unconditional +PP of clause 4.2.4 instead, so neither list may hold
        // it.
        assert!(!is_pp_eligible(cc::PP_Commands));
        assert!(!is_pp_eligible(cc::NV_Read));
        assert!(!is_pp_eligible(cc::GetRandom));
        assert!(!is_pp_eligible(0x2000_0000));
    }
}
