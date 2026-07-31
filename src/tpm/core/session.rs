//! Authorization sessions, Part 1 clauses 19 and 21.
//!
//! A session carries a rolling pair of nonces, a session key derived when it
//! was started, and either an HMAC state or a policy digest. The HMAC that
//! authorizes a command is computed over the command parameter digest and the
//! nonces, keyed by the session key concatenated with the authorization value
//! of the entity being used.

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::{alg, hc, rc, se};
use crate::tpm::crypto::hash;
use crate::tpm::crypto::hmac::{hmac_parts, kdfa};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::structures::attributes::SessionAttributes;
use crate::tpm::structures::schemes::SymDef;

/// The label of the session key derivation.
pub const LABEL_SESSION_KEY: &str = "ATH";
/// The label of the parameter encryption key derivation.
pub const LABEL_CFB: &str = "CFB";

/// The state a policy session accumulates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyState {
    /// The running policy digest.
    pub digest: Vec<u8>,
    /// Set by TPM2_PolicyCommandCode.
    pub command_code: Option<u32>,
    /// Set by TPM2_PolicyCpHash.
    pub cp_hash: Option<Vec<u8>>,
    /// Set by TPM2_PolicyNameHash or TPM2_PolicyDuplicationSelect.
    pub name_hash: Option<Vec<u8>>,
    /// Set by TPM2_PolicyLocality, as a TPMA_LOCALITY bit map.
    pub locality: Option<u8>,
    /// Set by TPM2_PolicyPCR, the counter value when the policy was made.
    pub pcr_update_counter: Option<u32>,
    /// Set by TPM2_PolicyAuthValue, meaning the authValue must be proven.
    pub auth_value_needed: bool,
    /// Set by TPM2_PolicyPassword, meaning the authValue is given in the clear.
    pub password_needed: bool,
    /// Set by TPM2_PolicyNvWritten.
    pub nv_written: Option<bool>,
    /// Set by TPM2_PolicyTemplate.
    pub template_hash: Option<Vec<u8>>,
    /// Set by TPM2_PolicyParameters.
    pub parameters_hash: Option<Vec<u8>>,
    /// Set by TPM2_PolicyPhysicalPresence.
    pub physical_presence_required: bool,
    /// When the authorization expires, in the TPM's time base.
    pub expiration: Option<u64>,
    /// The nonce that a ticket for this policy is bound to.
    pub timeout_nonce: Vec<u8>,
}

/// The audit state of a session.
///
/// Exclusivity is not held here. Part 1 clause 17.2 gives the TPM a single
/// exclusive audit session, which [`crate::tpm::core::state::AuditState`]
/// records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditState {
    pub is_audit: bool,
    pub digest: Vec<u8>,
}

/// Extend an audit digest, Part 1 clause 17.1 and clause 32.
///
/// `auditDigest_new = H(auditDigest_old || cpHash || rpHash)`. An empty
/// `digest` starts a new sequence, which the equation begins from a Zero
/// Digest of the size the hash produces.
pub fn extend_audit(
    hash_alg: u16,
    digest: &[u8],
    cp_hash: &[u8],
    rp_hash: &[u8],
) -> TpmResult<Vec<u8>> {
    let size = hash::digest_size(hash_alg)?;
    let zero = vec![0u8; size];
    let old = if digest.len() == size { digest } else { &zero };
    hash::digest_parts(hash_alg, &[old, cp_hash, rp_hash])
}

/// One authorization session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub handle: u32,
    /// TPM_SE_HMAC, TPM_SE_POLICY or TPM_SE_TRIAL.
    pub session_type: u8,
    /// The hash used for the session key, the HMAC and the policy digest.
    pub auth_hash: u16,
    /// The most recent nonce the TPM produced.
    pub nonce_tpm: Vec<u8>,
    /// The most recent nonce the caller supplied.
    pub nonce_caller: Vec<u8>,
    /// The key derived at TPM2_StartAuthSession, empty for an unsalted and
    /// unbound session.
    pub session_key: Vec<u8>,
    /// The entity the session is bound to, or TPM_RH_NULL.
    pub bind: u32,
    /// The Name of the bound entity, used to decide whether the authValue is
    /// already covered by the session key.
    pub bind_name: Vec<u8>,
    /// True when the bound entity is protected by the dictionary attack
    /// counter, which Part 1 clause 16.8.7 carries into every use of the
    /// session because the session key holds that entity's authValue.
    pub bind_uses_lockout: bool,
    /// The symmetric definition used for parameter encryption.
    pub symmetric: SymDef,
    /// Policy state, unused by an HMAC session.
    pub policy: PolicyState,
    /// Audit state.
    pub audit: AuditState,
    /// The attributes the caller sent with the most recent use.
    pub attributes: SessionAttributes,
}

impl Session {
    /// A new session with a fresh TPM nonce.
    pub fn new(
        handle: u32,
        session_type: u8,
        auth_hash: u16,
        nonce_tpm: Vec<u8>,
        nonce_caller: Vec<u8>,
        session_key: Vec<u8>,
        bind: u32,
        bind_name: Vec<u8>,
        symmetric: SymDef,
    ) -> TpmResult<Session> {
        let digest_len = hash::digest_size(auth_hash)?;
        Ok(Session {
            handle,
            session_type,
            auth_hash,
            nonce_tpm,
            nonce_caller,
            session_key,
            bind,
            bind_name,
            bind_uses_lockout: false,
            symmetric,
            policy: PolicyState {
                digest: vec![0u8; digest_len],
                ..PolicyState::default()
            },
            audit: AuditState::default(),
            attributes: SessionAttributes::default(),
        })
    }

    /// True for a policy or trial session.
    pub fn is_policy(&self) -> bool {
        self.session_type == se::POLICY || self.session_type == se::TRIAL
    }

    /// True for a trial session, which never authorizes anything.
    pub fn is_trial(&self) -> bool {
        self.session_type == se::TRIAL
    }

    /// True for an HMAC session.
    pub fn is_hmac(&self) -> bool {
        self.session_type == se::HMAC
    }

    /// The value that identifies the entity a session is bound to.
    ///
    /// Part 1 clause 19.6.10 identifies the bound entity by its Name followed
    /// by its authorization value, not by the Name alone. An NV Index or a
    /// persistent object can be removed and recreated with the same Name but a
    /// different authorization value, and without the value in the identifier a
    /// session bound to the old entity would still count as bound to the new
    /// one and would leave the new value out of the HMAC key.
    pub fn bind_id(name: &[u8], auth_value: &[u8]) -> Vec<u8> {
        let mut id = name.to_vec();
        id.extend_from_slice(trim_auth(auth_value));
        id
    }

    /// True when the session is bound to the entity with this Name and value.
    ///
    /// Part 1 clause 19.6.4 leaves the authorization value out of the HMAC key
    /// when the session is bound to the entity being authorized, because the
    /// session key already covers it.
    pub fn is_bound_to(&self, name: &[u8], auth_value: &[u8]) -> bool {
        self.bind != crate::tpm::constants::rh::NULL
            && !self.bind_name.is_empty()
            && self.bind_name == Session::bind_id(name, auth_value)
    }

    /// The HMAC key for authorizing an entity with this Name and authValue.
    pub fn hmac_key(&self, entity_name: &[u8], auth_value: &[u8]) -> Vec<u8> {
        let mut key = self.session_key.clone();
        if !self.is_bound_to(entity_name, auth_value) {
            // Trailing zero octets of an authValue are removed before use, as
            // Part 1 clause 19.6.4.3 requires, so that an authValue padded to
            // the digest size gives the same HMAC as the unpadded value.
            key.extend_from_slice(trim_auth(auth_value));
        }
        key
    }

    /// The value parameter encryption folds in, Part 1 clause 18.1.
    ///
    /// `sessionValue = sessionKey || authValue` when the session also
    /// authorizes a handle. Binding does not change this, unlike the
    /// authorization HMAC key.
    pub fn session_value(&self, auth_value: &[u8]) -> Vec<u8> {
        let mut value = self.session_key.clone();
        value.extend_from_slice(trim_auth(auth_value));
        value
    }

    /// Reset the policy digest to zeros, which TPM2_PolicyRestart does.
    pub fn restart_policy(&mut self) -> TpmResult<()> {
        let digest_len = hash::digest_size(self.auth_hash)?;
        self.policy = PolicyState {
            digest: vec![0u8; digest_len],
            ..PolicyState::default()
        };
        Ok(())
    }

    /// Extend the policy digest with `command_code` and `data`.
    ///
    /// Part 2 clause 12 defines every policy update as
    /// `policyDigest = H(policyDigest || commandCode || data)`.
    pub fn extend_policy(&mut self, command_code: u32, data: &[u8]) -> TpmResult<()> {
        self.policy.digest = hash::digest_parts(
            self.auth_hash,
            &[&self.policy.digest, &command_code.to_be_bytes(), data],
        )?;
        Ok(())
    }

    /// Replace the policy digest outright, which TPM2_PolicyAuthorize does.
    pub fn set_policy_digest(&mut self, digest: Vec<u8>) {
        self.policy.digest = digest;
    }
}

/// Remove trailing zero octets from an authorization value.
pub fn trim_auth(auth: &[u8]) -> &[u8] {
    let mut end = auth.len();
    while end > 0 && auth[end - 1] == 0 {
        end -= 1;
    }
    &auth[..end]
}

/// Derive the session key at TPM2_StartAuthSession.
///
/// `bind_auth` is the authorization value of the bound entity, empty when the
/// session is unbound, and `salt` is the decrypted salt, empty when the session
/// is unsalted. Part 1 clause 19.6.8 concatenates the two to key the KDF.
pub fn derive_session_key(
    auth_hash: u16,
    bind_auth: &[u8],
    salt: &[u8],
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
) -> TpmResult<Vec<u8>> {
    if bind_auth.is_empty() && salt.is_empty() {
        return Ok(Vec::new());
    }
    let mut key_material = Vec::with_capacity(bind_auth.len() + salt.len());
    key_material.extend_from_slice(trim_auth(bind_auth));
    key_material.extend_from_slice(salt);
    let bits = (hash::digest_size(auth_hash)? * 8) as u32;
    kdfa(
        auth_hash,
        &key_material,
        LABEL_SESSION_KEY,
        nonce_tpm,
        nonce_caller,
        bits,
    )
}

/// The command parameter digest, Part 1 clause 18.4.
///
/// `cpHash = H(commandCode || name1 || name2 || ... || parameters)`.
pub fn cp_hash(hash_alg: u16, command_code: u32, names: &[&[u8]], parameters: &[u8]) -> TpmResult<Vec<u8>> {
    let mut h = hash::Hasher::new(hash_alg)?;
    h.update(&command_code.to_be_bytes());
    for n in names {
        h.update(n);
    }
    h.update(parameters);
    Ok(h.finish())
}

/// The response parameter digest, Part 1 clause 18.5.
///
/// `rpHash = H(responseCode || commandCode || parameters)`.
pub fn rp_hash(
    hash_alg: u16,
    response_code: u32,
    command_code: u32,
    parameters: &[u8],
) -> TpmResult<Vec<u8>> {
    hash::digest_parts(
        hash_alg,
        &[
            &response_code.to_be_bytes(),
            &command_code.to_be_bytes(),
            parameters,
        ],
    )
}

/// The authorization HMAC, Part 1 clause 19.6.5.
///
/// `HMAC(hmacKey, pHash || nonceNewer || nonceOlder || sessionAttributes)`.
pub fn auth_hmac(
    auth_hash: u16,
    hmac_key: &[u8],
    p_hash: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    attributes: SessionAttributes,
) -> TpmResult<Vec<u8>> {
    auth_hmac_with_nonces(
        auth_hash,
        hmac_key,
        p_hash,
        nonce_newer,
        nonce_older,
        &[],
        &[],
        attributes,
    )
}

/// The authorization HMAC including the auxiliary session nonces.
///
/// Part 1 clause 19.6.3.4 puts the nonceTPM of the decrypt and encrypt
/// sessions into the HMAC of the first authorization, so those sessions cannot
/// be stripped from the command without invalidating it:
///
/// `HMAC(key, pHash || nonceNewer || nonceOlder || nonceTPMdecrypt ||
///  nonceTPMencrypt || sessionAttributes)`
#[allow(clippy::too_many_arguments)]
pub fn auth_hmac_with_nonces(
    auth_hash: u16,
    hmac_key: &[u8],
    p_hash: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    nonce_decrypt: &[u8],
    nonce_encrypt: &[u8],
    attributes: SessionAttributes,
) -> TpmResult<Vec<u8>> {
    hmac_parts(
        auth_hash,
        hmac_key,
        &[
            p_hash,
            nonce_newer,
            nonce_older,
            nonce_decrypt,
            nonce_encrypt,
            &[attributes.0],
        ],
    )
}

/// The key and IV used for parameter encryption, Part 1 clause 21.3.
///
/// The key material is the session key followed by the authorization value of
/// the first handle, and the derivation label is "CFB".
pub fn parameter_encryption_key(
    auth_hash: u16,
    session_key: &[u8],
    extra_key: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    key_bits: u16,
    iv_bytes: usize,
) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let mut material = session_key.to_vec();
    material.extend_from_slice(trim_auth(extra_key));
    let bits = key_bits as u32 + (iv_bytes * 8) as u32;
    let out = kdfa(
        auth_hash,
        &material,
        LABEL_CFB,
        nonce_newer,
        nonce_older,
        bits,
    )?;
    let key_bytes = key_bits as usize / 8;
    Ok((out[..key_bytes].to_vec(), out[key_bytes..].to_vec()))
}

/// The loaded sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSlots {
    sessions: BTreeMap<u32, Session>,
    /// Handles that have been assigned but whose context is not loaded.
    saved: BTreeMap<u32, u64>,
    /// The next context identifier, which orders saved sessions.
    context_counter: u64,
}

impl SessionSlots {
    pub fn new() -> SessionSlots {
        SessionSlots {
            context_counter: 1,
            ..SessionSlots::default()
        }
    }

    /// Number of loaded sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Number of sessions the TPM is tracking, loaded or saved.
    pub fn active(&self) -> usize {
        self.sessions.len() + self.saved.len()
    }

    /// The current context counter.
    pub fn context_counter(&self) -> u64 {
        self.context_counter
    }

    /// Take the next context identifier.
    pub fn next_context_id(&mut self) -> u64 {
        let id = self.context_counter;
        self.context_counter = self.context_counter.wrapping_add(1);
        id
    }

    /// Allocate a handle in the range that matches the session type.
    ///
    /// Part 2 Table 33 gives HMAC sessions the 0x02 range and policy sessions
    /// the 0x03 range.
    pub fn allocate_handle(&self, session_type: u8) -> TpmResult<u32> {
        let base = if session_type == se::HMAC {
            hc::HMAC_SESSION_FIRST
        } else {
            hc::POLICY_SESSION_FIRST
        };
        for i in 0..config::MAX_ACTIVE_SESSIONS as u32 {
            let handle = base + i;
            if !self.sessions.contains_key(&handle) && !self.saved.contains_key(&handle) {
                return Ok(handle);
            }
        }
        Err(TpmRc(rc::SESSION_HANDLES))
    }

    /// Load a new session.
    pub fn insert(&mut self, session: Session) -> TpmResult<u32> {
        if self.sessions.len() >= config::MAX_LOADED_SESSIONS as usize {
            return Err(TpmRc(rc::SESSION_MEMORY));
        }
        if self.active() >= config::MAX_ACTIVE_SESSIONS as usize {
            return Err(TpmRc(rc::SESSION_HANDLES));
        }
        let handle = session.handle;
        self.sessions.insert(handle, session);
        Ok(handle)
    }

    pub fn get(&self, handle: u32) -> TpmResult<&Session> {
        self.sessions.get(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    pub fn get_mut(&mut self, handle: u32) -> TpmResult<&mut Session> {
        self.sessions.get_mut(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    pub fn remove(&mut self, handle: u32) -> TpmResult<Session> {
        self.saved.remove(&handle);
        self.sessions.remove(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    /// Move a session out of memory, keeping its handle reserved.
    pub fn save(&mut self, handle: u32) -> TpmResult<(Session, u64)> {
        let session = self.sessions.remove(&handle).ok_or(TpmRc(rc::HANDLE))?;
        let id = self.next_context_id();
        self.saved.insert(handle, id);
        Ok((session, id))
    }

    /// Bring a saved session back into memory.
    pub fn restore(&mut self, session: Session) -> TpmResult<()> {
        let handle = session.handle;
        if !self.saved.contains_key(&handle) {
            return Err(TpmRc(rc::HANDLE));
        }
        if self.sessions.len() >= config::MAX_LOADED_SESSIONS as usize {
            return Err(TpmRc(rc::SESSION_MEMORY));
        }
        self.saved.remove(&handle);
        self.sessions.insert(handle, session);
        Ok(())
    }

    /// True when `handle` names a session, loaded or saved.
    pub fn contains(&self, handle: u32) -> bool {
        self.sessions.contains_key(&handle) || self.saved.contains_key(&handle)
    }

    /// Every loaded session handle.
    pub fn loaded_handles(&self) -> Vec<u32> {
        self.sessions.keys().copied().collect()
    }

    /// Every handle the TPM is tracking, loaded or saved.
    pub fn active_handles(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.sessions.keys().copied().collect();
        out.extend(self.saved.keys().copied());
        out.sort_unstable();
        out
    }

    /// Drop every session, which a TPM Reset does.
    pub fn clear(&mut self) {
        self.sessions.clear();
        self.saved.clear();
        self.context_counter = 1;
    }

    /// Drop every session bound to `handle`, which happens when the entity the
    /// session is bound to goes away.
    pub fn flush_bound_to(&mut self, handle: u32) {
        self.sessions.retain(|_, s| s.bind != handle);
    }
}

/// True when `handle` is in one of the session ranges.
pub fn is_session_handle(handle: u32) -> bool {
    (hc::HMAC_SESSION_FIRST..=hc::HMAC_SESSION_LAST).contains(&handle)
        || (hc::POLICY_SESSION_FIRST..=hc::POLICY_SESSION_LAST).contains(&handle)
}

/// True when `session_type` is one of the three defined values.
pub fn is_session_type(session_type: u8) -> bool {
    matches!(session_type, se::HMAC | se::POLICY | se::TRIAL)
}

/// The empty policy digest for `auth_hash`.
pub fn empty_policy(auth_hash: u16) -> TpmResult<Vec<u8>> {
    Ok(vec![0u8; hash::digest_size(auth_hash)?])
}

/// True when `alg_id` may be a session hash.
pub fn is_valid_auth_hash(alg_id: u16) -> bool {
    alg_id != alg::NULL && hash::is_supported(alg_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::rh;

    fn session(session_type: u8) -> Session {
        Session::new(
            hc::HMAC_SESSION_FIRST,
            session_type,
            alg::SHA256,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap()
    }

    #[test]
    fn a_new_session_starts_with_an_empty_policy() {
        let s = session(se::POLICY);
        assert_eq!(s.policy.digest, vec![0u8; 32]);
        assert!(s.is_policy());
        assert!(!s.is_trial());
        assert!(!s.is_hmac());
        assert!(session(se::HMAC).is_hmac());
        assert!(session(se::TRIAL).is_trial());
        assert!(session(se::TRIAL).is_policy());
    }

    #[test]
    fn trailing_zeros_are_trimmed_from_an_authorization_value() {
        assert_eq!(trim_auth(b"abc\0\0"), b"abc");
        assert_eq!(trim_auth(b"abc"), b"abc");
        assert_eq!(trim_auth(b"\0\0"), b"");
        assert_eq!(trim_auth(b""), b"");
        // Interior zeros are kept.
        assert_eq!(trim_auth(b"a\0b"), b"a\0b");
    }

    #[test]
    fn an_unsalted_unbound_session_has_no_key() {
        assert!(derive_session_key(alg::SHA256, b"", b"", b"n1", b"n2")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn the_session_key_is_kdfa_over_the_bind_value_and_salt() {
        let key = derive_session_key(alg::SHA256, b"auth", b"salt", b"tpm", b"caller").unwrap();
        let expected = kdfa(
            alg::SHA256,
            b"authsalt",
            "ATH",
            b"tpm",
            b"caller",
            256,
        )
        .unwrap();
        assert_eq!(key, expected);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn the_session_key_changes_with_every_input() {
        let base = derive_session_key(alg::SHA256, b"a", b"s", b"t", b"c").unwrap();
        assert_ne!(base, derive_session_key(alg::SHA256, b"b", b"s", b"t", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, b"a", b"x", b"t", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, b"a", b"s", b"u", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, b"a", b"s", b"t", b"d").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA384, b"a", b"s", b"t", b"c").unwrap());
    }

    #[test]
    fn the_hmac_key_includes_the_authorization_unless_bound() {
        let mut s = session(se::HMAC);
        let name = vec![9u8; 34];
        // Unbound: the authValue is appended.
        let mut expected = s.session_key.clone();
        expected.extend_from_slice(b"pw");
        assert_eq!(s.hmac_key(&name, b"pw"), expected);

        // Bound to this entity: the authValue is left out.
        s.bind = hc::TRANSIENT_FIRST;
        s.bind_name = Session::bind_id(&name, b"pw");
        assert_eq!(s.hmac_key(&name, b"pw"), s.session_key);
        // Bound to a different entity: the authValue is appended again.
        assert_eq!(s.hmac_key(&[8u8; 34], b"pw"), expected);
    }

    #[test]
    fn binding_covers_the_authorization_value_as_well_as_the_name() {
        // An entity that is removed and recreated with the same Name but a
        // different authorization value must not count as the bound entity.
        let mut s = session(se::HMAC);
        let name = vec![9u8; 34];
        s.bind = hc::TRANSIENT_FIRST;
        s.bind_name = Session::bind_id(&name, b"old");

        assert!(s.is_bound_to(&name, b"old"));
        assert!(!s.is_bound_to(&name, b"new"));
        // The replacement's value therefore goes into the HMAC key.
        let mut expected = s.session_key.clone();
        expected.extend_from_slice(b"new");
        assert_eq!(s.hmac_key(&name, b"new"), expected);
    }

    #[test]
    fn the_hmac_key_trims_a_padded_authorization_value() {
        let s = session(se::HMAC);
        assert_eq!(s.hmac_key(&[1u8; 34], b"pw\0\0"), s.hmac_key(&[1u8; 34], b"pw"));
    }

    #[test]
    fn the_session_value_always_includes_the_authorization_value() {
        // Part 1 clause 18.1 keeps the authValue in the parameter encryption
        // key even when the session is bound to the entity.
        let mut s = session(se::HMAC);
        let name = vec![9u8; 34];
        s.bind = hc::TRANSIENT_FIRST;
        s.bind_name = Session::bind_id(&name, b"pw");
        assert_eq!(s.hmac_key(&name, b"pw"), s.session_key);
        let mut expected = s.session_key.clone();
        expected.extend_from_slice(b"pw");
        assert_eq!(s.session_value(b"pw"), expected);
    }

    #[test]
    fn cp_hash_covers_the_command_code_names_and_parameters() {
        let names: Vec<&[u8]> = vec![b"name1", b"name2"];
        let got = cp_hash(alg::SHA256, 0x0000_0153, &names, b"params").unwrap();
        let expected = hash::digest_parts(
            alg::SHA256,
            &[&0x0000_0153u32.to_be_bytes(), b"name1", b"name2", b"params"],
        )
        .unwrap();
        assert_eq!(got, expected);
        // Changing any part changes the digest.
        assert_ne!(got, cp_hash(alg::SHA256, 0x0000_0154, &names, b"params").unwrap());
        assert_ne!(got, cp_hash(alg::SHA256, 0x0000_0153, &names, b"other").unwrap());
        assert_ne!(
            got,
            cp_hash(alg::SHA256, 0x0000_0153, &[b"name1".as_slice()], b"params").unwrap()
        );
    }

    #[test]
    fn rp_hash_covers_the_response_code_command_code_and_parameters() {
        let got = rp_hash(alg::SHA256, 0, 0x0000_017b, b"random").unwrap();
        let expected = hash::digest_parts(
            alg::SHA256,
            &[&0u32.to_be_bytes(), &0x0000_017bu32.to_be_bytes(), b"random"],
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn the_authorization_hmac_matches_the_definition() {
        let key = b"hmac key";
        let p = vec![1u8; 32];
        let attrs = SessionAttributes(SessionAttributes::CONTINUE_SESSION);
        let got = auth_hmac(alg::SHA256, key, &p, b"newer", b"older", attrs).unwrap();
        let expected = hmac_parts(alg::SHA256, key, &[&p, b"newer", b"older", &[0x01]]).unwrap();
        assert_eq!(got, expected);
        // The attribute octet is part of the input.
        let other = auth_hmac(alg::SHA256, key, &p, b"newer", b"older", SessionAttributes(0))
            .unwrap();
        assert_ne!(got, other);
    }

    #[test]
    fn parameter_encryption_derives_a_key_and_iv() {
        let (key, iv) = parameter_encryption_key(
            alg::SHA256,
            &[1u8; 32],
            b"auth",
            b"newer",
            b"older",
            128,
            16,
        )
        .unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 16);
        let mut material = vec![1u8; 32];
        material.extend_from_slice(b"auth");
        let expected = kdfa(alg::SHA256, &material, "CFB", b"newer", b"older", 256).unwrap();
        assert_eq!(key, expected[..16]);
        assert_eq!(iv, expected[16..]);
    }

    #[test]
    fn policy_extension_matches_the_definition() {
        let mut s = session(se::POLICY);
        let before = s.policy.digest.clone();
        s.extend_policy(0x0000_016c, b"data").unwrap();
        let expected = hash::digest_parts(
            alg::SHA256,
            &[&before, &0x0000_016cu32.to_be_bytes(), b"data"],
        )
        .unwrap();
        assert_eq!(s.policy.digest, expected);
    }

    #[test]
    fn restarting_a_policy_clears_every_assertion() {
        let mut s = session(se::POLICY);
        s.extend_policy(1, b"x").unwrap();
        s.policy.command_code = Some(5);
        s.policy.auth_value_needed = true;
        s.policy.locality = Some(1);
        s.restart_policy().unwrap();
        assert_eq!(s.policy.digest, vec![0u8; 32]);
        assert_eq!(s.policy.command_code, None);
        assert!(!s.policy.auth_value_needed);
        assert_eq!(s.policy.locality, None);
    }

    #[test]
    fn handles_come_from_the_range_that_matches_the_type() {
        let slots = SessionSlots::new();
        assert_eq!(slots.allocate_handle(se::HMAC).unwrap(), hc::HMAC_SESSION_FIRST);
        assert_eq!(
            slots.allocate_handle(se::POLICY).unwrap(),
            hc::POLICY_SESSION_FIRST
        );
        assert_eq!(
            slots.allocate_handle(se::TRIAL).unwrap(),
            hc::POLICY_SESSION_FIRST
        );
        assert!(is_session_handle(hc::HMAC_SESSION_FIRST));
        assert!(is_session_handle(hc::POLICY_SESSION_FIRST));
        assert!(!is_session_handle(hc::TRANSIENT_FIRST));
    }

    #[test]
    fn sessions_are_stored_and_removed_by_handle() {
        let mut slots = SessionSlots::new();
        let h = slots.insert(session(se::HMAC)).unwrap();
        assert_eq!(h, hc::HMAC_SESSION_FIRST);
        assert!(slots.contains(h));
        assert_eq!(slots.len(), 1);
        assert_eq!(slots.loaded_handles(), vec![h]);
        slots.remove(h).unwrap();
        assert!(!slots.contains(h));
        assert_eq!(slots.remove(h).unwrap_err(), TpmRc(rc::HANDLE));
    }

    #[test]
    fn saving_keeps_the_handle_reserved() {
        let mut slots = SessionSlots::new();
        let h = slots.insert(session(se::HMAC)).unwrap();
        let (saved, id) = slots.save(h).unwrap();
        assert_eq!(id, 1);
        assert_eq!(slots.len(), 0);
        assert_eq!(slots.active(), 1);
        assert!(slots.contains(h));
        // The handle is not handed out again while the context is outstanding.
        assert_ne!(slots.allocate_handle(se::HMAC).unwrap(), h);
        slots.restore(saved).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots.active(), 1);
    }

    #[test]
    fn restoring_an_unknown_handle_is_refused() {
        let mut slots = SessionSlots::new();
        assert_eq!(
            slots.restore(session(se::HMAC)).unwrap_err(),
            TpmRc(rc::HANDLE)
        );
    }

    #[test]
    fn the_loaded_session_count_is_bounded() {
        let mut slots = SessionSlots::new();
        for _ in 0..config::MAX_LOADED_SESSIONS {
            let handle = slots.allocate_handle(se::HMAC).unwrap();
            let mut s = session(se::HMAC);
            s.handle = handle;
            slots.insert(s).unwrap();
        }
        let handle = slots.allocate_handle(se::HMAC).unwrap();
        let mut s = session(se::HMAC);
        s.handle = handle;
        assert_eq!(slots.insert(s).unwrap_err(), TpmRc(rc::SESSION_MEMORY));
    }

    #[test]
    fn flushing_by_bind_handle_drops_only_matching_sessions() {
        let mut slots = SessionSlots::new();
        let mut bound = session(se::HMAC);
        bound.handle = hc::HMAC_SESSION_FIRST;
        bound.bind = hc::TRANSIENT_FIRST;
        slots.insert(bound).unwrap();
        let mut other = session(se::HMAC);
        other.handle = hc::HMAC_SESSION_FIRST + 1;
        slots.insert(other).unwrap();

        slots.flush_bound_to(hc::TRANSIENT_FIRST);
        assert!(!slots.contains(hc::HMAC_SESSION_FIRST));
        assert!(slots.contains(hc::HMAC_SESSION_FIRST + 1));
    }

    #[test]
    fn context_identifiers_increase() {
        let mut slots = SessionSlots::new();
        assert_eq!(slots.next_context_id(), 1);
        assert_eq!(slots.next_context_id(), 2);
        assert_eq!(slots.context_counter(), 3);
    }

    #[test]
    fn session_types_and_hashes_are_checked() {
        assert!(is_session_type(se::HMAC));
        assert!(is_session_type(se::POLICY));
        assert!(is_session_type(se::TRIAL));
        assert!(!is_session_type(2));
        assert!(is_valid_auth_hash(alg::SHA256));
        assert!(!is_valid_auth_hash(alg::NULL));
        assert!(!is_valid_auth_hash(alg::RSA));
        assert_eq!(empty_policy(alg::SHA384).unwrap(), vec![0u8; 48]);
    }
}
