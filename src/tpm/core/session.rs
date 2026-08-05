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
    /// Set by TPM2_PolicyTransportSPDM, meaning a secure channel is required.
    pub secure_channel_required: bool,
    /// The digest of the secure channel key Names the policy is tied to, when
    /// TPM2_PolicyTransportSPDM named either of them.
    pub secure_channel_key_hash: Option<Vec<u8>>,
    /// When the authorization expires, in the TPM's time base.
    pub expiration: Option<u64>,
    /// The nonce that a ticket for this policy is bound to.
    pub timeout_nonce: Vec<u8>,
}

impl PolicyState {
    /// Marshal everything a saved context has to carry.
    ///
    /// Part 1 clause 27.2.1 requires the context blob to hold what is needed
    /// to rebuild the whole session, so every assertion the policy has made so
    /// far travels with it. Without them a saved session could reload with the
    /// same policy digest but none of the restrictions it recorded.
    pub fn marshal(&self, w: &mut crate::tpm::marshal::Writer) {
        let optional_bytes = |w: &mut crate::tpm::marshal::Writer, v: &Option<Vec<u8>>| {
            match v {
                Some(b) => {
                    w.u8(1);
                    w.sized16(b);
                }
                None => w.u8(0),
            }
        };
        w.sized16(&self.digest);
        match self.command_code {
            Some(c) => {
                w.u8(1);
                w.u32(c);
            }
            None => w.u8(0),
        }
        optional_bytes(w, &self.cp_hash);
        optional_bytes(w, &self.name_hash);
        match self.locality {
            Some(m) => {
                w.u8(1);
                w.u8(m);
            }
            None => w.u8(0),
        }
        match self.pcr_update_counter {
            Some(c) => {
                w.u8(1);
                w.u32(c);
            }
            None => w.u8(0),
        }
        w.u8(u8::from(self.auth_value_needed));
        w.u8(u8::from(self.password_needed));
        match self.nv_written {
            Some(v) => {
                w.u8(1);
                w.u8(u8::from(v));
            }
            None => w.u8(0),
        }
        optional_bytes(w, &self.template_hash);
        optional_bytes(w, &self.parameters_hash);
        w.u8(u8::from(self.physical_presence_required));
        w.u8(u8::from(self.secure_channel_required));
        optional_bytes(w, &self.secure_channel_key_hash);
        match self.expiration {
            Some(t) => {
                w.u8(1);
                w.u64(t);
            }
            None => w.u8(0),
        }
        w.sized16(&self.timeout_nonce);
    }

    /// Rebuild the state [`PolicyState::marshal`] wrote.
    pub fn unmarshal(r: &mut crate::tpm::marshal::Reader<'_>) -> TpmResult<PolicyState> {
        fn bytes(r: &mut crate::tpm::marshal::Reader<'_>) -> TpmResult<Vec<u8>> {
            let n = r.u16()? as usize;
            Ok(r.take(n)?.to_vec())
        }
        fn optional_bytes(
            r: &mut crate::tpm::marshal::Reader<'_>,
        ) -> TpmResult<Option<Vec<u8>>> {
            if r.u8()? == 0 {
                Ok(None)
            } else {
                Ok(Some(bytes(r)?))
            }
        }
        let digest = bytes(r)?;
        let command_code = if r.u8()? == 0 { None } else { Some(r.u32()?) };
        let cp_hash = optional_bytes(r)?;
        let name_hash = optional_bytes(r)?;
        let locality = if r.u8()? == 0 { None } else { Some(r.u8()?) };
        let pcr_update_counter = if r.u8()? == 0 { None } else { Some(r.u32()?) };
        let auth_value_needed = r.u8()? != 0;
        let password_needed = r.u8()? != 0;
        let nv_written = if r.u8()? == 0 {
            None
        } else {
            Some(r.u8()? != 0)
        };
        let template_hash = optional_bytes(r)?;
        let parameters_hash = optional_bytes(r)?;
        let physical_presence_required = r.u8()? != 0;
        let secure_channel_required = r.u8()? != 0;
        let secure_channel_key_hash = optional_bytes(r)?;
        let expiration = if r.u8()? == 0 { None } else { Some(r.u64()?) };
        let timeout_nonce = bytes(r)?;
        Ok(PolicyState {
            digest,
            command_code,
            cp_hash,
            name_hash,
            locality,
            pcr_update_counter,
            auth_value_needed,
            password_needed,
            nv_written,
            template_hash,
            parameters_hash,
            physical_presence_required,
            secure_channel_required,
            secure_channel_key_hash,
            expiration,
            timeout_nonce,
        })
    }
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
    /// The value of Time when the session was created.
    ///
    /// Part 3 clause 23.2.2 measures a bound authorization from here rather
    /// than from when the authorization arrives, so a caller cannot extend the
    /// limit the signer set by delaying the command.
    pub start_time: u64,
    /// The run of Time the session belongs to, so a timeout recorded against
    /// an earlier one is seen as expired.
    pub time_epoch: u64,
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
            start_time: 0,
            time_epoch: 0,
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
    ///
    /// Part 1 clause 16.6.9 gives two different rules and which applies turns
    /// on the session type. For an HMAC session the authValue is left out when
    /// "the authorization is for the entity to which the session is bound". For
    /// a policy session binding does not come into it: the value is included
    /// when "the session has isAuthValueNeeded SET (by TPM_PolicyAuthValue())"
    /// and left out otherwise. Using the binding rule on a policy session gives
    /// a bound session that called TPM2_PolicyAuthValue the wrong key.
    pub fn hmac_key(&self, entity_name: &[u8], auth_value: &[u8]) -> Vec<u8> {
        let mut key = self.session_key.clone();
        let wants_auth = if self.is_policy() {
            self.policy.auth_value_needed
        } else {
            !self.is_bound_to(entity_name, auth_value)
        };
        if wants_auth {
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

/// Does a supplied authorization HMAC prove the caller knew the key?
///
/// Part 1 clause 16.6.16 lets the caller leave the HMAC out when the key would
/// be an Empty Buffer: "the caller has the option of either providing the
/// results of the authHMAC computation, or not. If authHMAC is provided, it
/// will be computed as shown in Equation 17 with an Empty Buffer as the HMAC
/// key and the TPM will validate that the value in hmac matches the internally
/// calculated value. If authHMAC is not provided, the size of hmac will be zero
/// and the TPM will accept this value of hmac as providing valid authorization
/// for the object."
///
/// So an empty HMAC is only ever accepted when the key is empty too, and a
/// value that was supplied is always checked. A caller that sends the wrong
/// HMAC is refused whether or not it could have sent none.
pub fn auth_hmac_accepted(key: &[u8], expected: &[u8], supplied: &[u8]) -> bool {
    if key.is_empty() && supplied.is_empty() {
        return true;
    }
    crate::tpm::core::protect::constant_time_eq(expected, supplied)
}

/// Derive the session key at TPM2_StartAuthSession.
///
/// `bind_auth` is the authorization value of the bound entity, empty when the
/// session is unbound, and `salt` is the decrypted salt, empty when the session
/// is unsalted. Part 1 clause 16.6.8 concatenates the two to key the KDF.
///
/// `plain` says that both tpmKey and bind were TPM_RH_NULL, which is the only
/// case the clause exempts: "If both tpmKey and bind are TPM_RH_NULL, then
/// sessionKey is set to an Empty Buffer. Otherwise, the sessionKey is created
/// as follows". The test is on the two handles and not on what they yield, so a
/// session bound to an entity whose authorization value happens to be empty
/// still gets a key, and it is not the Empty Buffer.
pub fn derive_session_key(
    auth_hash: u16,
    plain: bool,
    bind_auth: &[u8],
    salt: &[u8],
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
) -> TpmResult<Vec<u8>> {
    if plain {
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
    /// Handles that have been assigned but whose context is not loaded, with
    /// the identifier each was carrying when it was put away.
    saved: BTreeMap<u32, u64>,
    /// The identifier a loaded session is carrying.
    version: BTreeMap<u32, u64>,
    /// The contextCounter of Part 1 clause 27.2.2, which "is used to provide
    /// sequence numbers for sessions and increments when a session context is
    /// created or loaded". An object context does not take its number here.
    context_counter: u64,
    /// The objectContextID of the same clause, which "provides sequence
    /// numbers for Transient Objects" and "is incremented each time an object
    /// context is saved".
    object_counter: u64,
}

impl SessionSlots {
    pub fn new() -> SessionSlots {
        SessionSlots {
            context_counter: 1,
            object_counter: 1,
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

    /// Sessions in TPM memory, which TPM_PT_HR_LOADED counts.
    pub fn loaded(&self) -> usize {
        self.sessions.len()
    }

    /// The current context counter.
    pub fn context_counter(&self) -> u64 {
        self.context_counter
    }

    /// The counter an object or sequence context is stamped with.
    pub fn object_counter(&self) -> u64 {
        self.object_counter
    }

    /// The next object context identifier, without taking it.
    pub fn peek_object_id(&self) -> u64 {
        self.object_counter
    }

    /// Take the next object context identifier, clause 27.2.2.
    ///
    /// Both counters saturate rather than wrap. Clause 27.5 describes a
    /// rollover scheme for a counter "only be large enough for the majority of
    /// applications"; these are 64 bits wide, so a TPM cannot reach the end of
    /// one, and stopping there is safer than handing out a number twice.
    pub fn next_object_id(&mut self) -> u64 {
        let id = self.object_counter;
        self.object_counter = self.object_counter.saturating_add(1);
        id
    }

    /// The lowest identifier any active session holds, saved or loaded.
    ///
    /// Part 3 Table 17 describes TPM_RC_CONTEXT_GAP as "the gap between the
    /// lowest numbered active session and the highest numbered session is at
    /// the limits of the session tracking logic", so a session that is loaded
    /// counts as much as one that is put away.
    pub fn oldest_active(&self) -> Option<u64> {
        self.saved
            .values()
            .chain(self.version.values())
            .copied()
            .min()
    }

    /// The identifier a session is carrying, loaded or saved.
    pub fn saved_version(&self, handle: u32) -> Option<u64> {
        self.version
            .get(&handle)
            .or_else(|| self.saved.get(&handle))
            .copied()
    }

    /// The lowest identifier a saved session holds, which is the one the
    /// remedy for a gap says to load.
    pub fn oldest_saved(&self) -> Option<u64> {
        self.saved.values().copied().min()
    }

    /// True when the tracking window is full.
    pub fn at_context_gap(&self) -> bool {
        match self.oldest_active() {
            // Part 2 Table 30 makes TPM_PT_CONTEXT_GAP_MAX "the maximum
            // allowed difference (unsigned) between the contextID values of
            // two saved session contexts", and a difference equal to it is
            // allowed. A session taken now carries the counter as it stands,
            // so the window is full only once that number would sit further
            // from the oldest than the maximum.
            Some(oldest) => {
                self.context_counter.saturating_sub(oldest) > config::CONTEXT_GAP_MAX as u64
            }
            None => false,
        }
    }

    /// Refuse a new identifier when an old saved context could no longer be
    /// told from a new one.
    ///
    /// Part 3 clause 11.1.1: "if the TPM implements a gap scheme for assigning
    /// contextID values, then the TPM shall return TPM_RC_CONTEXT_GAP if
    /// creating the session would prevent recycling of old saved contexts."
    /// This TPM reports a gap in TPM_PT_CONTEXT_GAP_MAX, so it answers for one.
    fn check_gap(&self) -> TpmResult<()> {
        if self.at_context_gap() {
            return Err(TpmRc(rc::CONTEXT_GAP));
        }
        Ok(())
    }

    /// True when a counter has reached the end and cannot hand out a number
    /// that has not been handed out before.
    ///
    /// Clause 27.5 says the TPM has to be able "to ensure that the restored
    /// context is the correct context regardless of the number of contexts
    /// created". A counter that has stopped would give every later context the
    /// same number, so the TPM says it can take no more instead.
    pub fn counters_exhausted(&self) -> bool {
        self.context_counter == u64::MAX || self.object_counter == u64::MAX
    }

    /// Take the next session identifier, which clause 27.2.2 does when a
    /// session context is created or loaded.
    pub fn next_context_id(&mut self) -> u64 {
        let id = self.context_counter;
        self.context_counter = self.context_counter.saturating_add(1);
        id
    }

    /// True when a session of either type already holds this context
    /// identifier, which is the low order three octets of its handle.
    fn context_id_taken(&self, index: u32) -> bool {
        self.sessions
            .keys()
            .chain(self.saved.keys())
            .any(|h| h & 0x00FF_FFFF == index)
    }

    /// Allocate a handle in the range that matches the session type.
    ///
    /// Part 2 Table 33 gives HMAC sessions the 0x02 range and policy sessions
    /// the 0x03 range. Part 1 clause 12.4 makes the low order three octets of
    /// a session handle unique, so the identifier is taken from one pool
    /// shared by both ranges. Two sessions that differed only in the upper
    /// octet could not be told apart by the clause 28.4.1 flush, which names a
    /// session by those three octets alone.
    pub fn allocate_handle(&self, session_type: u8) -> TpmResult<u32> {
        let base = if session_type == se::HMAC {
            hc::HMAC_SESSION_FIRST
        } else {
            hc::POLICY_SESSION_FIRST
        };
        for i in 0..config::MAX_ACTIVE_SESSIONS as u32 {
            if !self.context_id_taken(i) {
                return Ok(base + i);
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
        self.check_gap()?;
        if self.counters_exhausted() {
            return Err(TpmRc(rc::CONTEXT_GAP));
        }
        let handle = session.handle;
        let id = self.next_context_id();
        self.version.insert(handle, id);
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
        self.version.remove(&handle);
        self.sessions.remove(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    /// Drop a session for TPM2_FlushContext.
    ///
    /// Part 3 clause 28.4.1 flushes a session whether it is loaded or only
    /// saved, and ignores the upper octet of the handle, so a caller may name
    /// a session by its index alone. A handle that references neither is
    /// TPM_RC_HANDLE.
    /// Returns the handle that was actually removed, which an aliased request
    /// resolves to something other than what the caller wrote.
    pub fn flush(&mut self, handle: u32) -> TpmResult<u32> {
        for candidate in self.flush_candidates(handle) {
            let loaded = self.sessions.remove(&candidate).is_some();
            let saved = self.saved.remove(&candidate).is_some();
            // Part 3 clause 28.4.1 has TPM2_FlushContext remove all of a
            // session's context, so what it was numbered goes too and stops
            // standing in the way of the gap.
            self.version.remove(&candidate);
            if loaded || saved {
                return Ok(candidate);
            }
        }
        Err(TpmRc(rc::HANDLE))
    }

    /// The handles a flush request could mean, most exact first.
    fn flush_candidates(&self, handle: u32) -> Vec<u32> {
        let index = handle & 0x00FF_FFFF;
        let mut out = vec![handle];
        for base in [hc::HMAC_SESSION_FIRST, hc::POLICY_SESSION_FIRST] {
            let aliased = (base & 0xFF00_0000) | index;
            if aliased != handle && (self.sessions.contains_key(&aliased)
                || self.saved.contains_key(&aliased))
            {
                out.push(aliased);
            }
        }
        out
    }

    /// Move a session out of memory, keeping its handle reserved.
    pub fn save(&mut self, handle: u32) -> TpmResult<(Session, u64)> {
        let session = self.sessions.remove(&handle).ok_or(TpmRc(rc::HANDLE))?;
        // The identifier was taken when the session was created or last
        // loaded, which is when clause 27.2.2 says the counter advances.
        let id = self.version.remove(&handle).unwrap_or(self.context_counter);
        self.saved.insert(handle, id);
        Ok((session, id))
    }

    /// Bring a saved session back into memory.
    pub fn restore(&mut self, session: Session, version: u64) -> TpmResult<()> {
        let handle = session.handle;
        // Part 1 clause 27.5: "a saved session context may only be loaded
        // once", and the counter value "serves as a version number for the
        // session context ... the TPM maintains a database of concurrent
        // sessions so that it can validate that a reloaded session context is
        // the most recent version". An older blob of the same session carries
        // an older version, and taking it would be the replay the clause says
        // these limitations exist to prevent.
        match self.saved.get(&handle) {
            Some(current) if *current == version => {}
            Some(_) => return Err(TpmRc(rc::VALUE)),
            None => return Err(TpmRc(rc::HANDLE)),
        }
        if self.sessions.len() >= config::MAX_LOADED_SESSIONS as usize {
            return Err(TpmRc(rc::SESSION_MEMORY));
        }
        // Part 1 clause 27.2.2 advances the counter when a context is loaded,
        // so it is taken once nothing is left that could refuse the load.
        let id = self.next_context_id();
        self.version.insert(handle, id);
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

    /// Every session handle whose context the TPM has saved.
    pub fn saved_handles(&self) -> Vec<u32> {
        self.saved.keys().copied().collect()
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
        self.version.clear();
        self.context_counter = 1;
        self.object_counter = 1;
    }

    /// The handles of the saved sessions and the identifier each was given.
    pub fn saved_contexts(&self) -> Vec<(u32, u64)> {
        self.saved.iter().map(|(h, id)| (*h, *id)).collect()
    }

    /// Put back what [`saved_contexts`] gave, after a TPM Restart or Resume.
    pub fn restore_saved_contexts(
        &mut self,
        saved: Vec<(u32, u64)>,
        counter: u64,
        object_counter: u64,
    ) {
        self.saved = saved.into_iter().collect();
        self.context_counter = counter;
        self.object_counter = object_counter;
    }

    /// Drop the sessions in TPM memory and keep the record of the saved ones.
    ///
    /// Part 1 clause 27.5: "session contexts in TPM RAM are flushed on any
    /// TPM2_Startup(). Saved session contexts are not invalidated and may be
    /// reloaded after a TPM Restart or TPM Resume. Saved session contexts are
    /// invalidated on a TPM Reset." A saved session is only reloadable while
    /// the TPM still remembers that its handle was assigned, so that record
    /// outlives a restart with it.
    pub fn flush_loaded(&mut self) {
        self.sessions.clear();
        self.version.clear();
    }

}

/// True when `handle` is in one of the session ranges.
pub fn is_session_handle(handle: u32) -> bool {
    (hc::HMAC_SESSION_FIRST..=hc::HMAC_SESSION_LAST).contains(&handle)
        || (hc::POLICY_SESSION_FIRST..=hc::POLICY_SESSION_LAST).contains(&handle)
}

/// True when `handle` could name a session for TPM2_FlushContext.
///
/// Part 3 clause 28.4.1 ignores the upper octet of a session handle there, so
/// a handle whose lower three octets fall in the session index range counts,
/// whatever the octet above them says. The example in that clause flushes
/// session 0x03000000 through the handle 0x20000000.
pub fn is_flushable_session(handle: u32) -> bool {
    if is_session_handle(handle) {
        return true;
    }
    // A transient object handle names an object, not a session.
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        return false;
    }
    let index = handle & 0x00FF_FFFF;
    index < config::MAX_ACTIVE_SESSIONS as u32
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

    fn hex(s: &str) -> Vec<u8> {
        crate::util::hex::decode(s).unwrap()
    }

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
        assert!(derive_session_key(alg::SHA256, true, b"", b"", b"n1", b"n2")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_bound_session_has_a_key_even_when_the_bound_value_is_empty() {
        // Part 1 clause 16.6.8: "If both tpmKey and bind are TPM_RH_NULL, then
        // sessionKey is set to an Empty Buffer. Otherwise, the sessionKey is
        // created as follows". The exemption is on the two handles, not on what
        // they yield, so binding to an entity whose authorization value is
        // empty still runs the KDF over nothing and gets a key.
        let key = derive_session_key(alg::SHA256, false, b"", b"", b"tpm", b"caller").unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(
            key,
            kdfa(alg::SHA256, b"", "ATH", b"tpm", b"caller", 256).unwrap()
        );

        // Windows binds a session to TPM_RH_LOCKOUT before it sets the lockout
        // authorization, and a TPM that answered with an Empty Buffer here
        // refused every command Windows sent on that session. These are the
        // nonces and the HMAC from one such command, taken from a command log.
        let nonce_tpm =
            hex("51702a01aa40328fa39e0012efe86b9e49a3fc72f2505ad7158474e0342403e5");
        let nonce_caller =
            hex("01878c105e542784d3c71662e2506a1c18517368f0705fe3957510ebea2fc9d9");
        let session_key =
            derive_session_key(alg::SHA256, false, b"", b"", &nonce_tpm, &nonce_caller).unwrap();

        // TPM2_HierarchyChangeAuth on TPM_RH_LOCKOUT setting an empty value.
        // The Name of a permanent handle is the handle, Part 1 clause 16.
        let cp = cp_hash(alg::SHA256, 0x0000_0129, &[&hex("4000000a")], &hex("0000")).unwrap();
        let command_nonce =
            hex("5ae571f232419f3c976628ff3b1eeff73e6cba12afed5eb8b8768412a0e00f88");
        let mut body = Vec::new();
        body.extend_from_slice(&cp);
        body.extend_from_slice(&command_nonce);
        body.extend_from_slice(&nonce_tpm);
        body.push(0x00);
        // The session is bound to the entity being authorized, so the
        // authorization value is not added to the key, Part 1 clause 16.6.9.
        assert_eq!(
            crate::tpm::crypto::hmac::hmac(alg::SHA256, &session_key, &body).unwrap(),
            hex("d2cd2fe7af6e7673a625e05fd154a1108815cde1f453afd2ee600aecd5eea1a7"),
            "the session key does not match what a real caller computed"
        );
    }

    #[test]
    fn the_session_key_is_kdfa_over_the_bind_value_and_salt() {
        let key =
            derive_session_key(alg::SHA256, false, b"auth", b"salt", b"tpm", b"caller").unwrap();
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
        let base = derive_session_key(alg::SHA256, false, b"a", b"s", b"t", b"c").unwrap();
        assert_ne!(base, derive_session_key(alg::SHA256, false, b"b", b"s", b"t", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, false, b"a", b"x", b"t", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, false, b"a", b"s", b"u", b"c").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA256, false, b"a", b"s", b"t", b"d").unwrap());
        assert_ne!(base, derive_session_key(alg::SHA384, false, b"a", b"s", b"t", b"c").unwrap());
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
    fn a_saved_session_can_be_flushed() {
        // Part 3 clause 28.4.1: a session need not be loaded to be flushed,
        // and its saved context is invalidated.
        let mut slots = SessionSlots::new();
        let handle = slots.allocate_handle(se::POLICY).unwrap();
        slots.insert(session_with(handle, se::POLICY)).unwrap();
        slots.save(handle).unwrap();
        assert_eq!(slots.len(), 0, "the session is saved, not loaded");
        assert_eq!(slots.active(), 1);

        assert_eq!(slots.flush(handle).unwrap(), handle);
        assert_eq!(slots.active(), 0, "the saved context is gone");

        // A handle that names neither a loaded nor a saved session is refused.
        assert_eq!(slots.flush(handle).unwrap_err(), TpmRc(rc::HANDLE));
    }

    #[test]
    fn the_upper_octet_of_a_flushed_session_handle_is_ignored() {
        let mut slots = SessionSlots::new();
        let handle = slots.allocate_handle(se::POLICY).unwrap();
        slots.insert(session_with(handle, se::POLICY)).unwrap();

        // The clause 28.4.1 example: 0x20000000 flushes 0x03000000.
        let aliased = 0x2000_0000 | (handle & 0x00FF_FFFF);
        assert!(is_flushable_session(aliased));
        // The flush reports the handle it resolved to, so the caller can act
        // on the session that actually went away.
        assert_eq!(slots.flush(aliased).unwrap(), handle);
        assert_eq!(slots.active(), 0);
    }

    /// A session with the given handle and type, for the flush tests.
    fn session_with(handle: u32, session_type: u8) -> Session {
        Session::new(
            handle,
            session_type,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            crate::tpm::constants::rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap()
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
    fn a_context_identifier_is_used_by_only_one_session() {
        // Part 1 clause 12.4 makes the low order three octets of a session
        // handle unique. An HMAC session and a policy session that shared them
        // could not be told apart by the clause 28.4.1 flush, which names a
        // session by those octets and ignores the upper one.
        let mut slots = SessionSlots::new();
        let hmac = slots.allocate_handle(se::HMAC).unwrap();
        slots.insert(session_with(hmac, se::HMAC)).unwrap();
        let policy = slots.allocate_handle(se::POLICY).unwrap();
        slots.insert(session_with(policy, se::POLICY)).unwrap();
        assert_eq!(hmac, hc::HMAC_SESSION_FIRST);
        assert_ne!(hmac & 0x00FF_FFFF, policy & 0x00FF_FFFF);

        // Flushing one by an aliased handle leaves the other alone.
        let alias = 0x2000_0000 | (policy & 0x00FF_FFFF);
        assert_eq!(slots.flush(alias).unwrap(), policy);
        assert!(slots.contains(hmac));
        assert!(!slots.contains(policy));
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
        slots.restore(saved.clone(), id).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots.active(), 1);
    }

    #[test]
    fn a_session_takes_its_number_when_it_is_created_and_when_it_is_loaded() {
        // Part 1 clause 27.2.2: contextCounter "increments when a session
        // context is created or loaded". Saving is neither, so a context
        // carries the number its session already had.
        let mut slots = SessionSlots::new();
        let before = slots.context_counter();
        let h = slots.insert(session(se::HMAC)).unwrap();
        assert_eq!(
            slots.context_counter(),
            before + 1,
            "creating a session did not take a number"
        );
        let at_create = slots.context_counter();
        let (blob, id) = slots.save(h).unwrap();
        assert_eq!(
            slots.context_counter(),
            at_create,
            "saving took a number of its own"
        );
        assert_eq!(id, before, "the context does not carry the session's number");
        slots.restore(blob, id).unwrap();
        assert_eq!(
            slots.context_counter(),
            at_create + 1,
            "loading did not take a number"
        );
    }

    #[test]
    fn an_object_context_does_not_move_the_session_counter() {
        // The same clause keeps objectContextID apart, incremented "each time
        // an object context is saved".
        let mut slots = SessionSlots::new();
        let sessions_before = slots.context_counter();
        let objects_before = slots.object_counter();
        assert_eq!(slots.next_object_id(), objects_before);
        assert_eq!(slots.object_counter(), objects_before + 1);
        assert_eq!(
            slots.context_counter(),
            sessions_before,
            "an object context took a session number"
        );
    }

    #[test]
    fn a_session_that_would_strand_an_old_context_is_refused() {
        // Part 3 clause 11.1.1: "if the TPM implements a gap scheme for
        // assigning contextID values, then the TPM shall return
        // TPM_RC_CONTEXT_GAP if creating the session would prevent recycling
        // of old saved contexts."
        let mut slots = SessionSlots::new();
        let h = slots.insert(session(se::HMAC)).unwrap();
        let (blob, id) = slots.save(h).unwrap();

        // A session whose number sits exactly the reported maximum from the
        // oldest is still allowed: Part 2 Table 30 calls that value "the
        // maximum allowed difference", not the first one refused.
        while slots.context_counter() - id < config::CONTEXT_GAP_MAX as u64 {
            slots.next_context_id();
        }
        assert!(!slots.at_context_gap(), "the maximum itself was refused");
        let mut edge = session(se::HMAC);
        edge.handle = hc::HMAC_SESSION_FIRST + 1;
        let at_edge = slots.insert(edge).unwrap();
        assert_eq!(
            slots.saved_version(at_edge).unwrap() - id,
            config::CONTEXT_GAP_MAX as u64,
            "the edge is not the maximum apart"
        );
        slots.save(at_edge).unwrap();

        // Taking that one moved the counter, so the next would sit further out
        // than the maximum and the window is full without another step.
        assert!(slots.at_context_gap(), "the window is not reported full");

        let mut past = session(se::HMAC);
        past.handle = hc::HMAC_SESSION_FIRST + 2;
        assert_eq!(
            slots.insert(past).unwrap_err(),
            TpmRc(rc::CONTEXT_GAP),
            "a session was created past the gap"
        );

        // Part 3 Table 17: "the remedy is to load the session context with the
        // lowest number so that its tracking number can be updated."
        slots.restore(blob, id).unwrap();
        assert!(!slots.at_context_gap(), "loading the oldest did not close the gap");
        let mut again = session(se::HMAC);
        again.handle = hc::HMAC_SESSION_FIRST + 3;
        assert!(slots.insert(again).is_ok(), "a session still could not be made");
    }

    #[test]
    fn a_flushed_session_stops_holding_the_window_open() {
        // Part 3 clause 28.4.1 has TPM2_FlushContext remove all of a session's
        // context, so the number it held is not one of the active ones any
        // more. Leaving it behind would report a gap whose remedy names a
        // session that is no longer there.
        let mut slots = SessionSlots::new();
        let h = slots.insert(session(se::HMAC)).unwrap();
        let id = slots.saved_version(h).unwrap();
        while slots.context_counter() - id <= config::CONTEXT_GAP_MAX as u64 {
            slots.next_context_id();
        }
        assert!(slots.at_context_gap(), "the loaded session did not hold it");
        slots.flush(h).unwrap();
        assert!(
            !slots.at_context_gap(),
            "a flushed session still holds the window open"
        );
    }

    #[test]
    fn an_older_version_of_the_same_session_is_refused() {
        // Part 1 clause 27.5: "a saved session context may only be loaded
        // once", and the counter value assigned at each save "serves as a
        // version number for the session context", so a blob from an earlier
        // save is not the most recent version and does not load.
        let mut slots = SessionSlots::new();
        let h = slots.insert(session(se::HMAC)).unwrap();
        let (first, first_id) = slots.save(h).unwrap();
        slots.restore(first.clone(), first_id).unwrap();
        let (_second, second_id) = slots.save(h).unwrap();
        assert_ne!(first_id, second_id, "a reload takes a new version");
        assert_eq!(
            slots.restore(first, first_id).unwrap_err(),
            TpmRc(rc::VALUE),
            "the older blob was taken"
        );
    }

    #[test]
    fn restoring_an_unknown_handle_is_refused() {
        let mut slots = SessionSlots::new();
        assert_eq!(
            slots.restore(session(se::HMAC), 1).unwrap_err(),
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

    #[test]
    fn a_policy_session_keys_on_what_the_policy_asked_for_not_on_binding() {
        // Part 1 clause 16.6.9 gives two rules. For an HMAC session the
        // authValue is left out when "the authorization is for the entity to
        // which the session is bound". For a policy session it is included when
        // "the session has isAuthValueNeeded SET (by TPM_PolicyAuthValue())"
        // and left out otherwise, and binding does not come into it. A bound
        // policy session that called TPM2_PolicyAuthValue therefore keys on
        // sessionKey || authValue, where a bound HMAC session would not.
        let name = b"an entity name".to_vec();
        let auth = b"an authorization value".to_vec();

        let mut hmac_session = session(se::HMAC);
        hmac_session.session_key = b"a session key".to_vec();
        hmac_session.bind = rh::OWNER;
        hmac_session.bind_name = Session::bind_id(&name, &auth);
        assert_eq!(
            hmac_session.hmac_key(&name, &auth),
            b"a session key".to_vec(),
            "a bound HMAC session leaves the authorization value out"
        );

        let mut policy = session(se::POLICY);
        policy.session_key = b"a session key".to_vec();
        policy.bind = rh::OWNER;
        policy.bind_name = Session::bind_id(&name, &auth);
        assert_eq!(
            policy.hmac_key(&name, &auth),
            b"a session key".to_vec(),
            "a policy that did not ask for the value leaves it out"
        );
        policy.policy.auth_value_needed = true;
        let mut want = b"a session key".to_vec();
        want.extend_from_slice(&auth);
        assert_eq!(
            policy.hmac_key(&name, &auth),
            want,
            "TPM2_PolicyAuthValue folds the value in even when the session is bound"
        );
    }

    #[test]
    fn an_authorization_hmac_may_be_omitted_only_when_the_key_is_empty() {
        // Part 1 clause 16.6.16: when the HMAC key would be an Empty Buffer
        // "the caller has the option of either providing the results of the
        // authHMAC computation, or not. If authHMAC is provided ... the TPM
        // will validate that the value in hmac matches the internally
        // calculated value. If authHMAC is not provided, the size of hmac will
        // be zero and the TPM will accept this value".
        let expected = vec![0xaau8; 32];

        // With no key, an omitted HMAC stands and a correct one still passes.
        assert!(auth_hmac_accepted(b"", &expected, &[]));
        assert!(auth_hmac_accepted(b"", &expected, &expected));
        // A value that was supplied is always checked, so a wrong one fails
        // even though none at all would have been accepted.
        assert!(!auth_hmac_accepted(b"", &expected, &[0xbbu8; 32]));

        // With a key there is no option: the HMAC has to be there and right.
        assert!(!auth_hmac_accepted(b"key", &expected, &[]));
        assert!(auth_hmac_accepted(b"key", &expected, &expected));
    }
}
