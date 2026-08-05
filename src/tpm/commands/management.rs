//! Startup, self test, randomness, capabilities and the clock.
//!
//! These are the commands of Part 3 clauses 9, 10, 16, 30 and 36.

use crate::tpm::config;
use crate::tpm::constants::{alg, cap, cc, curve, pt, pt_pcr, rc, su};
use crate::tpm::core::pcr;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{ecc, hash, rand::Rng, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::fips;
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::{CommandAttributes, PermanentAttributes};
use crate::tpm::structures::base::{PcrSelect, Tpm2bDigest};
use crate::tpm::structures::capability::{Capabilities, CapabilityData};
use crate::tpm::structures::keys::PublicParmsTagged;
use crate::tpm::structures::lists::{
    ActData, AlgProperty, TaggedPcrSelect, TaggedProperty, TpmlActData, TpmlAlg, TpmlAlgProperty,
    TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlPubKey,
    TpmlSpdmSessionInfo, TpmlTaggedPcrProperty, TpmlTaggedPolicy, TpmlTaggedTpmProperty,
    TpmlVendorProperty,
};

use super::dispatch::{Request, Response};
use super::execute::respond;
use super::table;

/// TPM2_Startup, Part 3 clause 9.3.
pub fn startup(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let startup_type = r.u16().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    // PC Client Platform TPM Profile 1.07 clause 5.3.2 item 1: "The TPM2_Startup
    // command SHALL come from Locality 0 or 3, else a TPM SHALL return
    // TPM_RC_Locality." The two are the ones a platform starts from: locality 0
    // for an ordinary boot and locality 3 for one that has run an S-HCRTM
    // sequence first.
    if request.locality != 0 && request.locality != 3 {
        return Err(TpmRc(rc::LOCALITY));
    }
    match startup_type {
        su::CLEAR => state.on_startup_clear(request.locality)?,
        su::STATE => {
            // A Startup(STATE) that was not preceded by Shutdown(STATE) has
            // no state to resume, which Part 3 clause 9.3.3 reports as
            // TPM_RC_VALUE.
            if state.shutdown_type != su::STATE {
                return Err(TpmRc(rc::VALUE).with_parameter(1));
            }
            state.on_startup_state(request.locality)?
        }
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
    respond(|_| Ok(()))
}

/// TPM2_Shutdown, Part 3 clause 9.4.
pub fn shutdown(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let shutdown_type = r.u16().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    match shutdown_type {
        su::STATE if state.pcr_allocation_pending => {
            // Part 3 clause 22.5.1 allows only TPM_SU_CLEAR after
            // TPM2_PCR_Allocate, until the next _TPM_Init.
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
        su::CLEAR | su::STATE => {
            state.shutdown_type = shutdown_type;
            // safe is deliberately left as it is. Part 1 clause 33.3.3: "If
            // Safe is not SET when TPM2_Shutdown() is received, then NVClock
            // must not be set from Clock and Safe must not be SET on the
            // subsequent startup." A clock that is already unsafe stays unsafe
            // until it rolls over, which is the only thing that clears the
            // doubt.
            if shutdown_type == su::STATE {
                // Part 1 clause 40.2 saves the ACT timeout here, whole when
                // TPM2_ACT_SetTimeout has been used since the last startup and
                // half otherwise, so that shutting down and starting up again
                // cannot extend the timer for ever.
                state.act.on_shutdown_state();
            }
        }
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
    // The state reaches the state file with the shutdown recorded, so the
    // RAM backed NV data is once again what NV holds.
    state.startup_clear = state
        .startup_clear
        .with(crate::tpm::structures::attributes::StartupClearAttributes::ORDERLY);
    state.started = false;
    respond(|_| Ok(()))
}

/// TPM2_SelfTest, Part 3 clause 10.2.
///
/// fullTest of YES repeats every test whether or not it has already been run,
/// which is the periodic self test both FIPS 140-2 and FIPS 140-3 ask for. NO
/// tests only what has not been tested yet, and since a power on runs the
/// whole set that leaves nothing to do.
///
/// A failed test puts the TPM in failure mode, as Part 1 clause 12.3 and
/// clause 10.3.1 of the FIPS 140-3 guidance both require, so no further
/// cryptographic output is produced.
pub fn self_test(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let full_test = r.u8().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    // Part 2 Table 48 makes TPMI_YES_NO a choice of exactly NO and YES, and
    // gives TPM_RC_VALUE for anything else.
    if full_test > 1 {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    if full_test == 0 && state.self_test_done {
        return respond(|_| Ok(()));
    }
    run_self_tests(state)?;
    respond(|_| Ok(()))
}

/// Run every known answer test and record the outcome.
///
/// A failure sets failure mode and answers TPM_RC_FAILURE. The digest of the
/// running image is kept so TPM2_GetTestResult can report it.
pub fn run_self_tests(state: &mut TpmState) -> TpmResult<()> {
    match fips::known_answer_tests() {
        Ok(()) => {}
        Err(fips::Failure(which)) => {
            state.failure_mode = true;
            state.self_test_done = false;
            state.test_failure = Some(which.to_string());
            return Err(TpmRc(rc::FAILURE));
        }
    }
    match fips::integrity() {
        Ok(digest) => state.test_digest = digest,
        Err(fips::Failure(which)) => {
            state.failure_mode = true;
            state.self_test_done = false;
            state.test_failure = Some(which.to_string());
            return Err(TpmRc(rc::FAILURE));
        }
    }
    state.self_test_done = true;
    state.test_failure = None;
    Ok(())
}

/// TPM2_IncrementalSelfTest, Part 3 clause 10.3.
///
/// The answer is the subset of `toTest` that has not been tested yet. A power
/// on runs the whole set, so the list is empty unless a test has been asked
/// for an algorithm this TPM does not cover.
pub fn incremental_self_test(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let to_test = TpmlAlg::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    for a in &to_test.items {
        if !config::implemented_algorithms().contains(a) {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
    }
    if !state.self_test_done {
        run_self_tests(state)?;
    }
    // Anything asked for that no known answer test covers is still untested,
    // and saying so is more honest than reporting an empty list.
    let remaining: Vec<u16> = to_test
        .items
        .iter()
        .copied()
        .filter(|a| !fips::tested_algorithms().contains(a))
        .collect();
    respond(move |w| {
        TpmlAlg::new(remaining)?.marshal(w);
        Ok(())
    })
}

/// TPM2_GetTestResult, Part 3 clause 10.4.
///
/// outData carries the digest of the running image that the pre-operational
/// integrity test produced, or the name of the test that failed.
pub fn get_test_result(state: &TpmState, _request: &Request) -> TpmResult<Response> {
    let failure = state.failure_mode;
    let data = match &state.test_failure {
        Some(which) => which.as_bytes().to_vec(),
        None => state.test_digest.clone(),
    };
    respond(move |w| {
        Tpm2bDigest::new(data)?.marshal(w);
        w.u32(if failure { rc::FAILURE } else { rc::SUCCESS });
        Ok(())
    })
}

/// TPM2_GetRandom, Part 3 clause 16.1.
pub fn get_random(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let requested = r.u16().map_err(|e| e.with_parameter(1))? as usize;
    r.expect_end()?;
    // Part 3 clause 16.1.3 caps the answer at the size of the largest digest.
    let size = requested.min(crate::tpm::structures::base::MAX_DIGEST_SIZE);
    let bytes = state.rng.bytes(size)?;
    respond(move |w| {
        Tpm2bDigest::new(bytes)?.marshal(w);
        Ok(())
    })
}

/// TPM2_StirRandom, Part 3 clause 16.2.
pub fn stir_random(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    // Part 3 Table 77 gives inData as a TPM2B_SENSITIVE_DATA, and clause
    // 16.2.1 says it "may not be larger than 128 octets", which is the size
    // that structure holds. A TPM2B_DIGEST would have refused everything past
    // the largest digest.
    let data = crate::tpm::structures::base::Tpm2bSensitiveData::unmarshal(&mut r)
        .map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    if data.len() > config::MAX_RNG_ENTROPY_SIZE {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    state.rng.stir(data.as_slice())?;
    respond(|_| Ok(()))
}

/// TPM2_ReadClock, Part 3 clause 36.1.
pub fn read_clock(state: &TpmState, _request: &Request) -> TpmResult<Response> {
    let info = clock_info(state);
    let time = state.clock.time;
    respond(move |w| {
        w.u64(time);
        info.marshal(w);
        Ok(())
    })
}

/// The TPMS_CLOCK_INFO the TPM currently reports.
pub fn clock_info(state: &TpmState) -> crate::tpm::structures::attest::ClockInfo {
    crate::tpm::structures::attest::ClockInfo {
        clock: state.clock.clock,
        reset_count: state.clock.reset_count,
        restart_count: state.clock.restart_count,
        safe: state.clock.safe,
    }
}

/// TPM2_ClockSet, Part 3 clause 36.2.
pub fn clock_set(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let new_time = r.u64().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    // Part 3 clause 29.2.1: "The command will fail if newTime is less than the
    // current value of Clock or if the new time is greater than
    // FF FF 00 00 00 00 00 00. If both of these checks succeed, Clock is set to
    // newTime. If either of these checks fails, the TPM shall return
    // TPM_RC_VALUE and make no change to Clock."
    if new_time < state.clock.clock || new_time > config::MAX_CLOCK {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    let jump = new_time - state.clock.clock;
    state.clock.clock = new_time;

    // Part 1 clause 33.3.1: "If TPM2_ClockSet() causes the volatile and
    // non-volatile versions of Clock to differ by more than the
    // implementation-dependent update interval, then NV Clock will be updated
    // before TPM2_ClockSet() returns", and "After the next NV update of Clock,
    // safe is SET to indicate that Clock is not a repeat." The command writes
    // NV, so the record follows on its own.
    // The step counts towards how far the two copies have drifted apart, the
    // same way passing time does, so a run of small steps reaches the interval
    // just as one large step does. Dropping a step that did not reach it on its
    // own would let a caller move Clock as far as it liked without the copy in
    // NV ever being brought up to date.
    state.clock.nv_elapsed = state.clock.nv_elapsed.saturating_add(jump);
    if state.clock.nv_elapsed >= u64::from(config::NV_CLOCK_UPDATE_INTERVAL) {
        state.clock.nv_elapsed = 0;
        state.clock.safe = true;
    }
    respond(|_| Ok(()))
}

/// TPM2_ClockRateAdjust, Part 3 clause 36.3.
///
/// The clock of a software TPM follows the host, so an adjustment is accepted
/// and recorded as having no effect.
pub fn clock_rate_adjust(_state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let adjust = r.i8().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    if !(-3..=3).contains(&adjust) {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    respond(|_| Ok(()))
}

/// TPM2_TestParms, Part 3 clause 12.9.
pub fn test_parms(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    // Unmarshalling applies every interface type check, so a structure that
    // parses names algorithms the TPM has.
    let parms = PublicParmsTagged::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    // Whether they go together is a separate question. Part 2 Table 229 says
    // of an ECC key's kdf that "in the context of object creation,
    // TPM2_LoadExternal(), or TPM2_TestParms(), TPM_RC_KDF indicates the TPM
    // does not support the requested KDF", and a KEM is named by a curve and a
    // hash together, so this command has to answer for the pair.
    if let crate::tpm::structures::keys::PublicParms::Ecc { curve_id, kdf, .. } = parms.parms {
        if !kdf.is_null() && !crate::tpm::crypto::dhkem::is_kem_suite(curve_id, &kdf) {
            return Err(TpmRc(rc::KDF).with_parameter(1));
        }
    }
    respond(|_| Ok(()))
}

/// TPM2_ECC_Parameters, Part 3 clause 14.7.
pub fn ecc_parameters(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bEccParameter;

    let mut r = request.reader();
    let curve_id = r.u16().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    let c = ecc::Curve::new(curve_id).map_err(|_| TpmRc(rc::CURVE).with_parameter(1))?;
    let (p, a, b) = c.parameters()?;
    let (gx, gy) = c.generator_coordinates()?;
    let order = c.order()?;
    let key_size = c.bits() as u16;

    respond(move |w| {
        w.u16(curve_id);
        w.u16(key_size);
        // kdf and sign are TPM_ALG_NULL: this TPM applies no default scheme to
        // a curve, so the object template decides.
        w.u16(alg::NULL);
        w.u16(alg::NULL);
        Tpm2bEccParameter::new(p.to_bytes()?)?.marshal(w);
        Tpm2bEccParameter::new(a.to_bytes()?)?.marshal(w);
        Tpm2bEccParameter::new(b.to_bytes()?)?.marshal(w);
        Tpm2bEccParameter::new(gx)?.marshal(w);
        Tpm2bEccParameter::new(gy)?.marshal(w);
        Tpm2bEccParameter::new(order.to_bytes()?)?.marshal(w);
        Tpm2bEccParameter::new(vec![0x01])?.marshal(w);
        Ok(())
    })
}

/// TPM2_GetCapability, Part 3 clause 30.2.
pub fn get_capability(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let capability = r.u32().map_err(|e| e.with_parameter(1))?;
    let property = r.u32().map_err(|e| e.with_parameter(2))?;
    let count = r.u32().map_err(|e| e.with_parameter(3))? as usize;
    r.expect_end()?;

    let (more, data) = build_capability(state, capability, property, count)?;
    respond(move |w| {
        w.u8(u8::from(more));
        CapabilityData { data }.marshal(w);
        Ok(())
    })
}

/// The property structure that TPM2_PolicyCapability compares against.
///
/// Part 3 clause 23.23.1 has the TPM "fetch the indicated property that is used
/// by the TPM in the requested logical operation", takes it as operandA, and
/// answers TPM_RC_VALUE when the capability is not one of those Table 184
/// lists. None here is the clause's "the requested TPM property does not
/// exist", which the caller answers for.
///
/// Errors are numbered for that command, where Table 185 makes capability the
/// fourth parameter and property the fifth, rather than for TPM2_GetCapability,
/// where the collection below numbers them one and two.
pub fn capability_property(
    state: &TpmState,
    capability: u32,
    property: u32,
) -> TpmResult<Option<Vec<u8>>> {
    // Every capability Table 184 gives a property type. TPM_CAP_PCRS is absent
    // from it, and the example beside the table says so in as many words.
    const LISTED: &[u32] = &[
        cap::ALGS,
        cap::HANDLES,
        cap::COMMANDS,
        cap::PP_COMMANDS,
        cap::AUDIT_COMMANDS,
        cap::TPM_PROPERTIES,
        cap::PCR_PROPERTIES,
        cap::ECC_CURVES,
        cap::AUTH_POLICIES,
        cap::ACT,
        cap::PUB_KEYS,
        cap::SPDM_SESSION_INFO,
        cap::VENDOR_PROPERTY,
    ];
    if !LISTED.contains(&capability) {
        return Err(TpmRc(rc::VALUE).with_parameter(4));
    }

    // The same collection TPM2_GetCapability answers with, asked for the one
    // property. Each of those starts at the property named and returns what
    // follows it, so the first item is the one asked for only when it carries
    // the same value back.
    let (_, data) =
        build_capability(state, capability, property, 1).map_err(|e| e.at_parameter(5))?;
    let found = match &data {
        Capabilities::Algorithms(l) => l.items.first().map(|i| u32::from(i.alg)),
        Capabilities::Handles(l) => l.items.first().copied(),
        Capabilities::Command(l) => l.items.first().map(|i| u32::from(i.command_index())),
        Capabilities::PpCommands(l) => l.items.first().copied(),
        Capabilities::AuditCommands(l) => l.items.first().copied(),
        Capabilities::TpmProperties(l) => l.items.first().map(|i| i.property),
        Capabilities::PcrProperties(l) => l.items.first().map(|i| i.tag),
        Capabilities::EccCurves(l) => l.items.first().map(|i| u32::from(*i)),
        Capabilities::AuthPolicies(l) => l.items.first().map(|i| i.handle),
        Capabilities::Act(l) => l.items.first().map(|i| i.handle),
        // This TPM has none of these, so no property of theirs exists.
        _ => None,
    };
    if found != Some(property) {
        return Ok(None);
    }

    // A list marshals as its count and then its items, and the count is not
    // part of the property structure the offset reaches into.
    let mut w = crate::tpm::marshal::Writer::new();
    data.marshal(&mut w);
    let octets = w.into_vec();
    Ok(Some(octets.get(4..).unwrap_or_default().to_vec()))
}

/// Collect one capability, returning whether more values follow.
fn build_capability(
    state: &TpmState,
    capability: u32,
    property: u32,
    count: usize,
) -> TpmResult<(bool, Capabilities)> {
    match capability {
        cap::ALGS => {
            let mut items = Vec::new();
            let mut more = false;
            for a in config::implemented_algorithms() {
                if (a as u32) < property {
                    continue;
                }
                if items.len() >= count.min(TpmlAlgProperty::MAX) {
                    more = true;
                    break;
                }
                items.push(AlgProperty {
                    alg: a,
                    alg_properties: 0,
                });
            }
            Ok((more, Capabilities::Algorithms(TpmlAlgProperty { items })))
        }
        cap::HANDLES => {
            let all = handles_in_range(state, property);
            let (items, more) = take(all, count, TpmlHandle::MAX);
            Ok((more, Capabilities::Handles(TpmlHandle { items })))
        }
        cap::COMMANDS => {
            let mut all: Vec<CommandAttributes> = table::COMMANDS
                .iter()
                .filter(|c| c.code >= property)
                .map(|c| c.attributes())
                .collect();
            all.sort_by_key(|a| a.command_index());
            let (items, more) = take(all, count, TpmlCca::MAX);
            Ok((more, Capabilities::Command(TpmlCca { items })))
        }
        cap::PP_COMMANDS => {
            let all: Vec<u32> = state
                .pp_commands
                .iter()
                .copied()
                .filter(|c| *c >= property)
                .collect();
            let (items, more) = take(all, count, TpmlCc::MAX);
            Ok((more, Capabilities::PpCommands(TpmlCc { items })))
        }
        cap::AUDIT_COMMANDS => {
            let all: Vec<u32> = state
                .audit
                .commands
                .iter()
                .copied()
                .filter(|c| *c >= property)
                .collect();
            let (items, more) = take(all, count, TpmlCc::MAX);
            Ok((more, Capabilities::AuditCommands(TpmlCc { items })))
        }
        cap::PCRS => {
            // Part 3 clause 30.2 returns "the current allocation of PCR in a
            // TPM", which Part 1 clause 14.8 chooses per register, so a bank
            // that was given some of them says so.
            let mut items = Vec::new();
            for (a, bits) in state.pcr.allocation() {
                let mut select = PcrSelect::none();
                for (i, set) in bits.iter().enumerate() {
                    if *set {
                        select.select(i);
                    }
                }
                items.push(crate::tpm::structures::base::PcrSelection::new(a, select));
            }
            Ok((false, Capabilities::AssignedPcr(TpmlPcrSelection { items })))
        }
        cap::TPM_PROPERTIES => {
            let all = tpm_properties(state, property);
            let (items, more) = take(all, count, TpmlTaggedTpmProperty::MAX);
            Ok((more, Capabilities::TpmProperties(TpmlTaggedTpmProperty { items })))
        }
        cap::PCR_PROPERTIES => {
            let all = pcr_properties(property);
            let (items, more) = take(all, count, TpmlTaggedPcrProperty::MAX);
            Ok((more, Capabilities::PcrProperties(TpmlTaggedPcrProperty { items })))
        }
        cap::ECC_CURVES => {
            let all: Vec<u16> = config::IMPLEMENTED_CURVES
                .iter()
                .copied()
                .filter(|c| (*c as u32) >= property)
                .collect();
            let (items, more) = take(all, count, TpmlEccCurve::MAX);
            Ok((more, Capabilities::EccCurves(TpmlEccCurve { items })))
        }
        cap::AUTH_POLICIES => {
            let all = auth_policies(state, property);
            let (items, more) = take(all, count, TpmlTaggedPolicy::MAX);
            Ok((more, Capabilities::AuthPolicies(TpmlTaggedPolicy { items })))
        }
        cap::ACT => {
            // Part 2 clause 8.12 reads TPMA_ACT with
            // TPM2_GetCapability(TPM_CAP_ACT, TPM_RH_ACT_x). There is one timer,
            // so the list holds one entry and a property above it selects
            // nothing.
            // Part 3 clause 30.2.1 gives this capability a TPM_HANDLE property
            // and asks for TPM_RC_VALUE when it is not in the range the
            // capability covers, which for a timer is TPM_RH_ACT_0 to
            // TPM_RH_ACT_F.
            if !(crate::tpm::constants::rh::ACT_0..=crate::tpm::constants::rh::ACT_F)
                .contains(&property)
            {
                return Err(TpmRc(rc::VALUE).with_parameter(2));
            }
            let all: Vec<ActData> = if property <= crate::tpm::constants::rh::ACT_0 {
                vec![ActData {
                    handle: crate::tpm::constants::rh::ACT_0,
                    timeout: state.act.timeout(),
                    attributes: state.act.attributes(),
                }]
            } else {
                Vec::new()
            };
            let (items, more) = take(all, count, TpmlActData::MAX);
            Ok((more, Capabilities::Act(TpmlActData { items })))
        }
        cap::PUB_KEYS => Ok((false, Capabilities::PubKeys(TpmlPubKey::empty()))),
        cap::SPDM_SESSION_INFO => Ok((
            false,
            Capabilities::SpdmSessionInfo(TpmlSpdmSessionInfo::empty()),
        )),
        cap::VENDOR_PROPERTY => Ok((
            false,
            Capabilities::VendorProperty(TpmlVendorProperty::empty()),
        )),
        _ => Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
}

/// Take at most `count` items, saying whether any were left behind.
fn take<T>(all: Vec<T>, count: usize, max: usize) -> (Vec<T>, bool) {
    let limit = count.min(max);
    let more = all.len() > limit;
    (all.into_iter().take(limit).collect(), more)
}

/// Handles in the range the caller asked about.
fn handles_in_range(state: &TpmState, property: u32) -> Vec<u32> {
    use crate::tpm::constants::{hc, ht};

    let range = (property >> hc::HR_SHIFT) as u8;
    let mut out: Vec<u32> = match range {
        ht::PCR => (0..config::IMPLEMENTATION_PCR as u32)
            .map(|i| hc::PCR_FIRST + i)
            .collect(),
        ht::NV_INDEX => state.nv.handles(),
        ht::HMAC_SESSION => state
            .sessions
            .active_handles()
            .into_iter()
            .filter(|h| (hc::HMAC_SESSION_FIRST..=hc::HMAC_SESSION_LAST).contains(h))
            .collect(),
        ht::POLICY_SESSION => state
            .sessions
            .active_handles()
            .into_iter()
            .filter(|h| (hc::POLICY_SESSION_FIRST..=hc::POLICY_SESSION_LAST).contains(h))
            .collect(),
        ht::PERMANENT => permanent_handles(),
        ht::TRANSIENT => state.objects.handles(),
        ht::PERSISTENT => state.persistent.keys().copied().collect(),
        _ => Vec::new(),
    };
    out.retain(|h| *h >= property);
    out.sort_unstable();
    out
}

/// The permanent handles this TPM answers to.
fn permanent_handles() -> Vec<u32> {
    use crate::tpm::constants::rh;
    vec![
        rh::OWNER,
        rh::NULL,
        rh::LOCKOUT,
        rh::ENDORSEMENT,
        rh::PLATFORM,
        rh::PLATFORM_NV,
    ]
}

/// The policies of the permanent handles that have one.
fn auth_policies(state: &TpmState, property: u32) -> Vec<crate::tpm::structures::lists::TaggedPolicy> {
    use crate::tpm::constants::rh;
    use crate::tpm::structures::lists::TaggedPolicy;

    let mut out = Vec::new();
    for handle in [rh::OWNER, rh::ENDORSEMENT, rh::PLATFORM, rh::LOCKOUT] {
        if handle < property {
            continue;
        }
        let policy = if handle == rh::LOCKOUT {
            state.lockout_policy.clone()
        } else {
            match state.hierarchies.get(handle) {
                Ok(h) => h.policy.clone(),
                Err(_) => continue,
            }
        };
        if policy.hash_alg == alg::NULL {
            continue;
        }
        out.push(TaggedPolicy {
            handle,
            policy_hash: policy,
        });
    }
    out
}

/// The fixed and variable properties of Part 2 Table 28.
fn tpm_properties(state: &TpmState, property: u32) -> Vec<TaggedProperty> {
    use crate::tpm::constants::{TPM_SPEC_ERRATA, TPM_SPEC_FAMILY, TPM_SPEC_LEVEL, TPM_SPEC_VERSION, TPM_SPEC_YEAR};
    use crate::tpm::structures::attributes::{MemoryAttributes, ModesAttributes};

    let mut all = vec![
        TaggedProperty::new(pt::FAMILY_INDICATOR, TPM_SPEC_FAMILY),
        TaggedProperty::new(pt::LEVEL, TPM_SPEC_LEVEL),
        TaggedProperty::new(pt::REVISION, TPM_SPEC_VERSION),
        TaggedProperty::new(pt::ERRATA, TPM_SPEC_ERRATA),
        TaggedProperty::new(pt::YEAR, TPM_SPEC_YEAR),
        TaggedProperty::new(pt::MANUFACTURER, config::MANUFACTURER),
        TaggedProperty::new(pt::VENDOR_STRING_1, config::VENDOR_STRING_1),
        TaggedProperty::new(pt::VENDOR_STRING_2, config::VENDOR_STRING_2),
        TaggedProperty::new(pt::VENDOR_STRING_3, config::VENDOR_STRING_3),
        TaggedProperty::new(pt::VENDOR_STRING_4, config::VENDOR_STRING_4),
        TaggedProperty::new(pt::VENDOR_TPM_TYPE, config::VENDOR_TPM_TYPE),
        TaggedProperty::new(pt::FIRMWARE_VERSION_1, config::FIRMWARE_VERSION_1),
        TaggedProperty::new(pt::FIRMWARE_VERSION_2, config::FIRMWARE_VERSION_2),
        TaggedProperty::new(pt::INPUT_BUFFER, config::MAX_COMMAND_SIZE),
        TaggedProperty::new(pt::HR_TRANSIENT_MIN, config::MAX_LOADED_OBJECTS as u32),
        TaggedProperty::new(pt::HR_PERSISTENT_MIN, config::MIN_EVICT_OBJECTS as u32),
        TaggedProperty::new(pt::HR_LOADED_MIN, config::MAX_LOADED_SESSIONS as u32),
        TaggedProperty::new(pt::ACTIVE_SESSIONS_MAX, config::MAX_ACTIVE_SESSIONS as u32),
        TaggedProperty::new(pt::PCR_COUNT, config::IMPLEMENTATION_PCR as u32),
        TaggedProperty::new(pt::PCR_SELECT_MIN, config::PCR_SELECT_MIN as u32),
        TaggedProperty::new(pt::CONTEXT_GAP_MAX, config::CONTEXT_GAP_MAX),
        TaggedProperty::new(pt::NV_COUNTERS_MAX, config::MIN_COUNTER_INDICES),
        TaggedProperty::new(pt::NV_INDEX_MAX, config::MAX_NV_INDEX_SIZE as u32),
        TaggedProperty::new(pt::MEMORY, MemoryAttributes(MemoryAttributes::SHARED_NV).0),
        TaggedProperty::new(pt::CLOCK_UPDATE, config::NV_CLOCK_UPDATE_INTERVAL),
        TaggedProperty::new(pt::CONTEXT_HASH, config::CONTEXT_INTEGRITY_HASH_ALG as u32),
        TaggedProperty::new(pt::CONTEXT_SYM, config::CONTEXT_ENCRYPT_ALG as u32),
        TaggedProperty::new(pt::CONTEXT_SYM_SIZE, config::CONTEXT_ENCRYPT_KEY_BITS as u32),
        TaggedProperty::new(pt::ORDERLY_COUNT, (1 << config::ORDERLY_BITS) - 1),
        TaggedProperty::new(pt::MAX_COMMAND_SIZE, config::MAX_COMMAND_SIZE),
        TaggedProperty::new(pt::MAX_RESPONSE_SIZE, config::MAX_RESPONSE_SIZE),
        TaggedProperty::new(
            pt::MAX_DIGEST,
            crate::tpm::structures::base::MAX_DIGEST_SIZE as u32,
        ),
        TaggedProperty::new(pt::MAX_OBJECT_CONTEXT, config::MAX_OBJECT_CONTEXT),
        TaggedProperty::new(pt::MAX_SESSION_CONTEXT, config::MAX_SESSION_CONTEXT),
        TaggedProperty::new(pt::PS_FAMILY_INDICATOR, crate::tpm::constants::ps::PC),
        TaggedProperty::new(pt::PS_LEVEL, 0),
        TaggedProperty::new(pt::PS_REVISION, config::PS_REVISION),
        TaggedProperty::new(pt::PS_DAY_OF_YEAR, 0),
        TaggedProperty::new(pt::PS_YEAR, 0),
        TaggedProperty::new(pt::SPLIT_MAX, config::MAX_COMMIT_SEQUENCES as u32),
        TaggedProperty::new(pt::TOTAL_COMMANDS, table::COMMANDS.len() as u32),
        TaggedProperty::new(pt::LIBRARY_COMMANDS, table::library_command_count() as u32),
        TaggedProperty::new(pt::VENDOR_COMMANDS, table::vendor_command_count() as u32),
        TaggedProperty::new(pt::NV_BUFFER_MAX, config::MAX_NV_BUFFER_SIZE as u32),
        TaggedProperty::new(pt::MODES, ModesAttributes(0).0),
        TaggedProperty::new(pt::MAX_CAP_BUFFER, config::MAX_CAP_BUFFER as u32),
        TaggedProperty::new(pt::FIRMWARE_SVN, 0),
        TaggedProperty::new(pt::FIRMWARE_MAX_SVN, 0),
        TaggedProperty::new(pt::ML_PARAMETER_SETS, 0),
        // Variable properties.
        TaggedProperty::new(pt::PERMANENT, permanent_attributes(state).0),
        TaggedProperty::new(pt::STARTUP_CLEAR, state.startup_clear.0),
        TaggedProperty::new(pt::HR_NV_INDEX, state.nv.len() as u32),
        TaggedProperty::new(pt::HR_LOADED, state.objects.len() as u32),
        TaggedProperty::new(pt::HR_LOADED_AVAIL, state.objects.available() as u32),
        TaggedProperty::new(pt::HR_ACTIVE, state.sessions.active() as u32),
        TaggedProperty::new(
            pt::HR_ACTIVE_AVAIL,
            (config::MAX_ACTIVE_SESSIONS as usize).saturating_sub(state.sessions.active()) as u32,
        ),
        TaggedProperty::new(pt::HR_TRANSIENT_AVAIL, state.objects.available() as u32),
        TaggedProperty::new(pt::HR_PERSISTENT, state.persistent.len() as u32),
        TaggedProperty::new(
            pt::HR_PERSISTENT_AVAIL,
            (config::MIN_EVICT_OBJECTS as usize).saturating_sub(state.persistent.len()) as u32,
        ),
        TaggedProperty::new(pt::NV_COUNTERS, state.nv.counter_count() as u32),
        TaggedProperty::new(
            pt::NV_COUNTERS_AVAIL,
            config::MIN_COUNTER_INDICES.saturating_sub(state.nv.counter_count() as u32),
        ),
        TaggedProperty::new(pt::ALGORITHM_SET, state.algorithm_set),
        TaggedProperty::new(pt::LOADED_CURVES, config::IMPLEMENTED_CURVES.len() as u32),
        TaggedProperty::new(pt::LOCKOUT_COUNTER, state.lockout.failed_tries),
        TaggedProperty::new(pt::MAX_AUTH_FAIL, state.lockout.max_tries),
        TaggedProperty::new(pt::LOCKOUT_INTERVAL, state.lockout.recovery_time),
        TaggedProperty::new(pt::LOCKOUT_RECOVERY, state.lockout.lockout_recovery),
        TaggedProperty::new(pt::NV_WRITE_RECOVERY, 0),
        TaggedProperty::new(pt::AUDIT_COUNTER_0, (state.audit.counter >> 32) as u32),
        TaggedProperty::new(pt::AUDIT_COUNTER_1, state.audit.counter as u32),
    ];
    all.retain(|p| p.property >= property);
    all.sort_by_key(|p| p.property);
    all
}

/// TPMA_PERMANENT as it currently stands.
pub fn permanent_attributes(state: &TpmState) -> PermanentAttributes {
    let mut a = state.permanent;
    a.set(
        PermanentAttributes::OWNER_AUTH_SET,
        state.hierarchies.owner.has_auth(),
    );
    a.set(
        PermanentAttributes::ENDORSEMENT_AUTH_SET,
        state.hierarchies.endorsement.has_auth(),
    );
    a.set(
        PermanentAttributes::LOCKOUT_AUTH_SET,
        !state.lockout_auth.is_empty(),
    );
    a.set(PermanentAttributes::IN_LOCKOUT, state.lockout.in_lockout);
    a
}

/// The PCR properties of Part 2 Table 29.
fn pcr_properties(property: u32) -> Vec<TaggedPcrSelect> {
    let mut out = Vec::new();
    let mut add = |tag: u32, f: &dyn Fn(u16) -> bool| {
        if tag < property {
            return;
        }
        let mut select = PcrSelect::none();
        for i in 0..config::IMPLEMENTATION_PCR {
            if f(i) {
                select.select(i as usize);
            }
        }
        out.push(TaggedPcrSelect { tag, select });
    };

    add(pt_pcr::SAVE, &|i| pcr::is_saved(i));
    for (tag, locality) in [
        (pt_pcr::EXTEND_L0, 0u8),
        (pt_pcr::EXTEND_L1, 1),
        (pt_pcr::EXTEND_L2, 2),
        (pt_pcr::EXTEND_L3, 3),
        (pt_pcr::EXTEND_L4, 4),
    ] {
        add(tag, &move |i| {
            pcr::attributes(i).extend_locality & (1 << locality) != 0
        });
    }
    for (tag, locality) in [
        (pt_pcr::RESET_L0, 0u8),
        (pt_pcr::RESET_L1, 1),
        (pt_pcr::RESET_L2, 2),
        (pt_pcr::RESET_L3, 3),
        (pt_pcr::RESET_L4, 4),
    ] {
        add(tag, &move |i| {
            pcr::reset_capability_locality(i) & (1 << locality) != 0
        });
    }
    add(pt_pcr::NO_INCREMENT, &|i| pcr::no_increment(i));
    add(pt_pcr::DRTM_RESET, &|i| pcr::attributes(i).starts_at_ones);
    add(pt_pcr::POLICY, &|_| false);
    add(pt_pcr::AUTH, &|_| false);
    out.sort_by_key(|p| p.tag);
    out
}

/// TPM2_Vendor_TCG_Test, Part 3 clause 38.1.
///
/// The command exists so a caller can check that command dispatch works. The
/// input data is returned unchanged.
pub fn vendor_tcg_test(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bData;
    let mut r = request.reader();
    let data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    respond(move |w| {
        data.marshal(w);
        Ok(())
    })
}

/// True when `alg_id` names something this TPM implements.
pub fn is_implemented_algorithm(alg_id: u16) -> bool {
    config::implemented_algorithms().contains(&alg_id)
        || hash::is_supported(alg_id)
        || sym::is_supported_mode(alg_id)
}

/// True when `curve_id` names a curve this TPM implements.
pub fn is_implemented_curve(curve_id: u16) -> bool {
    config::IMPLEMENTED_CURVES.contains(&curve_id) && curve_id != curve::NONE
}

/// True when `code` is a command this TPM implements.
pub fn is_implemented_command(code: u32) -> bool {
    table::lookup(code).is_some()
}

/// Commands that may be given physical presence, used by TPM2_PP_Commands.
///
/// TPM2_FieldUpgradeStart belongs to this set in Part 2 but is not implemented
/// here, and a command this TPM does not implement cannot be selected.
pub fn is_pp_eligible(code: u32) -> bool {
    matches!(
        code,
        cc::Clear
            | cc::ClearControl
            | cc::HierarchyChangeAuth
            | cc::HierarchyControl
            | cc::ChangeEPS
            | cc::ChangePPS
            | cc::PP_Commands
            | cc::SetPrimaryPolicy
            | cc::NV_DefineSpace
            | cc::NV_UndefineSpace
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_properties_report_the_vendor_identity() {
        let state = TpmState::manufacture().unwrap();
        let props = tpm_properties(&state, 0);
        let find = |p: u32| props.iter().find(|t| t.property == p).map(|t| t.value);
        assert_eq!(find(pt::MANUFACTURER), Some(0x5357_5400));
        assert_eq!(find(pt::FIRMWARE_VERSION_1), Some(0x0001_0000));
        assert_eq!(find(pt::FIRMWARE_VERSION_2), Some(0x0000_0000));
        assert_eq!(find(pt::VENDOR_STRING_1), Some(0x5357_5400));
        assert_eq!(find(pt::REVISION), Some(185));
        assert_eq!(find(pt::PCR_COUNT), Some(24));
        assert_eq!(find(pt::MAX_COMMAND_SIZE), Some(config::MAX_COMMAND_SIZE));
    }

    #[test]
    fn properties_are_sorted_and_filtered() {
        let state = TpmState::manufacture().unwrap();
        let props = tpm_properties(&state, pt::PT_VAR);
        assert!(props.iter().all(|p| p.property >= pt::PT_VAR));
        for pair in props.windows(2) {
            assert!(pair[0].property < pair[1].property);
        }
    }

    #[test]
    fn permanent_attributes_track_the_authorization_values() {
        let mut state = TpmState::manufacture().unwrap();
        assert!(!permanent_attributes(&state).has(PermanentAttributes::OWNER_AUTH_SET));
        state.hierarchies.owner.auth = b"x".to_vec();
        assert!(permanent_attributes(&state).has(PermanentAttributes::OWNER_AUTH_SET));
        state.lockout_auth = b"y".to_vec();
        assert!(permanent_attributes(&state).has(PermanentAttributes::LOCKOUT_AUTH_SET));
        state.lockout.in_lockout = true;
        assert!(permanent_attributes(&state).has(PermanentAttributes::IN_LOCKOUT));
    }

    #[test]
    fn pcr_properties_describe_the_platform_profile() {
        let props = pcr_properties(0);
        let find = |tag: u32| props.iter().find(|p| p.tag == tag).unwrap();
        // Every PCR can be extended from locality 0 except the D-RTM range.
        let l0 = find(pt_pcr::EXTEND_L0);
        assert!(l0.select.is_selected(0));
        assert!(!l0.select.is_selected(17));
        // Only PCR 16 and 23 reset from locality 0.
        let r0 = find(pt_pcr::RESET_L0);
        assert!(r0.select.is_selected(16));
        assert!(r0.select.is_selected(23));
        assert!(!r0.select.is_selected(0));
        // No command resets PCR 17, but a D-RTM event does, at locality four,
        // and the capability reports every way a register can be reset.
        let r4 = find(pt_pcr::RESET_L4);
        assert!(r4.select.is_selected(17));
        assert!(!r4.select.is_selected(0));
        assert!(!r4.select.is_selected(16));
        // The TCB registers reset by command from localities two and three.
        let r2 = find(pt_pcr::RESET_L2);
        assert!(r2.select.is_selected(21));
        assert!(r2.select.is_selected(22));
        assert!(!r2.select.is_selected(17));
        // The debug, TCB and application registers do not advance the counter.
        let ni = find(pt_pcr::NO_INCREMENT);
        for index in [16usize, 21, 22, 23] {
            assert!(ni.select.is_selected(index), "PCR {index}");
        }
        assert!(!ni.select.is_selected(0));
        // Only the static root of trust registers are saved.
        let save = find(pt_pcr::SAVE);
        assert!(save.select.is_selected(0));
        assert!(save.select.is_selected(15));
        assert!(!save.select.is_selected(16));
        assert!(!save.select.is_selected(17));
        assert!(!save.select.is_selected(23));
        // The registers a D-RTM resets are reported.
        let drtm = find(pt_pcr::DRTM_RESET);
        assert!(drtm.select.is_selected(17));
        assert!(!drtm.select.is_selected(0));
    }

    #[test]
    fn capability_lists_report_more_when_truncated() {
        let state = TpmState::manufacture().unwrap();
        let (more, data) = build_capability(&state, cap::TPM_PROPERTIES, 0, 3).unwrap();
        assert!(more);
        if let Capabilities::TpmProperties(l) = data {
            assert_eq!(l.len(), 3);
        } else {
            panic!("wrong capability");
        }
        let (more, _) = build_capability(&state, cap::TPM_PROPERTIES, 0, 1000).unwrap();
        assert!(!more);
    }

    #[test]
    fn an_unknown_capability_is_refused() {
        let state = TpmState::manufacture().unwrap();
        let e = build_capability(&state, 0x0000_0099, 0, 1).unwrap_err();
        assert_eq!(e.0 & 0x03F, rc::VALUE & 0x03F);
    }

    #[test]
    fn the_command_capability_lists_every_implemented_command() {
        let state = TpmState::manufacture().unwrap();
        let (_, data) = build_capability(&state, cap::COMMANDS, 0, 1000).unwrap();
        if let Capabilities::Command(l) = data {
            assert_eq!(l.len(), table::COMMANDS.len().min(TpmlCca::MAX));
        } else {
            panic!("wrong capability");
        }
    }

    #[test]
    fn the_curve_capability_lists_the_implemented_curves() {
        let state = TpmState::manufacture().unwrap();
        let (_, data) = build_capability(&state, cap::ECC_CURVES, 0, 100).unwrap();
        if let Capabilities::EccCurves(l) = data {
            assert_eq!(l.items, config::IMPLEMENTED_CURVES.to_vec());
        } else {
            panic!("wrong capability");
        }
    }

    #[test]
    fn permanent_handles_are_listed() {
        let state = TpmState::manufacture().unwrap();
        let handles = handles_in_range(&state, crate::tpm::constants::rh::FIRST);
        assert!(handles.contains(&crate::tpm::constants::rh::OWNER));
        assert!(handles.contains(&crate::tpm::constants::rh::PLATFORM));
        assert!(handles.contains(&crate::tpm::constants::rh::LOCKOUT));
    }
}
