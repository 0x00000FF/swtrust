//! Startup, self test, randomness, capabilities and the clock.
//!
//! These are the commands of Part 3 clauses 9, 10, 16, 30 and 36.

use crate::tpm::config;
use crate::tpm::constants::{alg, cap, cc, curve, pt, pt_pcr, rc, su};
use crate::tpm::core::pcr;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{ecc, hash, rand::Rng, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal, Writer};
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
    let startup_type = r.u16()?;
    match startup_type {
        su::CLEAR => state.on_startup_clear()?,
        su::STATE => {
            // A Startup(STATE) with no saved state is a TPM Reset instead,
            // reported as TPM_RC_VALUE per Part 3 clause 9.3.3.
            if state.startup_type != su::STATE {
                return Err(TpmRc(rc::VALUE).with_parameter(1));
            }
            state.on_startup_state()?
        }
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
    respond(|_| Ok(()))
}

/// TPM2_Shutdown, Part 3 clause 9.4.
pub fn shutdown(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let shutdown_type = r.u16()?;
    match shutdown_type {
        su::CLEAR => {
            state.startup_type = su::CLEAR;
            state.clock.safe = true;
        }
        su::STATE => {
            state.startup_type = su::STATE;
            state.clock.safe = true;
        }
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
    state.started = false;
    respond(|_| Ok(()))
}

/// TPM2_SelfTest, Part 3 clause 10.2.
pub fn self_test(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let _full_test = r.u8()?;
    state.self_test_done = true;
    respond(|_| Ok(()))
}

/// TPM2_IncrementalSelfTest, Part 3 clause 10.3.
///
/// Every algorithm this TPM implements is tested at power on, so nothing is
/// ever left to do and the returned list is always empty.
pub fn incremental_self_test(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let to_test = TpmlAlg::unmarshal(&mut r)?;
    for a in &to_test.items {
        if !config::IMPLEMENTED_ALGORITHMS.contains(a) {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
    }
    state.self_test_done = true;
    respond(|w| {
        TpmlAlg::empty().marshal(w);
        Ok(())
    })
}

/// TPM2_GetTestResult, Part 3 clause 10.4.
pub fn get_test_result(state: &TpmState, _request: &Request) -> TpmResult<Response> {
    let failure = state.failure_mode;
    respond(move |w| {
        Tpm2bDigest::empty().marshal(w);
        w.u32(if failure { rc::FAILURE } else { rc::SUCCESS });
        Ok(())
    })
}

/// TPM2_GetRandom, Part 3 clause 16.1.
pub fn get_random(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let requested = r.u16()? as usize;
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
    let data = Tpm2bDigest::unmarshal(&mut r)?;
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
    let new_time = r.u64()?;
    // Clock only ever advances.
    if new_time < state.clock.clock {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    state.clock.clock = new_time;
    respond(|_| Ok(()))
}

/// TPM2_ClockRateAdjust, Part 3 clause 36.3.
///
/// The clock of a software TPM follows the host, so an adjustment is accepted
/// and recorded as having no effect.
pub fn clock_rate_adjust(_state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let adjust = r.i8()?;
    if !(-3..=3).contains(&adjust) {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    respond(|_| Ok(()))
}

/// TPM2_TestParms, Part 3 clause 12.9.
pub fn test_parms(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    // Unmarshalling already applies every interface type check, so a structure
    // that parses is one the TPM supports.
    let _parms = PublicParmsTagged::unmarshal(&mut r)?;
    respond(|_| Ok(()))
}

/// TPM2_ECC_Parameters, Part 3 clause 14.7.
pub fn ecc_parameters(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bEccParameter;

    let mut r = request.reader();
    let curve_id = r.u16()?;
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
    let capability = r.u32()?;
    let property = r.u32()?;
    let count = r.u32()? as usize;

    let (more, data) = build_capability(state, capability, property, count)?;
    respond(move |w| {
        w.u8(u8::from(more));
        CapabilityData { data }.marshal(w);
        Ok(())
    })
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
            for a in config::IMPLEMENTED_ALGORITHMS {
                if (*a as u32) < property {
                    continue;
                }
                if items.len() >= count.min(TpmlAlgProperty::MAX) {
                    more = true;
                    break;
                }
                items.push(AlgProperty {
                    alg: *a,
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
            let mut items = Vec::new();
            for a in state.pcr.algorithms() {
                let mut select = PcrSelect::none();
                for i in 0..config::IMPLEMENTATION_PCR as usize {
                    select.select(i);
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
            let all: Vec<ActData> = Vec::new();
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
        TaggedProperty::new(pt::PS_REVISION, TPM_SPEC_VERSION),
        TaggedProperty::new(pt::PS_DAY_OF_YEAR, 0),
        TaggedProperty::new(pt::PS_YEAR, 0),
        TaggedProperty::new(pt::SPLIT_MAX, 0),
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

    add(pt_pcr::SAVE, &|_| true);
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
            pcr::attributes(i).reset_locality & (1 << locality) != 0
        });
    }
    add(pt_pcr::NO_INCREMENT, &|i| pcr::no_increment(i));
    add(pt_pcr::DRTM_RESET, &|i| pcr::attributes(i).starts_at_ones);
    add(pt_pcr::POLICY, &|_| false);
    add(pt_pcr::AUTH, &|_| false);
    out.sort_by_key(|p| p.tag);
    out
}

/// TPM2_FirmwareRead, Part 3 clause 34.3.
///
/// This TPM has no field upgradeable firmware, so there is nothing to read.
pub fn firmware_read(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let _sequence = r.u32()?;
    Err(TpmRc(rc::VALUE).with_parameter(1))
}

/// TPM2_Vendor_TCG_Test, Part 3 clause 38.1.
///
/// The command exists so a caller can check that command dispatch works. The
/// input data is returned unchanged.
pub fn vendor_tcg_test(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bData;
    let mut r = request.reader();
    let data = Tpm2bData::unmarshal(&mut r)?;
    respond(move |w| {
        data.marshal(w);
        Ok(())
    })
}

/// True when `alg_id` names something this TPM implements.
pub fn is_implemented_algorithm(alg_id: u16) -> bool {
    config::IMPLEMENTED_ALGORITHMS.contains(&alg_id)
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
            | cc::FieldUpgradeStart
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
        // The D-RTM registers reset from locality 4.
        let r4 = find(pt_pcr::RESET_L4);
        assert!(r4.select.is_selected(17));
        // PCR 16 does not advance the update counter.
        let ni = find(pt_pcr::NO_INCREMENT);
        assert!(ni.select.is_selected(16));
        assert!(!ni.select.is_selected(0));
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
