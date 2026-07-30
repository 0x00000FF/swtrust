//! Command implementations from TPM 2.0 Library Part 3.

pub mod dispatch;
pub mod execute;
pub mod hierarchy;
pub mod management;
pub mod nv;
pub mod pcr;
pub mod table;

use crate::tpm::constants::{cc, rc};
use crate::tpm::core::state::TpmState;
use crate::tpm::error::{TpmRc, TpmResult};

use dispatch::{Request, Response};

/// Run the command the request names.
pub fn run_command(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    match request.code {
        // Part 3 clause 9, startup and shutdown.
        cc::Startup => management::startup(state, request),
        cc::Shutdown => management::shutdown(state, request),

        // Part 3 clause 10, testing.
        cc::SelfTest => management::self_test(state, request),
        cc::IncrementalSelfTest => management::incremental_self_test(state, request),
        cc::GetTestResult => management::get_test_result(state, request),

        // Part 3 clause 12.9, parameter checking.
        cc::TestParms => management::test_parms(state, request),

        // Part 3 clause 14.7, curve parameters.
        cc::ECC_Parameters => management::ecc_parameters(state, request),

        // Part 3 clause 16, randomness.
        cc::GetRandom => management::get_random(state, request),
        cc::StirRandom => management::stir_random(state, request),

        // Part 3 clause 22, integrity collection.
        cc::PCR_Extend => pcr::pcr_extend(state, request),
        cc::PCR_Event => pcr::pcr_event(state, request),
        cc::PCR_Read => pcr::pcr_read(state, request),
        cc::PCR_Allocate => pcr::pcr_allocate(state, request),
        cc::PCR_SetAuthPolicy => pcr::pcr_set_auth_policy(state, request),
        cc::PCR_SetAuthValue => pcr::pcr_set_auth_value(state, request),
        cc::PCR_Reset => pcr::pcr_reset(state, request),

        // Part 3 clause 24, hierarchy administration.
        cc::HierarchyControl => hierarchy::hierarchy_control(state, request),
        cc::SetPrimaryPolicy => hierarchy::set_primary_policy(state, request),
        cc::ChangePPS => hierarchy::change_pps(state, request),
        cc::ChangeEPS => hierarchy::change_eps(state, request),
        cc::Clear => hierarchy::clear(state, request),
        cc::ClearControl => hierarchy::clear_control(state, request),
        cc::HierarchyChangeAuth => hierarchy::hierarchy_change_auth(state, request),

        // Part 3 clause 25, dictionary attack functions.
        cc::DictionaryAttackLockReset => {
            hierarchy::dictionary_attack_lock_reset(state, request)
        }
        cc::DictionaryAttackParameters => {
            hierarchy::dictionary_attack_parameters(state, request)
        }

        // Part 3 clause 26, miscellaneous management.
        cc::PP_Commands => hierarchy::pp_commands(state, request),
        cc::SetAlgorithmSet => hierarchy::set_algorithm_set(state, request),
        cc::ReadOnlyControl => hierarchy::read_only_control(state, request),

        // Part 3 clause 30, capabilities.
        cc::GetCapability => management::get_capability(state, request),

        // Part 3 clause 31, NV storage.
        cc::NV_DefineSpace => nv::nv_define_space(state, request),
        cc::NV_DefineSpace2 => nv::nv_define_space2(state, request),
        cc::NV_UndefineSpace => nv::nv_undefine_space(state, request),
        cc::NV_UndefineSpaceSpecial => nv::nv_undefine_space_special(state, request),
        cc::NV_ReadPublic => nv::nv_read_public(state, request),
        cc::NV_ReadPublic2 => nv::nv_read_public2(state, request),
        cc::NV_Write => nv::nv_write(state, request),
        cc::NV_Increment => nv::nv_increment(state, request),
        cc::NV_Extend => nv::nv_extend(state, request),
        cc::NV_SetBits => nv::nv_set_bits(state, request),
        cc::NV_WriteLock => nv::nv_write_lock(state, request),
        cc::NV_GlobalWriteLock => nv::nv_global_write_lock(state, request),
        cc::NV_Read => nv::nv_read(state, request),
        cc::NV_ReadLock => nv::nv_read_lock(state, request),
        cc::NV_ChangeAuth => nv::nv_change_auth(state, request),

        // Part 3 clause 34, field upgrade.
        cc::FirmwareRead => management::firmware_read(state, request),

        // Part 3 clause 36, the clock.
        cc::ReadClock => management::read_clock(state, request),
        cc::ClockSet => management::clock_set(state, request),
        cc::ClockRateAdjust => management::clock_rate_adjust(state, request),

        // Part 3 clause 38, vendor specific.
        cc::Vendor_TCG_Test => management::vendor_tcg_test(state, request),

        _ => Err(TpmRc(rc::COMMAND_CODE)),
    }
}
