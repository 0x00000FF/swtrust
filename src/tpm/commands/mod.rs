//! Command implementations from TPM 2.0 Library Part 3.

pub mod dispatch;
pub mod execute;
pub mod management;
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

        // Part 3 clause 30, capabilities.
        cc::GetCapability => management::get_capability(state, request),

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
