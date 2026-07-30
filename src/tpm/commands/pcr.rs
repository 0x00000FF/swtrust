//! Integrity collection, Part 3 clause 22.

use crate::tpm::config;
use crate::tpm::constants::{alg, hc, rc};
use crate::tpm::core::state::TpmState;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::base::{Tpm2bDigest, Tpm2bEvent, TpmtHa};
use crate::tpm::structures::lists::{TpmlDigest, TpmlDigestValues, TpmlPcrSelection};

use super::dispatch::{Request, Response};
use super::execute::respond;

/// The PCR index a handle names, or TPM_RC_VALUE.
fn pcr_index(handle: u32) -> TpmResult<u16> {
    if !(hc::PCR_FIRST..=hc::PCR_LAST).contains(&handle) {
        return Err(TpmRc(rc::VALUE));
    }
    Ok((handle - hc::PCR_FIRST) as u16)
}

/// TPM2_PCR_Extend, Part 3 clause 22.2.
pub fn pcr_extend(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let index = pcr_index(request.handle(0)?).map_err(|e| e.with_handle(1))?;
    let mut r = request.reader();
    let digests = TpmlDigestValues::unmarshal(&mut r)?;

    let mut pairs = Vec::with_capacity(digests.len());
    for d in &digests.items {
        if d.hash_alg == alg::NULL {
            return Err(TpmRc(rc::HASH).with_parameter(1));
        }
        pairs.push((d.hash_alg, d.digest.clone()));
    }
    state
        .pcr
        .extend(index, request.locality, &pairs)
        .map_err(|e| if e.0 == rc::LOCALITY { e } else { e.with_parameter(1) })?;
    respond(|_| Ok(()))
}

/// TPM2_PCR_Event, Part 3 clause 22.3.
pub fn pcr_event(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let event = Tpm2bEvent::unmarshal(&mut r)?;

    // A null handle means the event is only hashed, not recorded.
    let digests = if handle == crate::tpm::constants::rh::NULL {
        let mut out = Vec::new();
        for a in state.pcr.algorithms() {
            out.push((a, crate::tpm::crypto::hash::digest(a, event.as_slice())?));
        }
        out
    } else {
        let index = pcr_index(handle).map_err(|e| e.with_handle(1))?;
        state
            .pcr
            .event(index, request.locality, event.as_slice())?
    };

    respond(move |w| {
        let items = digests
            .into_iter()
            .map(|(a, d)| TpmtHa::new(a, d))
            .collect::<TpmResult<Vec<_>>>()?;
        TpmlDigestValues::new(items)?.marshal(w);
        Ok(())
    })
}

/// TPM2_PCR_Read, Part 3 clause 22.4.
pub fn pcr_read(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let requested = TpmlPcrSelection::unmarshal(&mut r)?;

    // Part 3 clause 22.4.3 returns as many values as fit in one response and
    // reports which ones those were.
    let filtered = state.pcr.filter_selection(&requested);
    let values = state.pcr.read_selection(&filtered);
    let limit = TpmlDigest::MAX;

    let mut selected = filtered.clone();
    if values.len() > limit {
        // Trim the selection to the registers actually returned.
        let mut remaining = limit;
        for sel in selected.items.iter_mut() {
            for index in sel.select.selected() {
                if remaining == 0 {
                    sel.select.deselect(index);
                } else {
                    remaining -= 1;
                }
            }
        }
    }
    let values = state.pcr.read_selection(&selected);
    let counter = state.pcr.update_counter();

    respond(move |w| {
        w.u32(counter);
        selected.marshal(w);
        let digests = values
            .into_iter()
            .map(Tpm2bDigest::new)
            .collect::<TpmResult<Vec<_>>>()?;
        // TPML_DIGEST normally requires two entries, but a read may return
        // fewer, so the list is written directly.
        w.u32(digests.len() as u32);
        for d in &digests {
            d.marshal(w);
        }
        Ok(())
    })
}

/// TPM2_PCR_Allocate, Part 3 clause 22.5.
pub fn pcr_allocate(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let requested = TpmlPcrSelection::unmarshal(&mut r)?;

    let mut banks = Vec::new();
    for sel in &requested.items {
        if sel.select.is_empty_selection() {
            continue;
        }
        if !config::IMPLEMENTED_PCR_BANKS.contains(&sel.hash_alg) {
            return Err(TpmRc(rc::HASH).with_parameter(1));
        }
        if !banks.contains(&sel.hash_alg) {
            banks.push(sel.hash_alg);
        }
    }
    if banks.is_empty() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    if banks.len() > config::HASH_COUNT {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    // The allocation takes effect at the next TPM Reset, so only the recorded
    // choice changes now.
    state.pcr_allocation = banks;
    let max_pcr = config::IMPLEMENTATION_PCR as u32;
    let size_needed = state.pcr_allocation.len() as u32 * max_pcr;
    let size_available = (config::NV_MEMORY_SIZE - state.nv.used()) as u32;

    respond(move |w| {
        w.u8(1);
        w.u32(max_pcr);
        w.u32(size_needed);
        w.u32(size_available);
        Ok(())
    })
}

/// TPM2_PCR_SetAuthPolicy, Part 3 clause 22.6.
pub fn pcr_set_auth_policy(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let policy = Tpm2bDigest::unmarshal(&mut r)?;
    let hash_alg = r.u16()?;
    let pcr_handle = r.u32()?;
    pcr_index(pcr_handle).map_err(|e| e.with_parameter(3))?;

    if hash_alg != alg::NULL {
        let size = crate::tpm::crypto::hash::digest_size(hash_alg)
            .map_err(|_| TpmRc(rc::HASH).with_parameter(2))?;
        if policy.len() != size {
            return Err(TpmRc(rc::SIZE).with_parameter(1));
        }
    } else if !policy.is_empty() {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    state.pcr_policy = TpmtHa::new(hash_alg, policy.as_slice().to_vec())?;
    respond(|_| Ok(()))
}

/// TPM2_PCR_SetAuthValue, Part 3 clause 22.7.
pub fn pcr_set_auth_value(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    pcr_index(request.handle(0)?).map_err(|e| e.with_handle(1))?;
    state.pcr_auth = auth.as_slice().to_vec();
    respond(|_| Ok(()))
}

/// TPM2_PCR_Reset, Part 3 clause 22.8.
pub fn pcr_reset(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let index = pcr_index(request.handle(0)?).map_err(|e| e.with_handle(1))?;
    state.pcr.reset(index, request.locality)?;
    respond(|_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pcr_handle_maps_to_an_index() {
        assert_eq!(pcr_index(hc::PCR_FIRST).unwrap(), 0);
        assert_eq!(pcr_index(hc::PCR_FIRST + 23).unwrap(), 23);
        assert_eq!(pcr_index(hc::PCR_LAST).unwrap(), 23);
        assert_eq!(pcr_index(hc::PCR_LAST + 1).unwrap_err(), TpmRc(rc::VALUE));
        assert_eq!(
            pcr_index(crate::tpm::constants::rh::OWNER).unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }
}
