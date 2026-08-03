//! Platform Configuration Registers, Part 1 clause 17.
//!
//! A PCR bank holds one register per implemented PCR for one hash algorithm.
//! Extending replaces the register with the hash of its old value followed by
//! the new digest. Which localities may reset or extend a register is fixed by
//! the platform profile and reported through
//! TPM2_GetCapability(TPM_CAP_PCR_PROPERTIES).

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::rc;
use crate::tpm::crypto::hash;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Reader, Writer};
use crate::tpm::structures::base::{digest_size, PcrSelect, PcrSelection};
use crate::tpm::structures::lists::TpmlPcrSelection;

/// What a locality may do to one PCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrAttributes {
    /// Bit `n` set means locality `n` may reset the PCR.
    pub reset_locality: u8,
    /// Bit `n` set means locality `n` may extend the PCR.
    pub extend_locality: u8,
    /// The register starts as all ones rather than all zeros after a reset.
    pub starts_at_ones: bool,
}

/// Localities zero through four.
const ALL_LOCALITIES: u8 = 0b0001_1111;
/// Locality four only, which is where a D-RTM sequence runs.
const LOCALITY_FOUR: u8 = 0b0001_0000;
/// Localities two through four.
const LOCALITY_TWO_TO_FOUR: u8 = 0b0001_1100;

/// Localities zero through three.
const LOCALITY_ZERO_TO_THREE: u8 = 0b0000_1111;
/// Localities one through three.
const LOCALITY_ONE_TO_THREE: u8 = 0b0000_1110;
/// Localities two and three, which reset the TCB registers by command.
const LOCALITY_TWO_AND_THREE: u8 = 0b0000_1100;
/// Locality two alone.
const LOCALITY_TWO: u8 = 0b0000_0100;

/// The attributes of `index` under the PC Client Platform Profile, clause 4.7.1
/// Table 14.
///
/// `reset_locality` is which localities may reset the register with
/// TPM2_PCR_Reset. It is not the same as being reset by a D-RTM event, which
/// the hardware does outside the command interface, so the registers a D-RTM
/// resets are marked by `starts_at_ones` instead.
///
/// PCR 0 through 15 hold the static root of trust and no command resets them.
/// PCR 16 is the debug register and PCR 23 the application register, both
/// resettable from any locality. PCR 17 through 20 belong to the dynamic root
/// of trust and no command resets them. PCR 21 and 22 are the TCB registers,
/// which localities two and three reset.
pub fn attributes(index: u16) -> PcrAttributes {
    match index {
        0..=15 => PcrAttributes {
            reset_locality: 0,
            extend_locality: ALL_LOCALITIES,
            starts_at_ones: false,
        },
        16 | 23 => PcrAttributes {
            reset_locality: LOCALITY_ZERO_TO_THREE,
            extend_locality: ALL_LOCALITIES,
            starts_at_ones: false,
        },
        17 | 18 => PcrAttributes {
            reset_locality: 0,
            extend_locality: LOCALITY_TWO_TO_FOUR,
            starts_at_ones: true,
        },
        19 => PcrAttributes {
            reset_locality: 0,
            extend_locality: LOCALITY_TWO_AND_THREE,
            starts_at_ones: true,
        },
        20 => PcrAttributes {
            reset_locality: LOCALITY_TWO_AND_THREE,
            extend_locality: LOCALITY_ONE_TO_THREE,
            starts_at_ones: true,
        },
        21 | 22 => PcrAttributes {
            reset_locality: LOCALITY_TWO_AND_THREE,
            extend_locality: LOCALITY_TWO,
            starts_at_ones: true,
        },
        _ => PcrAttributes {
            reset_locality: 0,
            extend_locality: 0,
            starts_at_ones: false,
        },
    }
}

/// True when the register is saved across a Startup(STATE).
///
/// The PC Client profile saves only the static root of trust registers.
pub fn is_saved(index: u16) -> bool {
    matches!(index, 0..=15)
}

/// The localities at which `index` can be reset by any means.
///
/// TPM_PT_PCR_RESET_Lx reports every way a register can be reset, not only
/// TPM2_PCR_Reset, so the registers a D-RTM event resets are reported at
/// locality four even though no command resets them.
pub fn reset_capability_locality(index: u16) -> u8 {
    let attrs = attributes(index);
    if attrs.starts_at_ones {
        attrs.reset_locality | LOCALITY_FOUR
    } else {
        attrs.reset_locality
    }
}

/// True when `index` is a PCR this TPM implements.
pub fn is_implemented(index: u16) -> bool {
    index < config::IMPLEMENTATION_PCR
}

/// True when changing `index` does not advance the update counter.
///
/// The PC Client profile excludes the debug register, the TCB registers and the
/// application register, so that repeated use of them does not invalidate every
/// outstanding PCR policy.
pub fn no_increment(index: u16) -> bool {
    matches!(index, 16 | 21 | 22 | 23)
}

/// The PCR of every allocated bank.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcrBanks {
    /// Registers keyed by hash algorithm, each holding IMPLEMENTATION_PCR
    /// digests of that algorithm's size.
    banks: BTreeMap<u16, Vec<Vec<u8>>>,
    /// Advanced whenever a PCR that increments is extended or reset.
    update_counter: u32,
}

impl PcrBanks {
    /// Allocate the given banks and set every register to its reset value.
    pub fn new(algorithms: &[u16]) -> TpmResult<PcrBanks> {
        let mut banks = PcrBanks::default();
        banks.allocate(algorithms)?;
        Ok(banks)
    }

    /// Replace the allocation, discarding the previous registers.
    ///
    /// Part 3 TPM2_PCR_Allocate takes effect on the next TPM Reset, so the
    /// caller is responsible for deferring this until then.
    pub fn allocate(&mut self, algorithms: &[u16]) -> TpmResult<()> {
        let mut banks = BTreeMap::new();
        for a in algorithms {
            let size = digest_size(*a).ok_or(TpmRc(rc::HASH))?;
            banks.insert(*a, vec![vec![0u8; size]; config::IMPLEMENTATION_PCR as usize]);
        }
        self.banks = banks;
        self.reset_all();
        Ok(())
    }

    /// The allocated hash algorithms, in increasing order.
    pub fn algorithms(&self) -> Vec<u16> {
        self.banks.keys().copied().collect()
    }

    /// True when a bank for `hash_alg` is allocated.
    pub fn has_bank(&self, hash_alg: u16) -> bool {
        self.banks.contains_key(&hash_alg)
    }

    /// The current update counter.
    pub fn update_counter(&self) -> u32 {
        self.update_counter
    }

    /// Put the update counter back to zero.
    ///
    /// Part 1 clause 34.4 keeps the counter across a TPM Resume, and starts it
    /// again from zero on a TPM Reset or a TPM Restart, because the registers
    /// go back to their reset values at the same time.
    pub fn reset_update_counter(&mut self) {
        self.update_counter = 0;
    }

    /// Put the counter back to a value that came from the state file.
    pub fn set_update_counter(&mut self, value: u32) {
        self.update_counter = value;
    }

    /// Apply a TPM Resume to the registers.
    ///
    /// Part 1 clause 8.6.2 keeps the value of a Resume PCR across a TPM Resume
    /// and puts every other register back to its default initial value.
    pub fn on_resume(&mut self) {
        for (hash_alg, bank) in self.banks.iter_mut() {
            let Some(size) = digest_size(*hash_alg) else {
                continue;
            };
            for (index, value) in bank.iter_mut().enumerate() {
                if is_saved(index as u16) {
                    continue;
                }
                let fill = if attributes(index as u16).starts_at_ones {
                    0xffu8
                } else {
                    0x00
                };
                *value = vec![fill; size];
            }
        }
    }

    /// Marshal every bank, so the values a TPM Resume restores survive a
    /// reload of the state file.
    pub fn marshal_values(&self, w: &mut Writer) {
        w.u32(self.banks.len() as u32);
        for (hash_alg, bank) in &self.banks {
            w.u16(*hash_alg);
            w.u32(bank.len() as u32);
            for value in bank {
                w.sized16(value);
            }
        }
    }

    /// Restore the values [`PcrBanks::marshal_values`] wrote.
    ///
    /// A bank or register that the current allocation does not have is
    /// discarded, so a state file written under a different allocation still
    /// loads.
    pub fn unmarshal_values(&mut self, r: &mut Reader<'_>) -> TpmResult<()> {
        let banks = r.u32()?;
        for _ in 0..banks {
            let hash_alg = r.u16()?;
            let count = r.u32()? as usize;
            for index in 0..count {
                let size = r.u16()? as usize;
                let value = r.take(size)?.to_vec();
                if let Some(bank) = self.banks.get_mut(&hash_alg) {
                    if let Some(slot) = bank.get_mut(index) {
                        if slot.len() == value.len() {
                            *slot = value;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Read one register.
    pub fn read(&self, hash_alg: u16, index: u16) -> TpmResult<&[u8]> {
        let bank = self.banks.get(&hash_alg).ok_or(TpmRc(rc::VALUE))?;
        bank.get(index as usize)
            .map(|v| v.as_slice())
            .ok_or(TpmRc(rc::VALUE))
    }

    /// Extend one register in one bank and advance the update counter.
    ///
    /// TPM2_PCR_Extend goes through [`PcrBanks::extend`], which checks the
    /// locality first and counts the whole command once. The debug console is
    /// not bound by locality but must still leave the counter right: a policy
    /// that recorded the counter has to stop matching once the register it
    /// covers has changed, which is Part 1 clause 16.7.7.6.
    pub fn extend_one(&mut self, hash_alg: u16, index: u16, digest: &[u8]) -> TpmResult<()> {
        self.extend_digest(hash_alg, index, digest)?;
        if !no_increment(index) {
            self.update_counter = self.update_counter.wrapping_add(1);
        }
        Ok(())
    }

    /// Put a digest straight into a register.
    ///
    /// No TPM command does this. The debug console uses it to place a register
    /// in a state that extending cannot reach, so a policy or a quote can be
    /// tried against a known value. The update counter advances as it would
    /// for an extend, because a reader has to be able to tell that the
    /// register changed.
    pub fn set(&mut self, hash_alg: u16, index: u16, digest: &[u8]) -> TpmResult<()> {
        if !is_implemented(index) {
            return Err(TpmRc(rc::VALUE));
        }
        let size = digest_size(hash_alg).ok_or(TpmRc(rc::HASH))?;
        if digest.len() != size {
            return Err(TpmRc(rc::SIZE));
        }
        let bank = self.banks.get_mut(&hash_alg).ok_or(TpmRc(rc::VALUE))?;
        bank[index as usize] = digest.to_vec();
        if !no_increment(index) {
            self.update_counter = self.update_counter.wrapping_add(1);
        }
        Ok(())
    }

    /// Set every register in every bank to its reset value.
    ///
    /// This is what TPM2_Startup(CLEAR) does.
    pub fn reset_all(&mut self) {
        for (alg, bank) in self.banks.iter_mut() {
            let size = digest_size(*alg).unwrap_or(0);
            for (index, reg) in bank.iter_mut().enumerate() {
                let fill = if attributes(index as u16).starts_at_ones {
                    0xff
                } else {
                    0x00
                };
                *reg = vec![fill; size];
            }
        }
    }

    /// Reset one PCR in every bank, checking the locality.
    pub fn reset(&mut self, index: u16, locality: u8) -> TpmResult<()> {
        if !is_implemented(index) {
            return Err(TpmRc(rc::VALUE));
        }
        let attrs = attributes(index);
        if locality > 4 || attrs.reset_locality & (1 << locality) == 0 {
            return Err(TpmRc(rc::LOCALITY));
        }
        for (alg, bank) in self.banks.iter_mut() {
            let size = digest_size(*alg).unwrap_or(0);
            // A reset by command always produces zeros; only a power on reset
            // gives the D-RTM registers their all ones value.
            bank[index as usize] = vec![0u8; size];
        }
        if !no_increment(index) {
            self.update_counter = self.update_counter.wrapping_add(1);
        }
        Ok(())
    }

    /// Extend one PCR in one bank with an already computed digest.
    pub fn extend_digest(&mut self, hash_alg: u16, index: u16, digest: &[u8]) -> TpmResult<()> {
        if !is_implemented(index) {
            return Err(TpmRc(rc::VALUE));
        }
        let size = digest_size(hash_alg).ok_or(TpmRc(rc::HASH))?;
        if digest.len() != size {
            return Err(TpmRc(rc::SIZE));
        }
        let bank = self.banks.get_mut(&hash_alg).ok_or(TpmRc(rc::VALUE))?;
        let current = bank[index as usize].clone();
        bank[index as usize] = hash::digest_parts(hash_alg, &[&current, digest])?;
        Ok(())
    }

    /// Extend one PCR in every allocated bank, checking the locality.
    ///
    /// `digests` supplies one digest per bank; a bank with no matching entry is
    /// left alone, which is what TPM2_PCR_Extend does.
    pub fn extend(
        &mut self,
        index: u16,
        locality: u8,
        digests: &[(u16, Vec<u8>)],
    ) -> TpmResult<()> {
        if !is_implemented(index) {
            return Err(TpmRc(rc::VALUE));
        }
        let attrs = attributes(index);
        if locality > 4 || attrs.extend_locality & (1 << locality) == 0 {
            return Err(TpmRc(rc::LOCALITY));
        }
        // Check every digest before changing anything so a failure leaves the
        // banks untouched.
        for (alg, digest) in digests {
            if !self.has_bank(*alg) {
                continue;
            }
            let size = digest_size(*alg).ok_or(TpmRc(rc::HASH))?;
            if digest.len() != size {
                return Err(TpmRc(rc::SIZE));
            }
        }
        // Part 3 clause 22.1 counts an extend once for each bank that changes,
        // unlike a reset, which is counted once however many banks it clears.
        // The count is of banks, not of entries: nothing stops a caller naming
        // the same algorithm twice, and both extends land in one bank.
        let mut counted: Vec<u16> = Vec::with_capacity(digests.len());
        for (alg, digest) in digests {
            if !self.has_bank(*alg) {
                continue;
            }
            self.extend_digest(*alg, index, digest)?;
            if !counted.contains(alg) {
                counted.push(*alg);
            }
        }
        let changed = counted.len() as u32;
        if !no_increment(index) {
            self.update_counter = self.update_counter.wrapping_add(changed);
        }
        Ok(())
    }

    /// Extend every allocated bank with the hash of `data`.
    ///
    /// This is TPM2_PCR_Event: each bank is extended with the digest of the
    /// event data taken with that bank's algorithm.
    pub fn event(
        &mut self,
        index: u16,
        locality: u8,
        data: &[u8],
    ) -> TpmResult<Vec<(u16, Vec<u8>)>> {
        let mut digests = Vec::with_capacity(self.banks.len());
        for alg in self.algorithms() {
            digests.push((alg, hash::digest(alg, data)?));
        }
        self.extend(index, locality, &digests)?;
        Ok(digests)
    }

    /// The digest over the selected PCR, as TPM2_Quote and TPM2_PolicyPCR use.
    ///
    /// Part 1 clause 17.9 concatenates the selected registers in increasing
    /// bank then index order and hashes the result with `hash_alg`.
    pub fn selection_digest(
        &self,
        hash_alg: u16,
        selection: &TpmlPcrSelection,
    ) -> TpmResult<Vec<u8>> {
        let mut h = hash::Hasher::new(hash_alg)?;
        for sel in &selection.items {
            let Some(bank) = self.banks.get(&sel.hash_alg) else {
                continue;
            };
            for index in sel.select.selected() {
                if index >= config::IMPLEMENTATION_PCR as usize {
                    continue;
                }
                h.update(&bank[index]);
            }
        }
        Ok(h.finish())
    }

    /// Narrow `selection` to the banks and registers that exist.
    ///
    /// TPM2_PCR_Read returns the selection it actually read, which drops any
    /// bank that is not allocated and any register that is not implemented.
    pub fn filter_selection(&self, selection: &TpmlPcrSelection) -> TpmlPcrSelection {
        let mut out = Vec::new();
        for sel in &selection.items {
            let mut filtered = PcrSelect {
                bits: vec![0u8; sel.select.bits.len().max(config::PCR_SELECT_MIN as usize)],
            };
            if self.banks.contains_key(&sel.hash_alg) {
                for index in sel.select.selected() {
                    if index < config::IMPLEMENTATION_PCR as usize {
                        filtered.select(index);
                    }
                }
            }
            out.push(PcrSelection::new(sel.hash_alg, filtered));
        }
        TpmlPcrSelection { items: out }
    }

    /// Read the values named by `selection`, in the order they are selected.
    pub fn read_selection(&self, selection: &TpmlPcrSelection) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for sel in &selection.items {
            let Some(bank) = self.banks.get(&sel.hash_alg) else {
                continue;
            };
            for index in sel.select.selected() {
                if index < config::IMPLEMENTATION_PCR as usize {
                    out.push(bank[index].clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;

    fn banks() -> PcrBanks {
        PcrBanks::new(config::DEFAULT_PCR_BANKS).unwrap()
    }

    #[test]
    fn allocation_creates_every_register() {
        let b = banks();
        assert_eq!(b.algorithms(), vec![alg::SHA256, alg::SHA384]);
        assert!(b.has_bank(alg::SHA256));
        assert!(!b.has_bank(alg::SHA512));
        assert_eq!(b.read(alg::SHA256, 0).unwrap().len(), 32);
        assert_eq!(b.read(alg::SHA384, 0).unwrap().len(), 48);
        assert_eq!(
            b.read(alg::SHA256, config::IMPLEMENTATION_PCR).unwrap_err(),
            TpmRc(rc::VALUE)
        );
        assert_eq!(b.read(alg::SHA512, 0).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn static_registers_start_at_zero_and_drtm_at_ones() {
        let b = banks();
        assert!(b.read(alg::SHA256, 0).unwrap().iter().all(|v| *v == 0));
        assert!(b.read(alg::SHA256, 16).unwrap().iter().all(|v| *v == 0));
        assert!(b.read(alg::SHA256, 23).unwrap().iter().all(|v| *v == 0));
        for i in 17..=22 {
            assert!(
                b.read(alg::SHA256, i).unwrap().iter().all(|v| *v == 0xff),
                "PCR {i}"
            );
        }
    }

    #[test]
    fn extend_matches_the_definition() {
        let mut b = banks();
        let digest = vec![0xaau8; 32];
        b.extend(0, 0, &[(alg::SHA256, digest.clone())]).unwrap();
        let expected = hash::digest_parts(alg::SHA256, &[&[0u8; 32], &digest]).unwrap();
        assert_eq!(b.read(alg::SHA256, 0).unwrap(), &expected[..]);
        // The bank that was not named is untouched.
        assert!(b.read(alg::SHA384, 0).unwrap().iter().all(|v| *v == 0));
    }

    #[test]
    fn extend_advances_the_update_counter() {
        let mut b = banks();
        assert_eq!(b.update_counter(), 0);
        b.extend(0, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap();
        assert_eq!(b.update_counter(), 1);
        // PCR 16 does not advance the counter.
        b.extend(16, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap();
        assert_eq!(b.update_counter(), 1);
    }

    #[test]
    fn an_extend_counts_once_for_each_bank_it_changes() {
        // Part 3 clause 22.1: "If a command causes PCR in multiple banks to
        // change, the PCR Update Counter must be incremented once for each
        // bank." A reset is the other way round, and is counted once.
        let mut b = banks();
        assert_eq!(b.update_counter(), 0);
        b.extend(
            0,
            0,
            &[(alg::SHA256, vec![1u8; 32]), (alg::SHA384, vec![1u8; 48])],
        )
        .unwrap();
        assert_eq!(b.update_counter(), 2, "two banks changed, so two counts");

        // A bank that is not allocated changes nothing and counts nothing.
        b.extend(
            0,
            0,
            &[(alg::SHA256, vec![2u8; 32]), (alg::SHA512, vec![2u8; 64])],
        )
        .unwrap();
        assert_eq!(b.update_counter(), 3, "only the allocated bank counted");

        // Naming one bank twice changes it twice but is still one bank, so
        // the counter moves once. Nothing stops a caller sending that list.
        let before = b.update_counter();
        b.extend(
            0,
            0,
            &[(alg::SHA256, vec![3u8; 32]), (alg::SHA256, vec![4u8; 32])],
        )
        .unwrap();
        assert_eq!(b.update_counter(), before + 1, "one bank, so one count");

        // Clearing the same register in every bank counts once. PCR 20 resets
        // from locality two and is not one of the registers that never count.
        let before = b.update_counter();
        b.reset(20, 2).unwrap();
        assert_eq!(b.update_counter(), before + 1, "a reset counts once");

        // PCR 23 resets but never counts, per TPM_PT_PCR_NO_INCREMENT.
        let before = b.update_counter();
        b.reset(23, 0).unwrap();
        assert_eq!(b.update_counter(), before);
    }

    #[test]
    fn extend_checks_the_locality() {
        let mut b = banks();
        // PCR 17 may only be extended from localities two through four.
        assert_eq!(
            b.extend(17, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap_err(),
            TpmRc(rc::LOCALITY)
        );
        assert_eq!(
            b.extend(17, 1, &[(alg::SHA256, vec![1u8; 32])]).unwrap_err(),
            TpmRc(rc::LOCALITY)
        );
        assert!(b.extend(17, 2, &[(alg::SHA256, vec![1u8; 32])]).is_ok());
        assert!(b.extend(17, 4, &[(alg::SHA256, vec![1u8; 32])]).is_ok());
        // An out of range locality is refused.
        assert_eq!(
            b.extend(0, 5, &[(alg::SHA256, vec![1u8; 32])]).unwrap_err(),
            TpmRc(rc::LOCALITY)
        );
    }

    #[test]
    fn extend_rejects_a_wrong_digest_length_without_changing_anything() {
        let mut b = banks();
        let before = b.read(alg::SHA256, 0).unwrap().to_vec();
        assert_eq!(
            b.extend(0, 0, &[(alg::SHA256, vec![1u8; 31])]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        assert_eq!(b.read(alg::SHA256, 0).unwrap(), &before[..]);
        assert_eq!(b.update_counter(), 0);
    }

    #[test]
    fn extend_ignores_a_bank_that_is_not_allocated() {
        let mut b = banks();
        b.extend(
            0,
            0,
            &[(alg::SHA384, vec![1u8; 48]), (alg::SHA256, vec![2u8; 32])],
        )
        .unwrap();
        let expected = hash::digest_parts(alg::SHA256, &[&[0u8; 32], &[2u8; 32]]).unwrap();
        assert_eq!(b.read(alg::SHA256, 0).unwrap(), &expected[..]);
    }

    #[test]
    fn reset_checks_the_locality_and_clears_to_zero() {
        let mut b = banks();
        b.extend(23, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap();
        assert!(b.read(alg::SHA256, 23).unwrap().iter().any(|v| *v != 0));
        b.reset(23, 0).unwrap();
        assert!(b.read(alg::SHA256, 23).unwrap().iter().all(|v| *v == 0));

        // PCR 0 cannot be reset from any locality.
        for loc in 0..=4 {
            assert_eq!(b.reset(0, loc).unwrap_err(), TpmRc(rc::LOCALITY));
        }
        // PCR 17 through 19 are reset by a D-RTM event, not by command, so
        // they refuse TPM2_PCR_Reset at every locality.
        for index in 17..=19u16 {
            for loc in 0..=4 {
                assert_eq!(
                    b.reset(index, loc).unwrap_err(),
                    TpmRc(rc::LOCALITY),
                    "PCR {index} locality {loc}"
                );
            }
        }
        // PCR 20 through 22 reset from localities two and three only.
        for index in 20..=22u16 {
            assert_eq!(b.reset(index, 1).unwrap_err(), TpmRc(rc::LOCALITY));
            assert_eq!(b.reset(index, 4).unwrap_err(), TpmRc(rc::LOCALITY));
        }
        b.reset(21, 2).unwrap();
        assert!(b.read(alg::SHA256, 21).unwrap().iter().all(|v| *v == 0));
        b.reset(22, 3).unwrap();
        // The debug and application registers do not reset from locality four.
        assert_eq!(b.reset(16, 4).unwrap_err(), TpmRc(rc::LOCALITY));
        b.reset(16, 3).unwrap();
    }

    #[test]
    fn the_locality_matrix_follows_the_pc_client_profile() {
        // Extend localities, PC Client Platform Profile clause 4.7.1 Table 14.
        assert_eq!(attributes(0).extend_locality, 0b0001_1111);
        assert_eq!(attributes(16).extend_locality, 0b0001_1111);
        assert_eq!(attributes(17).extend_locality, 0b0001_1100);
        assert_eq!(attributes(18).extend_locality, 0b0001_1100);
        assert_eq!(attributes(19).extend_locality, 0b0000_1100);
        assert_eq!(attributes(20).extend_locality, 0b0000_1110);
        assert_eq!(attributes(21).extend_locality, 0b0000_0100);
        assert_eq!(attributes(22).extend_locality, 0b0000_0100);
        assert_eq!(attributes(23).extend_locality, 0b0001_1111);

        // Command reset localities. The debug and application registers reset
        // from localities zero through three, not four.
        assert_eq!(attributes(0).reset_locality, 0);
        assert_eq!(attributes(16).reset_locality, 0b0000_1111);
        for index in 17..=19u16 {
            assert_eq!(attributes(index).reset_locality, 0, "PCR {index}");
        }
        assert_eq!(attributes(20).reset_locality, 0b0000_1100);
        assert_eq!(attributes(21).reset_locality, 0b0000_1100);
        assert_eq!(attributes(23).reset_locality, 0b0000_1111);

        // The reported reset capability also covers the D-RTM event, which
        // resets PCR 17 through 22 at locality four.
        assert_eq!(reset_capability_locality(0), 0);
        assert_eq!(reset_capability_locality(16), 0b0000_1111);
        assert_eq!(reset_capability_locality(17), 0b0001_0000);
        assert_eq!(reset_capability_locality(21), 0b0001_1100);

        // The registers a D-RTM resets start as all ones.
        for index in 0..=16u16 {
            assert!(!attributes(index).starts_at_ones, "PCR {index}");
        }
        for index in 17..=22u16 {
            assert!(attributes(index).starts_at_ones, "PCR {index}");
        }
        assert!(!attributes(23).starts_at_ones);

        // The debug, TCB and application registers do not advance the counter.
        for index in [16u16, 21, 22, 23] {
            assert!(no_increment(index), "PCR {index}");
        }
        for index in 0..=15u16 {
            assert!(!no_increment(index), "PCR {index}");
        }

        // Only the static root of trust registers are saved.
        for index in 0..=15u16 {
            assert!(is_saved(index), "PCR {index}");
        }
        for index in 16..=23u16 {
            assert!(!is_saved(index), "PCR {index}");
        }
    }

    #[test]
    fn event_extends_every_bank_with_its_own_digest() {
        let mut b = banks();
        let digests = b.event(0, 0, b"event data").unwrap();
        assert_eq!(digests.len(), 2);
        for (alg_id, d) in &digests {
            assert_eq!(d, &hash::digest(*alg_id, b"event data").unwrap());
            let expected =
                hash::digest_parts(*alg_id, &[&vec![0u8; d.len()], d]).unwrap();
            assert_eq!(b.read(*alg_id, 0).unwrap(), &expected[..]);
        }
    }

    #[test]
    fn selection_digest_concatenates_in_order() {
        let mut b = banks();
        b.extend(0, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap();
        b.extend(1, 0, &[(alg::SHA256, vec![2u8; 32])]).unwrap();

        let mut sel = PcrSelect::none();
        sel.select(0);
        sel.select(1);
        let list = TpmlPcrSelection::new(vec![PcrSelection::new(alg::SHA256, sel)]).unwrap();

        let expected = hash::digest_parts(
            alg::SHA256,
            &[b.read(alg::SHA256, 0).unwrap(), b.read(alg::SHA256, 1).unwrap()],
        )
        .unwrap();
        assert_eq!(b.selection_digest(alg::SHA256, &list).unwrap(), expected);
    }

    #[test]
    fn an_empty_selection_digests_the_empty_string() {
        let b = banks();
        let list = TpmlPcrSelection::empty();
        assert_eq!(
            b.selection_digest(alg::SHA256, &list).unwrap(),
            hash::digest(alg::SHA256, b"").unwrap()
        );
    }

    #[test]
    fn filtering_drops_absent_banks_and_registers() {
        let b = banks();
        let mut sel = PcrSelect::none();
        sel.select(0);
        sel.select(23);
        // SHA-512 is implemented but not allocated, so its half of the
        // selection is dropped while SHA-256 keeps both registers.
        let list = TpmlPcrSelection::new(vec![
            PcrSelection::new(alg::SHA256, sel.clone()),
            PcrSelection::new(alg::SHA512, sel),
        ])
        .unwrap();
        let filtered = b.filter_selection(&list);
        assert_eq!(filtered.items[0].select.selected(), vec![0, 23]);
        assert!(filtered.items[1].select.is_empty_selection());
        assert_eq!(b.read_selection(&filtered).len(), 2);
    }

    #[test]
    fn reallocation_resets_every_register() {
        let mut b = banks();
        b.extend(0, 0, &[(alg::SHA256, vec![1u8; 32])]).unwrap();
        b.allocate(&[alg::SHA256, alg::SHA512]).unwrap();
        assert_eq!(b.algorithms(), vec![alg::SHA256, alg::SHA512]);
        assert!(b.read(alg::SHA256, 0).unwrap().iter().all(|v| *v == 0));
        assert!(!b.has_bank(alg::SHA384));
        assert_eq!(
            b.allocate(&[alg::RSA]).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }
}
