//! NV Index storage, Part 1 clause 31 and Part 3 clause 31.
//!
//! An Index has a public area that fixes its size, attributes and policy, an
//! authorization value, and the data itself. What a write does depends on the
//! TPM_NT in the attributes: an ordinary Index takes data, a counter
//! increments, a bit field ORs, an extend hashes, and the two PIN types hold a
//! pair of counters.

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::{hc, rc};
use crate::tpm::crypto::hash;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::{nt, NvAttributes};
use crate::tpm::structures::base::digest_size;
use crate::tpm::structures::nv::{NvPinCounterParameters, NvPublic};

use super::names;

/// One defined NV Index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvIndex {
    pub public: NvPublic,
    pub auth: Vec<u8>,
    /// The stored data. A counter, bit field or PIN Index keeps its value here
    /// in the same marshalled form a read returns.
    pub data: Vec<u8>,
    /// Mirrors TPMA_NV_READLOCKED in the public area.
    ///
    /// The lock bits live in the public area because they are part of the
    /// Index Name, so both views are kept in step by [`NvIndex::set_read_lock`]
    /// and [`NvIndex::set_write_lock`].
    pub read_locked: bool,
    /// Mirrors TPMA_NV_WRITELOCKED in the public area.
    pub write_locked: bool,
}

impl NvIndex {
    /// The Name of the Index.
    pub fn name(&self) -> TpmResult<Vec<u8>> {
        names::nv_name(&self.public)
    }

    /// The TPM_NT of the Index.
    pub fn index_type(&self) -> u8 {
        self.public.attributes.index_type()
    }

    /// True when the Index has been written at least once.
    pub fn written(&self) -> bool {
        self.public.attributes.has(NvAttributes::WRITTEN)
    }

    fn set_written(&mut self) {
        self.public.attributes = self.public.attributes.with(NvAttributes::WRITTEN);
    }

    /// Set or clear the read lock, keeping the public area in step.
    pub fn set_read_lock(&mut self, locked: bool) {
        self.read_locked = locked;
        self.public
            .attributes
            .set(NvAttributes::READLOCKED, locked);
    }

    /// Set or clear the write lock, keeping the public area in step.
    pub fn set_write_lock(&mut self, locked: bool) {
        self.write_locked = locked;
        self.public
            .attributes
            .set(NvAttributes::WRITELOCKED, locked);
    }

    /// The value of a counter Index.
    pub fn counter_value(&self) -> TpmResult<u64> {
        if self.data.len() != 8 {
            return Err(TpmRc(rc::NV_UNINITIALIZED));
        }
        Ok(u64::from_be_bytes(self.data[..8].try_into().unwrap()))
    }

    /// Write data at `offset`, which is what an ordinary Index does.
    pub fn write(&mut self, offset: u16, value: &[u8]) -> TpmResult<()> {
        let size = self.public.data_size as usize;
        let offset = offset as usize;
        let end = offset
            .checked_add(value.len())
            .ok_or(TpmRc(rc::NV_RANGE))?;
        if end > size {
            return Err(TpmRc(rc::NV_RANGE));
        }
        if self.public.attributes.has(NvAttributes::WRITEALL) && value.len() != size {
            return Err(TpmRc(rc::NV_RANGE));
        }
        if self.data.len() != size {
            self.data = vec![0u8; size];
        }
        self.data[offset..end].copy_from_slice(value);
        self.set_written();
        Ok(())
    }

    /// Read `size` octets at `offset`.
    pub fn read(&self, offset: u16, size: u16) -> TpmResult<Vec<u8>> {
        if !self.written() {
            return Err(TpmRc(rc::NV_UNINITIALIZED));
        }
        let offset = offset as usize;
        let size = size as usize;
        let end = offset.checked_add(size).ok_or(TpmRc(rc::NV_RANGE))?;
        if end > self.public.data_size as usize {
            return Err(TpmRc(rc::NV_RANGE));
        }
        if end > self.data.len() {
            return Err(TpmRc(rc::NV_UNINITIALIZED));
        }
        Ok(self.data[offset..end].to_vec())
    }

    /// Advance a counter Index by one.
    ///
    /// The first increment of an unwritten counter sets it to one.
    pub fn increment(&mut self) -> TpmResult<u64> {
        if self.index_type() != nt::COUNTER {
            return Err(TpmRc(rc::ATTRIBUTES));
        }
        let next = if self.written() {
            self.counter_value()?.wrapping_add(1)
        } else {
            1
        };
        self.data = next.to_be_bytes().to_vec();
        self.set_written();
        Ok(next)
    }

    /// OR `bits` into a bit field Index.
    pub fn set_bits(&mut self, bits: u64) -> TpmResult<u64> {
        if self.index_type() != nt::BITS {
            return Err(TpmRc(rc::ATTRIBUTES));
        }
        let current = if self.written() {
            self.counter_value()?
        } else {
            0
        };
        let next = current | bits;
        self.data = next.to_be_bytes().to_vec();
        self.set_written();
        Ok(next)
    }

    /// Extend an extend Index with `value`.
    pub fn extend(&mut self, value: &[u8]) -> TpmResult<Vec<u8>> {
        if self.index_type() != nt::EXTEND {
            return Err(TpmRc(rc::ATTRIBUTES));
        }
        let size = digest_size(self.public.name_alg).ok_or(TpmRc(rc::HASH))?;
        let current = if self.written() && self.data.len() == size {
            self.data.clone()
        } else {
            vec![0u8; size]
        };
        let next = hash::digest_parts(self.public.name_alg, &[&current, value])?;
        self.data = next.clone();
        self.set_written();
        Ok(next)
    }

    /// The counters of a PIN Index.
    pub fn pin_counters(&self) -> TpmResult<NvPinCounterParameters> {
        if !matches!(self.index_type(), nt::PIN_FAIL | nt::PIN_PASS) {
            return Err(TpmRc(rc::ATTRIBUTES));
        }
        if !self.written() {
            return Ok(NvPinCounterParameters::default());
        }
        NvPinCounterParameters::from_bytes(&self.data).map_err(|_| TpmRc(rc::NV_UNINITIALIZED))
    }

    /// Replace the counters of a PIN Index.
    pub fn set_pin_counters(&mut self, p: NvPinCounterParameters) -> TpmResult<()> {
        if !matches!(self.index_type(), nt::PIN_FAIL | nt::PIN_PASS) {
            return Err(TpmRc(rc::ATTRIBUTES));
        }
        self.data = p.to_bytes();
        self.set_written();
        Ok(())
    }

    /// Number of octets of NV storage the Index occupies.
    pub fn footprint(&self) -> usize {
        // The public area, the authorization value and the data.
        self.public.to_bytes().len() + self.auth.len() + self.public.data_size as usize
    }
}

/// Every defined NV Index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NvStore {
    indices: BTreeMap<u32, NvIndex>,
}

impl NvStore {
    pub fn new() -> NvStore {
        NvStore::default()
    }

    /// Number of defined Indices.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Octets of NV storage in use.
    pub fn used(&self) -> usize {
        self.indices.values().map(|i| i.footprint()).sum()
    }

    /// Octets of NV storage still free.
    pub fn available(&self) -> usize {
        config::NV_MEMORY_SIZE.saturating_sub(self.used())
    }

    /// Number of counter Indices defined.
    pub fn counter_count(&self) -> usize {
        self.indices
            .values()
            .filter(|i| i.index_type() == nt::COUNTER)
            .count()
    }

    /// Define a new Index.
    pub fn define(&mut self, index: NvIndex) -> TpmResult<()> {
        let handle = index.public.nv_index;
        if !Self::is_nv_handle(handle) {
            return Err(TpmRc(rc::HANDLE));
        }
        if self.indices.contains_key(&handle) {
            return Err(TpmRc(rc::NV_DEFINED));
        }
        if index.footprint() > self.available() {
            return Err(TpmRc(rc::NV_SPACE));
        }
        self.indices.insert(handle, index);
        Ok(())
    }

    /// Remove an Index.
    pub fn undefine(&mut self, handle: u32) -> TpmResult<NvIndex> {
        self.indices.remove(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    pub fn get(&self, handle: u32) -> TpmResult<&NvIndex> {
        self.indices.get(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    pub fn get_mut(&mut self, handle: u32) -> TpmResult<&mut NvIndex> {
        self.indices.get_mut(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    /// True when an Index is defined at `handle`.
    pub fn contains(&self, handle: u32) -> bool {
        self.indices.contains_key(&handle)
    }

    /// Every defined handle, in increasing order.
    pub fn handles(&self) -> Vec<u32> {
        self.indices.keys().copied().collect()
    }

    /// Every defined Index, in handle order.
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &NvIndex)> {
        self.indices.iter()
    }

    /// Write lock every Index that has TPMA_NV_GLOBALLOCK.
    pub fn global_write_lock(&mut self) {
        for index in self.indices.values_mut() {
            if index.public.attributes.has(NvAttributes::GLOBALLOCK) {
                index.set_write_lock(true);
            }
        }
    }

    /// Apply a Startup(CLEAR) to the volatile lock state.
    ///
    /// A read lock is cleared when the Index has TPMA_NV_CLEAR_STCLEAR and a
    /// write lock when it has TPMA_NV_WRITE_STCLEAR. An Index locked by
    /// TPMA_NV_WRITEDEFINE stays locked.
    /// Apply a Startup(CLEAR) to the volatile lock state.
    ///
    /// Part 1 clause 13.6 fixes the rules: a read lock is dropped when the
    /// Index has TPMA_NV_READ_STCLEAR, and a write lock when it has
    /// TPMA_NV_WRITE_STCLEAR, except that an Index with TPMA_NV_WRITEDEFINE
    /// that has been written stays locked for good. `disorderly` says whether
    /// the last shutdown failed to save the state, which is when an orderly
    /// counter has to jump forward to stay monotonic.
    pub fn on_startup_clear_with(&mut self, disorderly: bool) {
        for index in self.indices.values_mut() {
            if index.public.attributes.has(NvAttributes::READ_STCLEAR) {
                index.set_read_lock(false);
            }
            if index.public.attributes.has(NvAttributes::WRITE_STCLEAR) {
                let permanent = index.public.attributes.has(NvAttributes::WRITEDEFINE)
                    && index.written();
                if !permanent {
                    index.set_write_lock(false);
                }
            }
            // An orderly Index that is not a counter loses its data, because
            // the value was only ever held in RAM.
            if index.public.attributes.has(NvAttributes::ORDERLY)
                && index.index_type() != nt::COUNTER
                && disorderly
            {
                index.data.clear();
                index.public.attributes =
                    index.public.attributes.without(NvAttributes::WRITTEN);
            }
            // An orderly counter may have advanced past its last saved value,
            // so after a disorderly shutdown it steps forward to stay
            // monotonic.
            if disorderly
                && index.public.attributes.has(NvAttributes::ORDERLY)
                && index.index_type() == nt::COUNTER
                && index.written()
            {
                if let Ok(v) = index.counter_value() {
                    index.data = v.saturating_add(1).to_be_bytes().to_vec();
                }
            }
        }
    }

    /// Apply a Startup(CLEAR) that followed an orderly shutdown.
    pub fn on_startup_clear(&mut self) {
        self.on_startup_clear_with(false);
    }

    /// Remove every Index that the platform did not create.
    ///
    /// TPM2_Clear removes the Indices of the storage hierarchy but leaves those
    /// created with platform authorization.
    pub fn clear_owner_indices(&mut self) {
        self.indices
            .retain(|_, i| i.public.attributes.has(NvAttributes::PLATFORMCREATE));
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        self.indices.clear();
    }

    /// True when `handle` is in the NV Index range.
    pub fn is_nv_handle(handle: u32) -> bool {
        (hc::NV_INDEX_FIRST..=hc::NV_INDEX_LAST).contains(&handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;
    use crate::tpm::structures::base::Tpm2bDigest;

    fn index(index_type: u8, size: u16, attributes: u32) -> NvIndex {
        NvIndex {
            public: NvPublic {
                nv_index: hc::NV_INDEX_FIRST + 1,
                name_alg: alg::SHA256,
                attributes: NvAttributes(attributes).with_index_type(index_type),
                auth_policy: Tpm2bDigest::empty(),
                data_size: size,
            },
            auth: b"pin".to_vec(),
            data: Vec::new(),
            read_locked: false,
            write_locked: false,
        }
    }

    #[test]
    fn an_ordinary_index_stores_data_at_an_offset() {
        let mut i = index(nt::ORDINARY, 16, NvAttributes::AUTHWRITE);
        assert!(!i.written());
        assert_eq!(i.read(0, 4).unwrap_err(), TpmRc(rc::NV_UNINITIALIZED));

        i.write(4, b"abcd").unwrap();
        assert!(i.written());
        assert_eq!(i.read(4, 4).unwrap(), b"abcd");
        assert_eq!(i.read(0, 4).unwrap(), vec![0u8; 4]);
        assert_eq!(i.read(0, 16).unwrap().len(), 16);
    }

    #[test]
    fn writes_and_reads_are_bounded_by_the_index_size() {
        let mut i = index(nt::ORDINARY, 16, 0);
        assert_eq!(i.write(13, b"abcd").unwrap_err(), TpmRc(rc::NV_RANGE));
        assert_eq!(i.write(0, &[0u8; 17]).unwrap_err(), TpmRc(rc::NV_RANGE));
        i.write(0, &[0u8; 16]).unwrap();
        assert_eq!(i.read(13, 4).unwrap_err(), TpmRc(rc::NV_RANGE));
        assert_eq!(i.read(u16::MAX, 4).unwrap_err(), TpmRc(rc::NV_RANGE));
    }

    #[test]
    fn write_all_requires_the_whole_index() {
        let mut i = index(nt::ORDINARY, 16, NvAttributes::WRITEALL);
        assert_eq!(i.write(0, b"abcd").unwrap_err(), TpmRc(rc::NV_RANGE));
        assert!(i.write(0, &[1u8; 16]).is_ok());
    }

    #[test]
    fn a_counter_starts_at_one_and_advances() {
        let mut i = index(nt::COUNTER, 8, 0);
        assert_eq!(i.increment().unwrap(), 1);
        assert_eq!(i.increment().unwrap(), 2);
        assert_eq!(i.counter_value().unwrap(), 2);
        assert_eq!(i.read(0, 8).unwrap(), 2u64.to_be_bytes());
        // The wrong type is refused.
        let mut o = index(nt::ORDINARY, 8, 0);
        assert_eq!(o.increment().unwrap_err(), TpmRc(rc::ATTRIBUTES));
    }

    #[test]
    fn a_bit_field_only_ever_sets_bits() {
        let mut i = index(nt::BITS, 8, 0);
        assert_eq!(i.set_bits(0b0101).unwrap(), 0b0101);
        assert_eq!(i.set_bits(0b0010).unwrap(), 0b0111);
        // Setting a bit that is already set changes nothing.
        assert_eq!(i.set_bits(0b0001).unwrap(), 0b0111);
        let mut o = index(nt::ORDINARY, 8, 0);
        assert_eq!(o.set_bits(1).unwrap_err(), TpmRc(rc::ATTRIBUTES));
    }

    #[test]
    fn an_extend_index_hashes_its_current_value() {
        let mut i = index(nt::EXTEND, 32, 0);
        let first = i.extend(b"one").unwrap();
        assert_eq!(
            first,
            hash::digest_parts(alg::SHA256, &[&[0u8; 32], b"one"]).unwrap()
        );
        let second = i.extend(b"two").unwrap();
        assert_eq!(
            second,
            hash::digest_parts(alg::SHA256, &[&first, b"two"]).unwrap()
        );
        assert_eq!(i.read(0, 32).unwrap(), second);
    }

    #[test]
    fn pin_indices_hold_a_pair_of_counters() {
        let mut i = index(nt::PIN_PASS, 8, 0);
        assert_eq!(i.pin_counters().unwrap(), NvPinCounterParameters::default());
        i.set_pin_counters(NvPinCounterParameters {
            pin_count: 2,
            pin_limit: 5,
        })
        .unwrap();
        let p = i.pin_counters().unwrap();
        assert_eq!(p.pin_count, 2);
        assert_eq!(p.pin_limit, 5);
        let o = index(nt::ORDINARY, 8, 0);
        assert_eq!(o.pin_counters().unwrap_err(), TpmRc(rc::ATTRIBUTES));
    }

    #[test]
    fn the_name_changes_when_the_written_bit_is_set() {
        let mut i = index(nt::ORDINARY, 8, 0);
        let before = i.name().unwrap();
        i.write(0, b"x").unwrap();
        assert_ne!(i.name().unwrap(), before);
    }

    #[test]
    fn the_store_defines_and_removes_indices() {
        let mut store = NvStore::new();
        let i = index(nt::ORDINARY, 16, 0);
        let handle = i.public.nv_index;
        store.define(i.clone()).unwrap();
        assert!(store.contains(handle));
        assert_eq!(store.len(), 1);
        assert_eq!(store.handles(), vec![handle]);
        // Defining the same handle twice is refused.
        assert_eq!(store.define(i).unwrap_err(), TpmRc(rc::NV_DEFINED));
        store.undefine(handle).unwrap();
        assert!(!store.contains(handle));
        assert_eq!(store.undefine(handle).unwrap_err(), TpmRc(rc::HANDLE));
    }

    #[test]
    fn only_nv_range_handles_are_accepted() {
        let mut store = NvStore::new();
        let mut i = index(nt::ORDINARY, 8, 0);
        i.public.nv_index = hc::PERSISTENT_FIRST;
        assert_eq!(store.define(i).unwrap_err(), TpmRc(rc::HANDLE));
        assert!(NvStore::is_nv_handle(hc::NV_INDEX_FIRST));
        assert!(NvStore::is_nv_handle(hc::NV_INDEX_LAST));
        assert!(!NvStore::is_nv_handle(hc::NV_INDEX_LAST + 1));
    }

    #[test]
    fn storage_is_bounded() {
        let mut store = NvStore::new();
        let mut handle = hc::NV_INDEX_FIRST;
        let mut defined = 0;
        loop {
            let mut i = index(nt::ORDINARY, config::MAX_NV_INDEX_SIZE as u16, 0);
            i.public.nv_index = handle;
            match store.define(i) {
                Ok(()) => defined += 1,
                Err(e) => {
                    assert_eq!(e, TpmRc(rc::NV_SPACE));
                    break;
                }
            }
            handle += 1;
            assert!(defined < 1000, "storage never filled");
        }
        assert!(defined > 0);
        assert!(store.used() <= config::NV_MEMORY_SIZE);
    }

    #[test]
    fn global_write_lock_only_touches_marked_indices() {
        let mut store = NvStore::new();
        let mut marked = index(nt::ORDINARY, 8, NvAttributes::GLOBALLOCK);
        marked.public.nv_index = hc::NV_INDEX_FIRST;
        let mut plain = index(nt::ORDINARY, 8, 0);
        plain.public.nv_index = hc::NV_INDEX_FIRST + 1;
        store.define(marked).unwrap();
        store.define(plain).unwrap();

        store.global_write_lock();
        assert!(store.get(hc::NV_INDEX_FIRST).unwrap().write_locked);
        assert!(!store.get(hc::NV_INDEX_FIRST + 1).unwrap().write_locked);
    }

    #[test]
    fn startup_clear_releases_the_locks_that_are_marked() {
        let mut store = NvStore::new();
        // A read lock is dropped when the Index has READ_STCLEAR and a write
        // lock when it has WRITE_STCLEAR.
        let mut a = index(
            nt::ORDINARY,
            8,
            NvAttributes::READ_STCLEAR | NvAttributes::WRITE_STCLEAR,
        );
        a.public.nv_index = hc::NV_INDEX_FIRST;
        a.set_read_lock(true);
        a.set_write_lock(true);
        // An Index with WRITEDEFINE that has been written stays locked.
        let mut b = index(
            nt::ORDINARY,
            8,
            NvAttributes::WRITEDEFINE | NvAttributes::WRITE_STCLEAR,
        );
        b.public.nv_index = hc::NV_INDEX_FIRST + 1;
        b.write(0, &[1u8; 8]).unwrap();
        b.set_write_lock(true);
        store.define(a).unwrap();
        store.define(b).unwrap();

        store.on_startup_clear();
        assert!(!store.get(hc::NV_INDEX_FIRST).unwrap().read_locked);
        assert!(!store.get(hc::NV_INDEX_FIRST).unwrap().write_locked);
        assert!(store.get(hc::NV_INDEX_FIRST + 1).unwrap().write_locked);
    }

    #[test]
    fn a_lock_shows_up_in_the_public_area_and_changes_the_name() {
        // The lock bits are part of the Index Name, so a lock must be visible
        // in the public area, not only in a side flag.
        let mut i = index(nt::ORDINARY, 8, NvAttributes::READ_STCLEAR);
        let before = i.name().unwrap();
        i.set_read_lock(true);
        assert!(i.public.attributes.has(NvAttributes::READLOCKED));
        assert!(i.read_locked);
        assert_ne!(i.name().unwrap(), before);
        i.set_read_lock(false);
        assert!(!i.public.attributes.has(NvAttributes::READLOCKED));
        assert_eq!(i.name().unwrap(), before);

        i.set_write_lock(true);
        assert!(i.public.attributes.has(NvAttributes::WRITELOCKED));
        assert!(i.write_locked);
    }

    #[test]
    fn an_orderly_counter_only_steps_after_a_disorderly_shutdown() {
        let mut store = NvStore::new();
        let mut c = index(nt::COUNTER, 8, NvAttributes::ORDERLY);
        c.public.nv_index = hc::NV_INDEX_FIRST;
        store.define(c).unwrap();
        store.get_mut(hc::NV_INDEX_FIRST).unwrap().increment().unwrap();

        // An orderly shutdown saved the value, so it stays where it was.
        store.on_startup_clear();
        assert_eq!(
            store.get(hc::NV_INDEX_FIRST).unwrap().counter_value().unwrap(),
            1
        );
        // A disorderly one may have lost an increment, so the counter jumps to
        // stay monotonic.
        store.on_startup_clear_with(true);
        assert_eq!(
            store.get(hc::NV_INDEX_FIRST).unwrap().counter_value().unwrap(),
            2
        );
    }

    #[test]
    fn orderly_data_is_lost_after_a_disorderly_shutdown() {
        let mut store = NvStore::new();
        let mut i = index(nt::ORDINARY, 8, NvAttributes::ORDERLY);
        i.public.nv_index = hc::NV_INDEX_FIRST;
        store.define(i).unwrap();
        store
            .get_mut(hc::NV_INDEX_FIRST)
            .unwrap()
            .write(0, &[7u8; 8])
            .unwrap();

        store.on_startup_clear();
        assert!(store.get(hc::NV_INDEX_FIRST).unwrap().written());

        store.on_startup_clear_with(true);
        assert!(!store.get(hc::NV_INDEX_FIRST).unwrap().written());
    }

    #[test]
    fn clear_keeps_platform_created_indices() {
        let mut store = NvStore::new();
        let mut owner = index(nt::ORDINARY, 8, 0);
        owner.public.nv_index = hc::NV_INDEX_FIRST;
        let mut platform = index(nt::ORDINARY, 8, NvAttributes::PLATFORMCREATE);
        platform.public.nv_index = hc::NV_INDEX_FIRST + 1;
        store.define(owner).unwrap();
        store.define(platform).unwrap();

        store.clear_owner_indices();
        assert!(!store.contains(hc::NV_INDEX_FIRST));
        assert!(store.contains(hc::NV_INDEX_FIRST + 1));
    }

    #[test]
    fn counters_are_counted() {
        let mut store = NvStore::new();
        let mut c = index(nt::COUNTER, 8, 0);
        c.public.nv_index = hc::NV_INDEX_FIRST;
        let mut o = index(nt::ORDINARY, 8, 0);
        o.public.nv_index = hc::NV_INDEX_FIRST + 1;
        store.define(c).unwrap();
        store.define(o).unwrap();
        assert_eq!(store.counter_count(), 1);
    }
}
