//! Flags of address ranges that have no bytes in ID1.
//!
//! Since IDA 9.1 the sixth section of an inline IDB (`IDAS`) stores the flags
//! of ranges without file data (`.bss`, `extern`, alignment padding) as sparse
//! records instead of 4 bytes per address in ID1. Layout, all numbers in IDA's
//! packed encoding (`dd` = `unpack_dd`, `dq` = `unpack_dq`):
//!
//! ```text
//! "IDAS" u32(0x5555A51D) dd(version = 0)
//! dd(n) n * (dq(start delta), dq(size))   ranges stored here instead of ID1
//! dd(m) m * (dq(start delta), dq(size))   sub-ranges whose bytes have a value (0)
//! records: dq(address delta) dd(flags) dq(item size), until the address is BADADDR
//! ```
//!
//! Range starts are deltas from the end of the previous range; record
//! addresses are deltas from the previous record. A record sets the flags of
//! its address; the following `item size - 1` bytes are tails unless a later
//! record names them.

use std::ops::Range;

use anyhow::{ensure, Result};

use super::flag::byte::FF_IVL;
use super::flag::flags::byte_type::FF_TAIL;
use crate::ida_reader::IdbRead;

const MAGIC: &[u8; 8] = b"IDAS\x1d\xa5\x55\x55";

#[derive(Clone, Debug, Default)]
pub struct SparseFlags {
    ranges: Vec<Range<u64>>,
    valued: Vec<Range<u64>>,
    /// (address, flags, item size), sorted by address
    records: Vec<(u64, u32, u64)>,
}

impl SparseFlags {
    pub(crate) fn read(mut input: &[u8]) -> Result<Self> {
        ensure!(
            input.len() >= 8 && &input[..8] == MAGIC,
            "Invalid IDAS magic"
        );
        input = &input[8..];
        let version = input.unpack_dd()?;
        ensure!(version == 0, "Unknown IDAS version {version}");
        let ranges = read_ranges(&mut input)?;
        let valued = read_ranges(&mut input)?;
        let mut records = Vec::new();
        let mut address = 0u64;
        loop {
            address = address.wrapping_add(input.unpack_dq()?);
            if address == u64::MAX {
                break;
            }
            let flags = input.unpack_dd()?;
            let size = input.unpack_dq()?;
            records.push((address, flags, size));
        }
        ensure!(
            input.is_empty(),
            "IDAS has {} bytes after the records",
            input.len()
        );
        records.sort_unstable_by_key(|r| r.0);
        Ok(Self {
            ranges,
            valued,
            records,
        })
    }

    /// Ranges whose flags are stored here instead of in ID1.
    pub fn ranges(&self) -> &[Range<u64>] {
        &self.ranges
    }

    /// Raw flags of `address`, or `None` outside [`Self::ranges`].
    pub fn flags(&self, address: u64) -> Option<u32> {
        self.ranges.iter().any(|r| r.contains(&address)).then(|| {
            let idx = self.records.partition_point(|r| r.0 <= address);
            let flags = match idx.checked_sub(1).map(|i| self.records[i]) {
                Some((at, flags, _)) if at == address => flags,
                _ => {
                    // explicit tail records have size 0; the nearest sized
                    // record is the only item that can cover `address`
                    let in_item = self.records[..idx]
                        .iter()
                        .rev()
                        .find(|r| r.2 > 0)
                        .is_some_and(|&(at, _, size)| {
                            address < at.saturating_add(size)
                        });
                    if in_item {
                        FF_TAIL
                    } else {
                        0
                    }
                }
            };
            if self.valued.iter().any(|r| r.contains(&address)) {
                flags | FF_IVL
            } else {
                flags
            }
        })
    }
}

fn read_ranges(input: &mut &[u8]) -> Result<Vec<Range<u64>>> {
    let count = input.unpack_dd()?;
    let mut end = 0u64;
    (0..count)
        .map(|_| {
            let start = end + input.unpack_dq()?;
            end = start + input.unpack_dq()?;
            Ok(start..end)
        })
        .collect()
}
