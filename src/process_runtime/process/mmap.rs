extern crate alloc;
use core::ops::Range;
use core::cmp::Ordering;
use alloc::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
pub struct MmapInfo {
    pub fd: i32, // File descriptor
    pub offset: usize, // Offset in the file
    pub addr: usize, // Start of trustlet's virtual address of the mapping
    pub size: usize, // Size of the mapping
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeWrapper(Range<usize>);

impl PartialOrd for RangeWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other)) // Delegate to the Ord implementation
    }
}

impl Ord for RangeWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare ranges by their start first, then by their end
        // e.g., [1..3] < [2..4] < [2..5] < [3..4]
        self.0.start.cmp(&other.0.start).then(self.0.end.cmp(&other.0.end))
    }
}

#[derive(Debug, Clone)]
pub struct MmapManager {
    mappings: BTreeMap<RangeWrapper, MmapInfo>,
}

impl MmapManager {
    pub fn new() -> Self {
        MmapManager {
            mappings: BTreeMap::new(),
        }
    }

    pub fn add_mapping(&mut self, addr: usize, size: usize, fd: i32, offset: usize) {
        let range = addr..(addr + size);
        let info = MmapInfo { fd, offset, addr, size};
        self.mappings.insert(RangeWrapper(range), info);
    }

    pub fn lookup(&self, addr: usize) -> Option<&MmapInfo> {
        // Search for the range that contains the address
        for (range, info) in self.mappings.range(..=RangeWrapper(addr..usize::max_value())).rev() {
            if range.0.contains(&addr) {
                return Some(info);
            }
        }
        None
    }
}
