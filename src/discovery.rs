use crate::dump::MemoryDump;
use crate::v8_constants::*;
use rayon::prelude::*;

// Bounds for MetaMap location within cage
const MIN_METAMAP_OFFSET: u64 = 0x100;
const MAX_METAMAP_OFFSET: u64 = 0x2000000;

// MetaMap validation heuristics
const METAMAP_VERIFICATION_SAMPLE_SIZE: usize = 20;
const MIN_VERIFIED_MAPS: usize = 1;

// V8 cage base aligned to 4GB (kPtrComprCageBaseAlignment)
// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=182>
const CAGE_BASE_ALIGNMENT_MASK: u64 = 0xFFFFFFFF;  // Lower 32 bits must be zero for 4GB alignment

pub struct MetaMapInfo {
    pub address: u64,
    pub cage_base: u64,
    pub map_size: usize,
}

impl MemoryDump {
    /// Find MetaMap via self-reference pattern (parallelized).
    ///
    /// MetaMap is the root Map object in V8's type system - its own map pointer points to itself.
    /// This creates a self-referential compressed pointer we can search for to locate the V8 heap.
    ///
    /// Map structure: <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/map.tq;l=56-77>
    pub fn find_all_metamaps(&self) -> Vec<MetaMapInfo> {
        let candidates: Vec<MetaMapInfo> = self
            .regions()
            .par_iter()
            .flat_map(|region| self.find_metamap_candidates_in_region(region))
            .collect();

        let candidates_in_valid_range: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| {
                let offset_from_cage_base = candidate.address - candidate.cage_base;
                (MIN_METAMAP_OFFSET..=MAX_METAMAP_OFFSET).contains(&offset_from_cage_base)
            })
            .collect();

        let mut verified_metamaps = Vec::new();
        for candidate in candidates_in_valid_range {
            if self.verify_metamap(&candidate) {
                verified_metamaps.push(candidate);
            }
        }

        verified_metamaps
    }

    /// Verify MetaMap by checking if subsequent Map objects reference it
    ///
    /// All Map objects in V8 have their own map pointer pointing to MetaMap.
    /// We verify by sampling nearby Map-sized objects and checking if they reference our candidate.
    ///
    /// Compressed pointer calculation: <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=72-76>
    fn verify_metamap(&self, candidate: &MetaMapInfo) -> bool {
        let offset_from_cage_base = candidate.address - candidate.cage_base;
        let metamap_compressed = (offset_from_cage_base | HEAP_OBJECT_TAG) as u32;

        let mut verified_map_count = 0;
        let mut current_address = candidate.address + candidate.map_size as u64;

        for _ in 0..METAMAP_VERIFICATION_SAMPLE_SIZE {
            if let Some(map_pointer) = self.read_tagged(current_address) {
                let map_pointer_compressed = map_pointer as u32;
                if map_pointer_compressed == metamap_compressed {
                    verified_map_count += 1;
                }
            }
            current_address += candidate.map_size as u64;
        }

        verified_map_count >= MIN_VERIFIED_MAPS
    }

    /// Search a memory region for potential MetaMap locations
    ///
    /// MetaMap has a self-referential map pointer, so we look for Map-like structures
    /// where the first field (map pointer) points back to the same address when resolved.
    fn find_metamap_candidates_in_region(
        &self,
        region: &crate::dump::MemoryRegion,
    ) -> Vec<MetaMapInfo> {
        let mut candidates = Vec::new();
        let pointer_size = self.tagged_size;

        for offset in (0..region.data.len().saturating_sub(pointer_size)).step_by(pointer_size) {
            let address = region.base + offset as u64;

            let candidate = self.try_parse_metamap_at_offset(region, offset, address);
            if let Some(metamap_info) = candidate {
                candidates.push(metamap_info);
            }
        }

        candidates
    }

    /// Attempt to parse a MetaMap candidate at a specific memory offset
    fn try_parse_metamap_at_offset(
        &self,
        region: &crate::dump::MemoryRegion,
        offset: usize,
        address: u64,
    ) -> Option<MetaMapInfo> {
        // Read the first 4 bytes as a potential compressed map pointer
        let bytes: [u8; 4] = region.data[offset..offset + 4].try_into().ok()?;
        let compressed_map_pointer = u32::from_le_bytes(bytes) as u64;

        // Check if this looks like a heap object pointer (tagged with 0x1)
        // <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=72-76>
        if !is_heap_object(compressed_map_pointer) {
            return None;
        }

        // Remove the tag to get the offset from cage base
        let offset_from_cage_base = untag(compressed_map_pointer);

        // MetaMap should be within a reasonable offset from the cage base
        if !(MIN_METAMAP_OFFSET..=MAX_METAMAP_OFFSET).contains(&offset_from_cage_base) {
            return None;
        }

        // Calculate where the cage base would be if this is MetaMap
        let candidate_cage_base = address.wrapping_sub(offset_from_cage_base);

        // Cage base cannot be null
        if candidate_cage_base == 0 {
            return None;
        }

        // V8 cage base must be 4GB-aligned (lower 32 bits must be zero)
        // <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=182>
        if candidate_cage_base & CAGE_BASE_ALIGNMENT_MASK != 0 {
            return None;
        }

        Some(MetaMapInfo {
            address,
            cage_base: candidate_cage_base,
            map_size: map_size(self.tagged_size),
        })
    }
}
