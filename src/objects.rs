use crate::detection::array::{detect_anomalies, ArrayAnomaly};
use crate::discovery::MetaMapInfo;
use crate::dump::{MemoryDump, MemoryRegion};
use crate::v8_constants::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

// Minimum instance type occurrences to be considered valid (prevents noise from rare garbage patterns)
const MIN_TYPE_COUNT: u32 = 20;

// Frequency threshold: 1% of arrays (adaptive filtering based on heap size)
const FREQUENCY_DIVISOR: usize = 100;

// Maximum length value for array length field (prevents overflow)
const MAX_LENGTH_VALUE: u32 = 10_000_000;

// Minimum distance between array object and its elements backing store (prevents self-reference)
const MIN_ELEMENTS_DISTANCE: u64 = 32;

#[derive(Debug, Clone)]
pub struct V8Map {
    pub address: u64,
    pub instance_type: u16,
    pub bit_field2: u8,
    pub elements_kind: u8,
}

#[derive(Debug, Clone)]
pub struct JSArray {
    pub address: u64,
    pub map_address: u64,
    pub elements_kind: u8,
    pub elements_address: u64,
    pub elements_map_address: u64,
    pub array_length: u32,
    pub elements_length: u32,
    pub is_fake: bool,
}

impl JSArray {
    // V8 invariant: fast arrays have length <= elements.length()
    // https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/js-array.h;l=22
    fn follows_jsarray_invariant(&self) -> bool {
        self.array_length <= self.elements_length
    }

    fn has_elements_map(&self) -> bool {
        self.elements_map_address != 0
    }
}

pub struct V8Heap {
    pub cage_base: u64,
    pub meta_map: u64,
    pub maps: HashMap<u64, V8Map>,
    pub arrays: Vec<JSArray>,
    pub anomalies: Vec<(usize, ArrayAnomaly)>,
}

impl V8Heap {
    /// Analyzes backing store types to separate double arrays from object arrays.
    ///
    /// Returns sets of instance types for type confusion detection and a set of all
    /// valid backing store map addresses. Removes ambiguous types that appear in both
    /// categories to prevent false positives.
    fn analyze_backing_store_types(
        valid_arrays: &[JSArray],
        maps: &HashMap<u64, V8Map>,
    ) -> (HashSet<u16>, HashSet<u16>, HashSet<u64>) {
        let mut double_elements_map_types: HashMap<u16, u32> = HashMap::new();
        let mut object_elements_map_types: HashMap<u16, u32> = HashMap::new();

        let mut double_backing_store_maps: HashMap<u64, u32> = HashMap::new();
        let mut object_backing_store_maps: HashMap<u64, u32> = HashMap::new();

        let mut double_count = 0;
        let mut object_count = 0;

        for arr in valid_arrays {
            if !arr.follows_jsarray_invariant()
                || !arr.has_elements_map()
                || arr.elements_length == 0
            {
                continue;
            }

            let Some(elements_map) = maps.get(&arr.elements_map_address) else {
                continue;
            };

            if elements_kind::is_double(arr.elements_kind) {
                *double_elements_map_types.entry(elements_map.instance_type).or_insert(0) += 1;
                *double_backing_store_maps.entry(arr.elements_map_address).or_insert(0) += 1;
                double_count += 1;
            } else {
                *object_elements_map_types.entry(elements_map.instance_type).or_insert(0) += 1;
                *object_backing_store_maps.entry(arr.elements_map_address).or_insert(0) += 1;
                object_count += 1;
            }
        }

        let min_frequency = std::cmp::max(
            MIN_TYPE_COUNT,
            double_count.min(object_count) / FREQUENCY_DIVISOR as u32,
        );

        double_elements_map_types.retain(|_, &mut count| count >= min_frequency);
        object_elements_map_types.retain(|_, &mut count| count >= min_frequency);

        let ambiguous_types: HashSet<u16> = double_elements_map_types
            .keys()
            .filter(|&k| object_elements_map_types.contains_key(k))
            .copied()
            .collect();

        // Remove ambiguous instance types - they appear in both categories and can't be used for mismatch detection
        for ambiguous_type in &ambiguous_types {
            double_elements_map_types.remove(ambiguous_type);
            object_elements_map_types.remove(ambiguous_type);
        }

        let double_types: HashSet<u16> = double_elements_map_types.keys().copied().collect();
        let object_types: HashSet<u16> = object_elements_map_types.keys().copied().collect();

        let valid_backing_store_maps: HashSet<u64> = double_backing_store_maps
            .keys()
            .chain(object_backing_store_maps.keys())
            .copied()
            .collect();

        (double_types, object_types, valid_backing_store_maps)
    }

    /// Builds a set of valid JSArray instance types based on frequency analysis.
    ///
    /// Filters to instance types that appear frequently enough to be legitimate JSArrays,
    /// preventing false positives from garbage data that coincidentally matches JSArray structure.
    fn build_valid_instance_types(
        valid_arrays: &[JSArray],
        maps: &HashMap<u64, V8Map>,
    ) -> HashMap<u16, ()> {
        let mut instance_type_counts: HashMap<u16, u32> = HashMap::new();

        for arr in valid_arrays.iter().filter(|a| a.follows_jsarray_invariant()) {
            if let Some(map) = maps.get(&arr.map_address) {
                *instance_type_counts.entry(map.instance_type).or_insert(0) += 1;
            }
        }

        let min_frequency_threshold = std::cmp::max(
            MIN_TYPE_COUNT,
            (valid_arrays.len() / FREQUENCY_DIVISOR) as u32,
        );
        let mut valid_instance_types = HashMap::new();
        
        for (instance_type, count) in instance_type_counts {
            if count >= min_frequency_threshold {
                valid_instance_types.insert(instance_type, ());
            }
        }

        valid_instance_types
    }

    pub fn extract(dump: &MemoryDump, meta: &MetaMapInfo) -> Self {
        // Setup: Find all MetaMaps and extract compressed pointer values
        let map_offsets = MapOffsets::compressed();
        let all_metamaps = dump.find_all_metamaps();
        let metamap_compressed_values: Vec<u32> = all_metamaps
            .iter()
            .map(|m| ((m.address - m.cage_base) | HEAP_OBJECT_TAG) as u32)
            .collect();

        // Phase 1: Extract all V8 Maps from memory
        let maps = Self::extract_maps_parallel(
            dump,
            &map_offsets,
            &metamap_compressed_values,
        );

        // Phase 2: Extract high-confidence legitimate arrays (strict validation)
        let valid_arrays =
            Self::extract_arrays_parallel(dump, meta, &maps, &metamap_compressed_values, true);

        // Phase 3: Build frequency-filtered sets for anomaly detection
        // - Filter to frequent JSArray instance types to prevent false positives
        let valid_instance_types = Self::build_valid_instance_types(&valid_arrays, &maps);

        // - Separate double vs object backing stores for type confusion detection
        let (double_elements_map_types, object_elements_map_types, valid_backing_store_maps) =
            Self::analyze_backing_store_types(&valid_arrays, &maps);

        // Phase 4: Extract potential fake arrays (relaxed validation) and deduplicate
        let valid_array_addresses: HashSet<u64> = valid_arrays.iter().map(|a| a.address).collect();

        let all_fake_arrays =
            Self::extract_arrays_parallel(dump, meta, &maps, &metamap_compressed_values, false);

        // Exclude arrays already found in Phase 2 to prevent duplicate anomaly reports
        let fake_arrays: Vec<_> = all_fake_arrays
            .into_iter()
            .filter(|arr| !valid_array_addresses.contains(&arr.address))
            .collect();

        let mut arrays = [valid_arrays, fake_arrays].concat();
        
        let anomalies = detect_anomalies(
            &mut arrays,
            dump,
            meta,
            &maps,
            &valid_instance_types,
            &all_metamaps,
            &double_elements_map_types,
            &object_elements_map_types,
            &valid_backing_store_maps,
        );

        V8Heap {
            cage_base: meta.cage_base,
            meta_map: meta.address,
            maps,
            arrays,
            anomalies,
        }
    }

    fn extract_maps_parallel(
        dump: &MemoryDump,
        offsets: &MapOffsets,
        metamap_compressed_values: &[u32],
    ) -> HashMap<u64, V8Map> {
        dump.regions()
            .par_iter()
            .flat_map(|region| {
                Self::extract_maps_from_region(region, dump, offsets, metamap_compressed_values)
            })
            .collect()
    }

    fn extract_maps_from_region(
        region: &MemoryRegion,
        dump: &MemoryDump,
        offsets: &MapOffsets,
        metamap_compressed_values: &[u32],
    ) -> Vec<(u64, V8Map)> {
        let mut maps = Vec::new();
        let step = dump.tagged_size;

        for offset in (0..region.data.len().saturating_sub(step)).step_by(step) {
            let addr = region.base + offset as u64;
            let Ok(bytes) = region.data[offset..offset + 4].try_into() else {
                continue;
            };
            let map_ptr = u32::from_le_bytes(bytes) as u64;

            if !metamap_compressed_values.contains(&(map_ptr as u32)) {
                continue;
            }

            if let Some(bytes) = dump.read(addr + offsets.instance_type as u64, 2) {
                let instance_type = u16::from_le_bytes([bytes[0], bytes[1]]);

                if let Some(&bit_field2) = dump
                    .read(addr + offsets.bit_field2 as u64, 1)
                    .and_then(|b| b.first())
                {
                    let elements_kind = elements_kind::from_bit_field2(bit_field2);

                    maps.push((
                        addr,
                        V8Map {
                            address: addr,
                            instance_type,
                            bit_field2,
                            elements_kind,
                        },
                    ));
                }
            }
        }
        maps
    }

    fn extract_arrays_parallel(
        dump: &MemoryDump,
        meta: &MetaMapInfo,
        maps: &HashMap<u64, V8Map>,
        metamap_compressed_values: &[u32],
        strict_mode: bool,
    ) -> Vec<JSArray> {
        let elements_offset = 2 * dump.tagged_size;

        dump.regions()
            .par_iter()
            .flat_map(|region| {
                Self::extract_arrays_from_region(
                    region,
                    dump,
                    meta,
                    maps,
                    elements_offset,
                    metamap_compressed_values,
                    strict_mode,
                )
            })
            .collect()
    }

    fn extract_arrays_from_region(
        region: &MemoryRegion,
        dump: &MemoryDump,
        meta: &MetaMapInfo,
        maps: &HashMap<u64, V8Map>,
        elements_offset: usize,
        metamap_compressed_values: &[u32],
        strict_mode: bool,
    ) -> Vec<JSArray> {
        let mut arrays = Vec::new();
        let step = dump.tagged_size;

        for offset in (0..region
            .data
            .len()
            .saturating_sub(elements_offset + dump.tagged_size))
            .step_by(step)
        {
            let addr = region.base + offset as u64;
            let Ok(bytes) = region.data[offset..offset + 4].try_into() else {
                continue;
            };
            let map_ptr = u32::from_le_bytes(bytes) as u64;
            
            if !is_heap_object(map_ptr) {
                continue;
            }
            
            let map_addr = meta.cage_base + untag(map_ptr);
            let Some(map) = maps.get(&map_addr) else {
                continue;
            };
            
            if map.elements_kind > elements_kind::HOLEY_DOUBLE_ELEMENTS {
                continue;
            }
            
            let Some(elements_ptr) = dump.read_tagged(addr + elements_offset as u64) else {
                continue;
            };
            
            if !is_heap_object(elements_ptr) {
                continue;
            }
            
            let elements_addr = meta.cage_base + untag(elements_ptr);
            
            if elements_addr == addr || (strict_mode && elements_addr.abs_diff(addr) < MIN_ELEMENTS_DISTANCE) {
                continue;
            }
            
            let Some(elements_map_ptr) = dump.read_tagged(elements_addr) else {
                continue;
            };

            // Validate elements backing store map
            let (elements_map_addr, has_valid_elements_map) = if !is_heap_object(elements_map_ptr) {
                // In relaxed mode, allow arrays with invalid elements_map_ptr to pass through
                // They will be handled in mismatch detection where we can try to read the instance type directly
                if strict_mode {
                    continue;
                }
                // Set elements_map_addr to 0 to indicate it's invalid, mismatch detection will handle it
                (0, false)
            } else {
                let elements_map_addr = meta.cage_base + untag(elements_map_ptr);
                let has_valid_elements_map = maps.contains_key(&elements_map_addr)
                    || dump
                        .read_tagged(elements_map_addr)
                        .map(|ptr| metamap_compressed_values.contains(&(ptr as u32)))
                        .unwrap_or(false);
                (elements_map_addr, has_valid_elements_map)
            };

            if strict_mode && !has_valid_elements_map {
                continue;
            }

            let mut elements_length = 0;

            if has_valid_elements_map {
                if let Some(len_ptr) = dump.read_tagged(elements_addr + dump.tagged_size as u64) {
                    if is_smi(len_ptr) {
                        let length = smi_value(len_ptr, dump.tagged_size) as u32;
                        if length > 0 && length <= MAX_LENGTH_VALUE {
                            elements_length = length;
                        }
                    }
                }
            }

            let mut array_length = 0;
            
            if let Some(len_ptr) = dump.read_tagged(addr + (3 * dump.tagged_size) as u64) {
                if is_smi(len_ptr) {
                    let length = smi_value(len_ptr, dump.tagged_size) as u32;
                    
                    if length > 0 && length <= MAX_LENGTH_VALUE {
                        array_length = length;
                    }
                } else if elements_kind::is_double(map.elements_kind) && elements_length > 0 {
                    // For double arrays with valid elements, try treating non-SMI value as raw length.
                    // Exploit-corrupted length fields may not be SMI-encoded.
                    // Guard: elements_length > 0 prevents treating heap pointers as lengths
                    // when elements_map is invalid (which sets elements_length = 0).
                    let raw_length = (len_ptr & 0x7FFFFFFF) as u32;
                    
                    if raw_length > 0 && raw_length <= MAX_LENGTH_VALUE {
                        array_length = raw_length;
                    }
                }
            }

            let array = JSArray {
                address: addr,
                map_address: map_addr,
                elements_kind: map.elements_kind,
                elements_address: elements_addr,
                elements_map_address: if has_valid_elements_map { elements_map_addr } else { 0 },
                array_length,
                elements_length,
                is_fake: false,
            };

            arrays.push(array);
        }

        arrays
    }

    /// Find which array's elements backing store contains the given address
    pub fn find_containing_array(&self, addr: u64, dump: &MemoryDump) -> Option<&JSArray> {
        for arr in &self.arrays {
            if arr.is_fake {
                continue;
            }
            if arr.elements_address == 0 || arr.elements_length == 0 {
                continue;
            }
            if arr.array_length != arr.elements_length {
                continue;
            }

            let backing_store_size = crate::detection::array::calculate_backing_store_size(
                arr.elements_kind,
                arr.elements_length,
                dump.tagged_size,
            );
            let elements_end = arr.elements_address + backing_store_size;

            if addr >= arr.elements_address && addr < elements_end && addr != arr.elements_address {
                return Some(arr);
            }
        }
        None
    }
}
