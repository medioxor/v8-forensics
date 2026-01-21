use crate::discovery::MetaMapInfo;
use crate::dump::MemoryDump;
use crate::objects::{JSArray, V8Map};
use crate::v8_constants::{is_heap_object, untag};
use std::collections::{HashMap, HashSet};

struct DetectionContext<'a> {
    dump: &'a MemoryDump,
    meta: &'a MetaMapInfo,
    maps: &'a HashMap<u64, V8Map>,
    all_metamaps: &'a [MetaMapInfo],
    valid_instance_types: &'a HashMap<u16, ()>,
    double_elements_map_types: &'a HashSet<u16>,
    object_elements_map_types: &'a HashSet<u16>,
    valid_backing_store_maps: &'a HashSet<u64>,
}

// V8 cage size: 4GB (kPtrComprCageReservationSize)
// https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=181
const V8_CAGE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

// Sanity bound: arrays with more elements than this are likely corrupt data, not real arrays.
// Prevents wasting time computing backing store sizes for garbage values.
const MAX_ELEMENTS_LENGTH: u32 = 1_000_000;

// Maximum offset from elements_start for embedded array detection.
// Fake arrays are placed at controlled offsets within backing stores (typically small).
// Large offsets indicate coincidental address overlap, not deliberate embedding.
const MAX_ELEMENTS_DISTANCE: u64 = 10_000_000;

pub(crate) fn calculate_backing_store_size(elements_kind: u8, elements_length: u32, tagged_size: usize) -> u64 {
    let header_size = 2 * tagged_size as u64;
    let element_size = if crate::v8_constants::elements_kind::is_double(elements_kind) { 8u64 } else { tagged_size as u64 };
    header_size + (elements_length as u64 * element_size)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayAnomaly {
    /// ElementsKind contradicts backing store instance type (type confusion or write32/read32/addrof indicator)
    ElementsMapMismatch,
    /// Array object embedded within another array's backing store (fake object technique)
    EmbeddedInElements,
    /// array_length > elements_length (OOB primitive indicator)
    /// V8 invariant: length <= elements.length() for fast arrays
    CorruptedLength,
}

pub fn detect_anomalies(
    arrays: &mut [JSArray],
    dump: &MemoryDump,
    meta: &MetaMapInfo,
    maps: &HashMap<u64, V8Map>,
    valid_instance_types: &HashMap<u16, ()>,
    all_metamaps: &[MetaMapInfo],
    double_elements_map_types: &HashSet<u16>,
    object_elements_map_types: &HashSet<u16>,
    valid_backing_store_maps: &HashSet<u64>,
) -> Vec<(usize, ArrayAnomaly)> {
    let mut anomalies = Vec::new();

    let ctx = DetectionContext {
        dump,
        meta,
        maps,
        all_metamaps,
        valid_instance_types,
        double_elements_map_types,
        object_elements_map_types,
        valid_backing_store_maps,
    };

    let elements_ranges: Vec<(u64, u64)> = arrays
        .iter()
        .filter_map(|arr| {
            if arr.elements_address == 0 || arr.elements_length == 0 {
                return None;
            }
            if arr.elements_length > MAX_ELEMENTS_LENGTH {
                return None;
            }
            if arr.array_length != arr.elements_length {
                return None;
            }

            let backing_store_size = calculate_backing_store_size(arr.elements_kind, arr.elements_length, dump.tagged_size);
            Some((arr.elements_address, arr.elements_address + backing_store_size))
        })
        .collect();

    let mut processed_addresses: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for (idx, arr) in arrays.iter_mut().enumerate() {
        if !processed_addresses.insert(arr.address) {
            continue;
        }

        if arr.address < meta.cage_base || arr.address >= meta.cage_base + V8_CAGE_SIZE {
            continue;
        }

        let has_oob = has_oob_length(arr, dump, meta, all_metamaps);

        // Flag double arrays with corrupted length (array_length > elements_length)
        //
        // Two legitimate scenarios for corrupted lengths:
        // 1. Fake array embedded in backing store (exploit technique)
        //    - Marking bit is CLEAR (inside another object's storage)
        //    - Detected via is_embedded check
        // 2. Real array with corrupted length field (exploit modified legitimate array)
        //    - Marking bit is SET (real allocated object)
        //    - Detected via marking bitmap (only checked when NOT embedded for performance)
        //
        // Filters out coincidental garbage patterns that have BOTH:
        // - Marking bit CLEAR (not a real object)
        // - NOT embedded (not a deliberate fake array)
        if has_oob && crate::v8_constants::elements_kind::is_double(arr.elements_kind) {
            // Validate this is a recognized JSArray type, not some other V8 object.
            let Some(array_map) = maps.get(&arr.map_address) else {
                continue;
            };
            if !valid_instance_types.contains_key(&array_map.instance_type) {
                continue;
            }

            let is_embedded = detect_embedded_in_elements(arr, &elements_ranges, dump, meta, maps, all_metamaps);

            // Validate with generation-appropriate check:
            // - Old gen: marking bit set (allocated by mark-compact)
            // - Young gen: page flags indicate FROM_PAGE or TO_PAGE (with valid elements)
            // - Embedded: inside another array's backing store (fake array technique)
            if is_embedded
                || is_marking_bit_set(arr.address, dump, meta)
                || (is_in_young_generation(arr.address, dump, meta) && arr.elements_map_address != 0)
            {
                anomalies.push((idx, ArrayAnomaly::CorruptedLength));
            }
        }

        let mismatch_result = detect_elements_map_mismatch(arr, &ctx);

        if mismatch_result {
            arr.is_fake = true;
            anomalies.push((idx, ArrayAnomaly::ElementsMapMismatch));
        }

        // Fake array = array embedded within another array's backing store
        if has_oob && detect_embedded_in_elements(arr, &elements_ranges, dump, meta, maps, all_metamaps) {
            arr.is_fake = true;
            anomalies.push((idx, ArrayAnomaly::EmbeddedInElements));
        }
    }
    
    anomalies
}

/// Checks if array violates the length invariant: array_length > elements_length.
///
/// V8 invariant (src/objects/js-array.h:22): For fast arrays, length <= elements.length().
/// This violation indicates either:
/// - A deliberately constructed fake array for OOB access
/// - Length field corruption via prior exploit primitive
///
/// Note: During major GC, V8 can temporarily violate this invariant while performing
/// concurrent right-trim operations on arrays (src/heap/heap-visitor-inl.h:357-359).
/// Arrays in GC-affected pages are excluded to prevent false positives.
fn has_oob_length(
    arr: &JSArray,
    dump: &MemoryDump,
    meta: &MetaMapInfo,
    all_metamaps: &[MetaMapInfo],
) -> bool {
    // Must have positive lengths with array_length > elements_length
    if arr.array_length == 0
        || arr.elements_length == 0
        || arr.array_length <= arr.elements_length
    {
        return false;
    }

    if is_major_gc_in_progress(arr.address, dump, meta) {
        return false;
    }

    // Verify the array's map is a valid V8 Map (points to MetaMap)
    if let Some(map_ptr) = dump.read_tagged(arr.map_address) {
        if is_heap_object(map_ptr) {
            let map_map_addr = meta.cage_base + untag(map_ptr);
            if !all_metamaps.iter().any(|m| m.address == map_map_addr) {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    let elements_map_addr = if arr.elements_map_address != 0 {
        arr.elements_map_address
    } else {
        let Some(elements_map_ptr) = dump.read_tagged(arr.elements_address) else {
            return false;
        };
        if !is_heap_object(elements_map_ptr) {
            return false;
        }
        meta.cage_base + untag(elements_map_ptr)
    };

    check_elements_map_points_to_metamap(elements_map_addr, dump, meta, all_metamaps)
}

fn check_elements_map_points_to_metamap(
    elements_map_addr: u64,
    dump: &MemoryDump,
    meta: &MetaMapInfo,
    all_metamaps: &[MetaMapInfo],
) -> bool {
    dump.read_tagged(elements_map_addr)
        .map(|compressed| {
            let decompressed = if dump.tagged_size == 4 {
                meta.cage_base + untag(compressed)
            } else {
                untag(compressed)
            };
            all_metamaps.iter().any(|m| decompressed == m.address)
        })
        .unwrap_or(false)
}

fn read_instance_type(addr: u64, dump: &MemoryDump) -> Option<u16> {
    let map_offsets = crate::v8_constants::MapOffsets::compressed();
    let inst_bytes = dump.read(addr + map_offsets.instance_type as u64, 2)?;
    Some(u16::from_le_bytes([inst_bytes[0], inst_bytes[1]]))
}

/// Detects type confusion by checking if the array's ElementsKind contradicts
/// the actual instance type of its backing store.
///
/// V8 invariant: ElementsKind in Map must match backing store type.
/// - PACKED_DOUBLE_ELEMENTS/HOLEY_DOUBLE_ELEMENTS → FixedDoubleArray
/// - PACKED_ELEMENTS/HOLEY_ELEMENTS → FixedArray
///
/// Type confusion exploits violate this: JIT sees double array but runtime has object array.
fn detect_elements_map_mismatch(arr: &JSArray, ctx: &DetectionContext) -> bool {
    if arr.elements_address == 0 {
        return false;
    }

    // We can detect mismatches even when elements_length == 0 because we read the instance type
    // from the elements map address, not from the elements backing store itself.
    // However, we still need elements_length > 0 to validate that the elements map is readable.
    // For corrupted arrays, elements_length might be 0, but we can still check the map instance type.
    // Only filter out if we can't read the elements map instance type (handled later).

    let Some(array_map) = ctx.maps.get(&arr.map_address) else {
        return false;
    };

    if !ctx.valid_instance_types.contains_key(&array_map.instance_type) {
        return false;
    }

    let (elements_map_addr, read_instance_type_directly) = if arr.elements_map_address != 0 {
        (arr.elements_map_address, false)
    } else {
        match ctx.dump.read_tagged(arr.elements_address) {
            Some(elements_map_ptr) if is_heap_object(elements_map_ptr) => {
                (ctx.meta.cage_base + untag(elements_map_ptr), false)
            }
            Some(_) | None => (0, true),
        }
    };

    let elements_map_instance_type = if read_instance_type_directly {
        read_instance_type(arr.elements_address, ctx.dump).unwrap_or(0)
    } else {
        if !check_elements_map_points_to_metamap(elements_map_addr, ctx.dump, ctx.meta, ctx.all_metamaps) {
            // Metamap check failed - the "map" at elements_address doesn't chain to MetaMap.
            // This could mean:
            // 1. Type confusion: elements points to real object of wrong type (TP)
            // 2. Garbage: elements points to garbage that happens to have heap tag (FP)
            //
            // Robust validation using frequency analysis: verify that elements_map_addr
            // is a real backing store by checking if its map is one of the known
            // FixedArray/FixedDoubleArray maps collected from valid arrays.
            //
            // For TP: elements_map_addr points to a real FixedArray → its map is a known backing store map
            // For FP: elements_map_addr points to garbage → its "map" is not a known backing store map

            let has_valid_backing_store_map = ctx.dump
                .read_tagged(elements_map_addr)
                .filter(|&ptr| is_heap_object(ptr))
                .map(|ptr| {
                    let obj_map_addr = ctx.meta.cage_base + untag(ptr);
                    // Check if obj_map_addr is one of the known FixedArray/FixedDoubleArray maps
                    ctx.valid_backing_store_maps.contains(&obj_map_addr)
                })
                .unwrap_or(false);

            // Only flag as mismatch if:
            // 1. It's a double array (type confusion target)
            // 2. elements_map_addr has a known backing store map (proving it's a real FixedArray/FixedDoubleArray)
            return has_valid_backing_store_map
                && crate::v8_constants::elements_kind::is_double(arr.elements_kind);
        }

        ctx.maps.get(&elements_map_addr)
            .map(|m| m.instance_type)
            .or_else(|| read_instance_type(elements_map_addr, ctx.dump))
            .unwrap_or(0)
    };

    // Instance type 0 means we failed to read the backing store's map.
    // For double arrays, this is suspicious: legitimate FixedDoubleArrays have readable maps.
    // Corrupted/fake backing stores often have invalid map pointers.
    if elements_map_instance_type == 0 && crate::v8_constants::elements_kind::is_double(arr.elements_kind) {
        return true;
    }

    let elements_is_for_double = ctx.double_elements_map_types.contains(&elements_map_instance_type);
    let elements_is_for_object = ctx.object_elements_map_types.contains(&elements_map_instance_type);

    // If instance type isn't recognized as either double or object backing store,
    // we can't determine mismatch. This avoids false positives on unusual but valid V8 states.
    if !elements_is_for_double && !elements_is_for_object {
        return false;
    }

    let array_expects_double = crate::v8_constants::elements_kind::is_double(arr.elements_kind);
    let mismatch = (array_expects_double && elements_is_for_object)
        || (!array_expects_double && elements_is_for_double);

    if !mismatch {
        return false;
    }

    // Special handling for arrays with array_length == 0:
    // - Object arrays (non-double) with length 0: V8 may use shared empty backing stores
    //   with different instance types. Not suspicious → skip.
    // - Double arrays with length 0 AND elements_length 0: No actual confusion possible → skip.
    // - Double arrays with length 0 BUT elements_length > 0: Suspicious! The backing store
    //   has capacity but array claims empty. Combined with type mismatch, this indicates exploit.
    if arr.array_length == 0
        && (!crate::v8_constants::elements_kind::is_double(arr.elements_kind) || arr.elements_length == 0)
    {
        return false;
    }

    true
}

/// Validates that an address is at a real V8 object boundary by checking
/// what follows the object. Valid objects are followed by either:
/// - Another valid object (map pointer must be in discovered Maps)
/// - FreeSpace filler (SMI size field with reasonable value)
/// - End of allocation (zeros)
///
/// This filters garbage data that coincidentally matches JSArray structure but
/// exists at non-object-boundary addresses (e.g., inside double element data
/// where upper 32 bits of consecutive doubles happen to look like valid pointers).
/// Checks if an address has its marking bitmap bit set, indicating it's a real
/// V8 allocated object according to the GC.
///
/// V8's GC uses a marking bitmap (1 bit per kTaggedSize bytes) in MutablePageMetadata
/// to track which addresses are valid object starts. This is the definitive source of
/// truth for distinguishing real objects from garbage data that coincidentally matches
/// object structure.
///
/// Returns true if the bit is set (real object), false if clear (garbage data) or
/// if the bitmap cannot be read.
/// Checks if an address is in V8's young generation by reading page flags.
///
/// Young generation uses semi-space copying (Scavenger), NOT mark-sweep, so
/// marking bitmaps are not set for young gen objects. We use page flags instead.
///
/// V8 source: memory-chunk.h:58-60
///   FROM_PAGE = 1 << 3  (in from-space before scavenge)
///   TO_PAGE = 1 << 4    (in to-space after scavenge)
fn is_in_young_generation(addr: u64, dump: &MemoryDump, meta: &MetaMapInfo) -> bool {
    const PAGE_SIZE: u64 = 0x40000; // 256KB (1 << 18)
    // MemoryChunk.main_thread_flags_ is first field at offset 0
    const FROM_PAGE: u64 = 1 << 3;
    const TO_PAGE: u64 = 1 << 4;
    const YOUNG_GEN_MASK: u64 = FROM_PAGE | TO_PAGE;

    if addr < meta.cage_base {
        return false;
    }

    // Page base = addr aligned to 256KB boundary
    let page_base = addr & !(PAGE_SIZE - 1);

    // Read main_thread_flags_ at offset 0
    let Some(flags_bytes) = dump.read(page_base, 4) else {
        return false;
    };
    let flags = u32::from_le_bytes([flags_bytes[0], flags_bytes[1], flags_bytes[2], flags_bytes[3]]) as u64;

    (flags & YOUNG_GEN_MASK) != 0
}

/// Checks if an address is in a page where major GC is currently in progress.
///
/// During major GC, V8 can temporarily violate array length invariants as it
/// performs evacuation, compaction, and right-trimming operations on arrays.
/// Arrays in these pages should not be flagged as corrupted.
///
/// V8 source: src/heap/memory-chunk.h:71-73
///   IS_MAJOR_GC_IN_PROGRESS = 1u << 7
/// V8 source: src/heap/heap-visitor-inl.h:357-359
///   "we only see sizes that get smaller during marking" (concurrent right-trim)
fn is_major_gc_in_progress(addr: u64, dump: &MemoryDump, meta: &MetaMapInfo) -> bool {
    const PAGE_SIZE: u64 = 0x40000; // 256KB (1 << 18)
    const IS_MAJOR_GC_IN_PROGRESS: u64 = 1 << 7; // 0x80

    if addr < meta.cage_base {
        return false;
    }

    // Page base = addr aligned to 256KB boundary
    let page_base = addr & !(PAGE_SIZE - 1);

    // Read main_thread_flags_ at offset 0
    let Some(flags_bytes) = dump.read(page_base, 4) else {
        return false;
    };
    let flags = u32::from_le_bytes([flags_bytes[0], flags_bytes[1], flags_bytes[2], flags_bytes[3]]) as u64;

    (flags & IS_MAJOR_GC_IN_PROGRESS) != 0
}

fn is_marking_bit_set(addr: u64, dump: &MemoryDump, meta: &MetaMapInfo) -> bool {
    const PAGE_SIZE: u64 = 0x40000; // 256KB V8 page size
    const MARKING_BITMAP_OFFSET: u64 = 0x140; // MutablePageMetadata::marking_bitmap_ offset
    const BITS_PER_CELL: u64 = 64; // MarkingBitmap uses 64-bit cells (uintptr_t)

    // Check if address is within the V8 cage
    if addr < meta.cage_base {
        return false;
    }

    // Calculate which page this address belongs to
    let offset_from_cage = addr - meta.cage_base;
    let page_index = offset_from_cage / PAGE_SIZE;
    let page_start = meta.cage_base + (page_index * PAGE_SIZE);

    // MutablePageMetadata is at the page start, marking_bitmap_ at offset 0x140
    let bitmap_start = page_start + MARKING_BITMAP_OFFSET;

    // Calculate bit index: MarkingBitmap tracks at kTaggedSize granularity
    let offset_in_page = addr - page_start;
    let bit_index = offset_in_page / dump.tagged_size as u64;

    // Calculate which cell and bit within that cell
    let cell_index = bit_index / BITS_PER_CELL;
    let bit_in_cell = bit_index % BITS_PER_CELL;

    // Read the 64-bit cell containing our bit
    let cell_addr = bitmap_start + (cell_index * 8);
    let Some(cell_bytes) = dump.read(cell_addr, 8) else {
        return false; // Can't read bitmap, assume bit is clear
    };
    let Ok(bytes_array) = cell_bytes.try_into() else {
        return false;
    };
    let cell_value = u64::from_le_bytes(bytes_array);

    // Check if the bit is set
    let mask = 1u64 << bit_in_cell;
    (cell_value & mask) != 0
}

/// Detects fake arrays embedded within another array's backing store.
///
/// Exploit technique: Attackers construct a fake JSArray header inside a FixedDoubleArray's
/// element storage. By controlling float values, they craft valid-looking tagged pointers.
///
/// Detection requires BOTH conditions:
/// 1. Array address falls within another array's backing store range
/// 2. Array's map pointer resolves to a valid Map (points to MetaMap)
///
/// The metamap validation is critical: random data within backing stores may accidentally
/// look like array addresses, but won't have map pointers that correctly chain to MetaMap.
/// Only deliberately crafted fake objects pass this check.
fn detect_embedded_in_elements(
    arr: &JSArray,
    elements_ranges: &[(u64, u64)],
    dump: &MemoryDump,
    meta: &MetaMapInfo,
    maps: &HashMap<u64, V8Map>,
    all_metamaps: &[MetaMapInfo],
) -> bool {
    let arr_addr = arr.address;

    for (elements_start, elements_end) in elements_ranges {
        // Skip if this IS the backing store start (not embedded within it)
        if arr_addr == *elements_start {
            continue;
        }

        if arr_addr >= *elements_start && arr_addr < *elements_end {
            let offset = arr_addr - *elements_start;
            // Large offsets suggest coincidental overlap, not deliberate embedding
            if offset > MAX_ELEMENTS_DISTANCE {
                continue;
            }

            // Validate the array's map is a real V8 Map by checking metamap chain.
            // This filters out false positives from garbage data that happens to
            // fall within backing store ranges but isn't a crafted fake object.
            if let Some(_map) = maps.get(&arr.map_address) {
                if let Some(map_ptr) = dump.read_tagged(arr.map_address) {
                    let decompressed = if dump.tagged_size == 4 {
                        meta.cage_base + untag(map_ptr)
                    } else {
                        untag(map_ptr)
                    };

                    let points_to_metamap = all_metamaps
                        .iter()
                        .any(|m| decompressed == m.address);

                    if points_to_metamap {
                        return true;
                    }
                }
            }
        }
    }

    false
}

