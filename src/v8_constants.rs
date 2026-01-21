// V8 tagged pointer constants
// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=72-76>
pub const HEAP_OBJECT_TAG: u64 = 1;        // kHeapObjectTag
pub const HEAP_OBJECT_TAG_MASK: u64 = 3;  // kHeapObjectTagMask = (1 << kHeapObjectTagSize) - 1

/// Check if value is a heap object pointer
pub fn is_heap_object(ptr: u64) -> bool {
    (ptr & HEAP_OBJECT_TAG_MASK) == HEAP_OBJECT_TAG
}

/// Remove heap object tag to get raw address
pub fn untag(ptr: u64) -> u64 {
    ptr & !HEAP_OBJECT_TAG
}

/// Tag address for V8 display format (adds heap object tag offset)
pub fn tag_addr(addr: u64) -> u64 {
    addr + 1
}

/// Untag address from V8 display format (removes heap object tag offset)
pub fn untag_addr(tagged: u64) -> u64 {
    tagged - 1
}

/// Check if value is a Smi
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=86-88>
pub fn is_smi(value: u64) -> bool {
    (value & 1) == 0  // kSmiTag == 0, kSmiTagMask == 1
}

/// Extract Smi value (SmiToInt)
///
/// - 32-bit: <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=107-110>
/// - 64-bit: <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=148-151>
pub fn smi_value(tagged: u64, tagged_size: usize) -> i64 {
    if tagged_size == 4 {
        // 32-bit: kSmiShiftSize=0, shift_bits = kSmiTagSize(1) + 0 = 1
        ((tagged as i32) >> 1) as i64
    } else {
        // 64-bit: kSmiShiftSize=31, shift_bits = kSmiTagSize(1) + 31 = 32
        (tagged as i64) >> 32
    }
}

/// Map object field offsets
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/map.tq;l=59-66>
pub struct MapOffsets {
    pub instance_type: usize,
    pub bit_field2: usize,
}

impl MapOffsets {
    pub fn compressed() -> Self {
        // Compressed pointers (4 bytes): map(4) + 4*uint8(4) + instance_type@8 + bit_field@10 + bit_field2@11
        Self {
            instance_type: 8,
            bit_field2: 11,
        }
    }

    pub fn full_64bit() -> Self {
        // Full 64-bit pointers (8 bytes): map(8) + 4*uint8(4) + instance_type@12 + bit_field@14 + bit_field2@15
        Self {
            instance_type: 12,
            bit_field2: 15,
        }
    }
}

/// JSObject header size = map + properties + elements
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/include/v8-internal.h;l=847>
pub fn jsobject_header_size(tagged_size: usize) -> usize {
    3 * tagged_size  // kJSObjectHeaderSize = 3 * kApiTaggedSize
}

/// FixedArray header size = map + length
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/fixed-array.h;l=366-367>
pub fn fixed_array_header_size(tagged_size: usize) -> usize {
    2 * tagged_size  // kHeaderSize = HeapObject::kHeaderSize + kTaggedSize
}

/// Map object size (calculated from map.tq structure)
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/map.tq;l=56-77>
pub fn map_size(tagged_size: usize) -> usize {
    if tagged_size == 4 {
        // Compressed: map(4) + 4xUint8(4) + Uint16(2) + 2xUint8(2) + Uint32(4) + 6xTagged(24) = 40
        40
    } else {
        // Full 64-bit: map(8) + 4xUint8(4) + Uint16(2) + 2xUint8(2) + Uint32(4) + padding(4) + 6xTagged(48) = 72
        56
    }
}

/// ElementsKind enum and helper functions
///
/// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/elements-kind.h;l=105-119>
pub mod elements_kind {
    pub const PACKED_SMI_ELEMENTS: u8 = 0;
    pub const HOLEY_SMI_ELEMENTS: u8 = 1;
    pub const PACKED_ELEMENTS: u8 = 2;
    pub const HOLEY_ELEMENTS: u8 = 3;
    pub const PACKED_DOUBLE_ELEMENTS: u8 = 4;
    pub const HOLEY_DOUBLE_ELEMENTS: u8 = 5;

    /// IsDoubleElementsKind - checks if backing store is FixedDoubleArray (raw floats)
    ///
    /// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/elements-kind.h;l=365-367>
    pub fn is_double(kind: u8) -> bool {
        kind == PACKED_DOUBLE_ELEMENTS || kind == HOLEY_DOUBLE_ELEMENTS
    }

    /// IsSmiOrObjectElementsKind - checks if backing store is FixedArray (tagged pointers)
    ///
    /// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/elements-kind.h;l=414-416>
    pub fn is_smi_or_object(kind: u8) -> bool {
        kind <= HOLEY_ELEMENTS  // Equivalent to IsInRange(PACKED_SMI_ELEMENTS, HOLEY_ELEMENTS)
    }

    /// Extract ElementsKind from Map.bit_field2
    ///
    /// <https://source.chromium.org/chromium/chromium/src/+/debba63b78f8791411bff379835982cb2e8cabfa:v8/src/objects/map.tq;l=16-19>
    pub fn from_bit_field2(bf2: u8) -> u8 {
        (bf2 >> 2) & 0x3F  // elements_kind: ElementsKind: 6 bit (starts at bit 2)
    }
}
