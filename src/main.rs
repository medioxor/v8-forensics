use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use v8_forensics::dump::MemoryDump;
use v8_forensics::objects::V8Heap;
use v8_forensics::v8_constants::{tag_addr, elements_kind};

#[derive(Parser)]
#[command(name = "v8-forensics")]
#[command(about = "Detect V8 Exploitation Artifacts")]
struct Args {
    /// Path to memory dump file (.dmp)
    dump: PathBuf,

    /// Show heap statistics
    #[arg(long)]
    stats: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    process_dump(&args.dump, &args)?;
    Ok(())
}

fn process_dump(dump_path: &PathBuf, args: &Args) -> Result<()> {
    eprintln!("loading dump: {:?}", dump_path);
    let dump = MemoryDump::from_minidump(dump_path)?;
    eprintln!(
        "loaded {} regions ({:.1} MB)",
        dump.region_count(),
        dump.total_bytes() as f64 / 1_000_000.0
    );

    let all_metamaps = dump.find_all_metamaps();
    if all_metamaps.is_empty() {
        return Err(anyhow::anyhow!(
            "could not find metamap - is this a Chrome process dump?"
        ));
    }

    let meta = &all_metamaps[0];
    let heap = V8Heap::extract(&dump, meta);

    display_corrupted_arrays(&heap);
    display_embedded_arrays(&heap, &dump);
    display_mismatch_arrays(&heap);

    if args.stats {
        print_stats(&heap);
    }

    Ok(())
}

fn display_corrupted_arrays(heap: &V8Heap) {
    use std::collections::HashSet;
    use v8_forensics::detection::array::ArrayAnomaly;

    let mut seen = HashSet::new();
    let corrupted: Vec<_> = heap.anomalies.iter().filter_map(|(idx, anomaly)| {
        if let ArrayAnomaly::CorruptedLength = anomaly {
            let arr = &heap.arrays[*idx];
            if seen.insert(arr.address) {
                Some(arr)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    if corrupted.is_empty() {
        return;
    }

    eprintln!("\narrays with corrupted length (array_length > elements_length):");
    for (i, arr) in corrupted.iter().enumerate() {
        eprintln!("\n  corrupted array {}:", i + 1);
        eprintln!("    address: {:#x}", arr.address);
        if let Some(map) = heap.maps.get(&arr.map_address) {
            eprintln!("    map_address: {:#x} (instance_type: {})", tag_addr(arr.map_address), map.instance_type);
        } else {
            eprintln!("    map_address: {:#x}", tag_addr(arr.map_address));
        }
        eprintln!("    elements_kind: {}", arr.elements_kind);
        eprintln!("    array_length: {} (CORRUPTED)", arr.array_length);
        eprintln!("    elements_length: {}", arr.elements_length);
        eprintln!("    oob_elements: {}", arr.array_length - arr.elements_length);
    }
}

fn display_embedded_arrays(heap: &V8Heap, dump: &MemoryDump) {
    use std::collections::HashSet;
    use v8_forensics::detection::array::ArrayAnomaly;

    let mut seen = HashSet::new();
    let embedded: Vec<_> = heap.anomalies.iter().filter_map(|(idx, anomaly)| {
        if let ArrayAnomaly::EmbeddedInElements = anomaly {
            let arr = &heap.arrays[*idx];
            if seen.insert(arr.address) {
                Some(arr)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    if embedded.is_empty() {
        return;
    }

    eprintln!("\nfake arrays embedded in other arrays:");
    for (i, arr) in embedded.iter().enumerate() {
        eprintln!("\n  embedded array {}:", i + 1);
        eprintln!("    address: {:#x}", arr.address);

        if let Some(map) = heap.maps.get(&arr.map_address) {
            eprintln!("    map_address: {:#x} (instance_type: {})", tag_addr(arr.map_address), map.instance_type);
        } else {
            eprintln!("    map_address: {:#x}", tag_addr(arr.map_address));
        }

        eprintln!("    elements_kind: {}", arr.elements_kind);
        eprintln!("    array_length: {}", arr.array_length);
        eprintln!("    elements_length: {}", arr.elements_length);
        eprintln!("    elements_address: {:#x}", tag_addr(arr.elements_address));
        eprintln!("    elements_map_address: {:#x}", tag_addr(arr.elements_map_address));

        if let Some(container) = heap.find_containing_array(arr.address, dump) {
            eprintln!("    container_address: {:#x}", container.address);
            eprintln!("    container.array_length: {}", container.array_length);
            eprintln!("    container.elements_length: {}", container.elements_length);
            eprintln!("    container.elements_address: {:#x}", tag_addr(container.elements_address));

            let offset = arr.address - container.elements_address;
            let header_size = 2 * dump.tagged_size as u64;
            let element_size = if v8_forensics::v8_constants::elements_kind::is_double(container.elements_kind) { 8u64 } else { dump.tagged_size as u64 };
            if offset >= header_size {
                let element_index = (offset - header_size) / element_size;
                eprintln!("    offset: {} bytes (element ~{})", offset, element_index);
            } else {
                eprintln!("    offset: {} bytes (header)", offset);
            }
        }
    }
}

fn display_mismatch_arrays(heap: &V8Heap) {
    use std::collections::HashSet;
    use v8_forensics::detection::array::ArrayAnomaly;

    let mut seen = HashSet::new();
    let mismatches: Vec<_> = heap.anomalies.iter().filter_map(|(idx, anomaly)| {
        if let ArrayAnomaly::ElementsMapMismatch = anomaly {
            let arr = &heap.arrays[*idx];
            if seen.insert(arr.address) {
                Some(arr)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    if mismatches.is_empty() {
        return;
    }

    eprintln!("\nelements map mismatches detected:");
    for (i, arr) in mismatches.iter().enumerate() {
        eprintln!("\n  mismatch {}:", i + 1);
        eprintln!("    address: {:#x}", arr.address);
        if let Some(map) = heap.maps.get(&arr.map_address) {
            eprintln!("    map_address: {:#x} (instance_type: {})", tag_addr(arr.map_address), map.instance_type);
        }
        eprintln!("    elements_kind: {}", arr.elements_kind);
        eprintln!("    array_length: {}", arr.array_length);
        eprintln!("    elements_length: {}", arr.elements_length);
        eprintln!("    elements_address: {:#x}", tag_addr(arr.elements_address));
        eprintln!("    elements_map_address: {:#x}", tag_addr(arr.elements_map_address));
        if let Some(elements_map) = heap.maps.get(&arr.elements_map_address) {
            eprintln!("    elements_map.instance_type: {}", elements_map.instance_type);
        }
    }
}

fn print_stats(heap: &V8Heap) {
    use std::collections::HashMap;

    let double_arrays = heap.arrays.iter().filter(|a| elements_kind::is_double(a.elements_kind)).count();
    let object_arrays = heap.arrays.iter().filter(|a| elements_kind::is_smi_or_object(a.elements_kind)).count();

    // Count Maps by instance_type
    let mut map_instance_types: HashMap<u16, u32> = HashMap::new();
    for map in heap.maps.values() {
        *map_instance_types.entry(map.instance_type).or_insert(0) += 1;
    }

    // Count Arrays by their Map's instance_type
    let mut array_instance_types: HashMap<u16, u32> = HashMap::new();
    for arr in &heap.arrays {
        if let Some(map) = heap.maps.get(&arr.map_address) {
            *array_instance_types.entry(map.instance_type).or_insert(0) += 1;
        }
    }

    eprintln!("\nheap statistics:");
    eprintln!("  total maps: {}", heap.maps.len());
    eprintln!("  total arrays: {}", heap.arrays.len());
    eprintln!("  object arrays: {}", object_arrays);
    eprintln!("  double arrays: {}", double_arrays);

    eprintln!("\n  map instance_type distribution (top 20):");
    let mut sorted_maps: Vec<_> = map_instance_types.iter().collect();
    sorted_maps.sort_by(|a, b| b.1.cmp(a.1));
    for (instance_type, count) in sorted_maps.iter().take(20) {
        eprintln!("    instance_type {}: {} maps", instance_type, count);
    }

    eprintln!("\n  array instance_type distribution (top 20):");
    let mut sorted_arrays: Vec<_> = array_instance_types.iter().collect();
    sorted_arrays.sort_by(|a, b| b.1.cmp(a.1));
    for (instance_type, count) in sorted_arrays.iter().take(20) {
        eprintln!("    instance_type {}: {} arrays", instance_type, count);
    }
}
