use anyhow::{Context, Result};
use std::path::Path;

pub struct MemoryRegion {
    pub base: u64,
    pub data: Vec<u8>,
}

pub struct MemoryDump {
    regions: Vec<MemoryRegion>,
    pub tagged_size: usize,
}

impl MemoryDump {
    pub fn from_minidump(path: &Path) -> Result<Self> {
        use minidump::{Minidump, MinidumpMemory64List, MinidumpMemoryList};

        let dump = Minidump::read_path(path)
            .with_context(|| format!("Failed to read minidump: {}", path.display()))?;

        let tagged_size = 4;

        let regions = if let Ok(memory) = dump.get_stream::<MinidumpMemoryList>() {
            memory
                .iter()
                .map(|m| MemoryRegion {
                    base: m.base_address,
                    data: m.bytes.to_vec(),
                })
                .collect()
        } else if let Ok(memory) = dump.get_stream::<MinidumpMemory64List>() {
            memory
                .iter()
                .map(|m| MemoryRegion {
                    base: m.base_address,
                    data: m.bytes.to_vec(),
                })
                .collect()
        } else {
            anyhow::bail!(
                "No memory stream found in dump."
            );
        };

        Ok(Self {
            regions,
            tagged_size,
        })
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.data.len()).sum()
    }

    pub fn read(&self, addr: u64, size: usize) -> Option<&[u8]> {
        for region in &self.regions {
            let end = region.base + region.data.len() as u64;
            if addr >= region.base && addr + size as u64 <= end {
                let offset = (addr - region.base) as usize;
                return Some(&region.data[offset..offset + size]);
            }
        }
        None
    }

    pub fn read_tagged(&self, addr: u64) -> Option<u64> {
        let bytes = self.read(addr, self.tagged_size)?;
        Some(if self.tagged_size == 4 {
            u32::from_le_bytes(bytes.try_into().ok()?) as u64
        } else {
            u64::from_le_bytes(bytes.try_into().ok()?)
        })
    }
}
