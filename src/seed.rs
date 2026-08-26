// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

use crate::datadesc::SymInfo;
use crate::ecu::EcuDescription;

pub const SEED_RECORD_SIZE: usize = 16;
pub const SEED_KIND_AXIS: u32 = 1;
pub const SEED_KIND_MAP3D8: u32 = 2;

pub struct SeedRecord {
    pub kind: u32,
    pub dst: u32,
    pub src: u32,
    pub src_yaxis: u32,
}

pub fn parse_records(section_data: &[u8]) -> Result<Vec<SeedRecord>, String> {
    if section_data.len() % SEED_RECORD_SIZE != 0 {
        return Err(format!(
            "data_seed section size {} is not a multiple of {}",
            section_data.len(),
            SEED_RECORD_SIZE
        ));
    }
    let word = |c: &[u8], i: usize| u32::from_be_bytes(c[i * 4..i * 4 + 4].try_into().unwrap());
    Ok(section_data
        .chunks_exact(SEED_RECORD_SIZE)
        .map(|c| SeedRecord {
            kind: word(c, 0),
            dst: word(c, 1),
            src: word(c, 2),
            src_yaxis: word(c, 3),
        })
        .collect())
}

/// Byte length of the object named by the symbol at `addr`, from the ELF
/// symbol table. Seeding needs it to derive the new table's dimensions.
fn symbol_size_at(addr: u32, symbols: &[SymInfo]) -> Result<usize, String> {
    let sym = symbols
        .iter()
        .find(|s| !s.is_section_sym && s.address == u64::from(addr) && s.size > 0)
        .ok_or_else(|| {
            format!(
                "no sized symbol at seed destination {addr:#x}; \
                 seeded tables must be C objects with a non-zero st_size"
            )
        })?;
    Ok(sym.size as usize)
}

/// Applies any `records` whose `dst` falls within `[section_addr, section_addr
/// + section_data.len())` to `section_data`, and marks each one applied in
/// `applied` (indexed identically to `records`).
///
/// `applied` is threaded through by the caller across every injected section
/// in a single run, so that after the whole section loop it can tell which
/// records (if any) never landed in any section -- a mis-wired linker script
/// producing a `dst` that matches no section at all would otherwise be
/// silently dropped, shipping a ROM with a zeroed table and exit code 0.
pub fn apply_records(
    records: &[SeedRecord],
    section_addr: u64,
    section_data: &mut [u8],
    symbols: &[SymInfo],
    ori_buf: &[u8],
    ecu: &EcuDescription,
    applied: &mut [bool],
) -> Result<(), String> {
    if !records.is_empty() && ecu.short_pointer_size != 2 {
        return Err(format!("data_seed is only supported on m32r, not {}", ecu.name));
    }
    let section_end = section_addr + section_data.len() as u64;
    for (rec, applied) in records.iter().zip(applied.iter_mut()) {
        let dst = u64::from(rec.dst);
        if dst < section_addr || dst >= section_end {
            continue;
        }
        *applied = true;
        let off = (dst - section_addr) as usize;
        let dst_len = symbol_size_at(rec.dst, symbols)?;
        if off + dst_len > section_data.len() {
            return Err(format!(
                "seed destination {:#x} (len {}) overruns its section",
                rec.dst, dst_len
            ));
        }
        match rec.kind {
            SEED_KIND_AXIS => seed_axis(rec, &mut section_data[off..off + dst_len], ori_buf)?,
            SEED_KIND_MAP3D8 => {
                seed_map3d8(rec, &mut section_data[off..off + dst_len], ori_buf)?
            }
            other => return Err(format!("unknown data_seed record kind {other}")),
        }
    }
    Ok(())
}

fn seed_axis(_rec: &SeedRecord, _dst: &mut [u8], _ori: &[u8]) -> Result<(), String> {
    Err("axis seeding not implemented".to_string())
}

fn seed_map3d8(_rec: &SeedRecord, _dst: &mut [u8], _ori: &[u8]) -> Result<(), String> {
    Err("3dmap8 seeding not implemented".to_string())
}
