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
    if !section_data.len().is_multiple_of(SEED_RECORD_SIZE) {
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

const AXIS_HEADER: usize = 6;

fn be16(buf: &[u8], off: usize) -> Result<u16, String> {
    buf.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("read past end of ROM at {off:#x}"))
}

fn seed_axis(rec: &SeedRecord, dst: &mut [u8], ori: &[u8]) -> Result<(), String> {
    let src = rec.src as usize;
    let stock_n = be16(ori, src + 4)? as usize;

    if dst.len() < AXIS_HEADER || !(dst.len() - AXIS_HEADER).is_multiple_of(2) {
        return Err(format!(
            "seeded axis at {:#x} has size {}, which is not {AXIS_HEADER} + 2*n",
            rec.dst,
            dst.len()
        ));
    }
    let new_n = (dst.len() - AXIS_HEADER) / 2;

    if stock_n < 2 {
        return Err(format!(
            "stock axis {src:#x} has {stock_n} entries; need at least 2 to extrapolate"
        ));
    }
    if new_n < stock_n {
        return Err(format!(
            "seeded axis at {:#x} has {new_n} entries, fewer than stock's {stock_n}",
            rec.dst
        ));
    }

    // Header: dst and src copied verbatim, size is the new one.
    dst[0..4].copy_from_slice(&ori[src..src + 4]);
    dst[4..6].copy_from_slice(&(new_n as u16).to_be_bytes());

    // Stock breakpoints.
    for i in 0..stock_n {
        let v = be16(ori, src + AXIS_HEADER + 2 * i)?;
        dst[AXIS_HEADER + 2 * i..AXIS_HEADER + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }

    // Extrapolated tail.
    let last = be16(ori, src + AXIS_HEADER + 2 * (stock_n - 1))?;
    let prev = be16(ori, src + AXIS_HEADER + 2 * (stock_n - 2))?;
    if last <= prev {
        return Err(format!(
            "stock axis {src:#x} tail is not ascending ({prev} -> {last}); \
             extrapolation would run backwards"
        ));
    }
    let delta = u32::from(last - prev);
    for i in stock_n..new_n {
        let v = u32::from(last) + delta * (i - (stock_n - 1)) as u32;
        if v > 0xffff {
            return Err(format!(
                "axis extrapolation for {:#x} overflows u16 at entry {i} ({v:#x}); \
                 equal top entries would divide by zero in calc_axis",
                rec.dst
            ));
        }
        dst[AXIS_HEADER + 2 * i..AXIS_HEADER + 2 * i + 2]
            .copy_from_slice(&(v as u16).to_be_bytes());
    }
    Ok(())
}

const MAP3D8_HEADER: usize = 7;

fn seed_map3d8(rec: &SeedRecord, dst: &mut [u8], ori: &[u8]) -> Result<(), String> {
    let src = rec.src as usize;
    let yaxis = rec.src_yaxis as usize;

    let stock_xs = *ori
        .get(src + 6)
        .ok_or_else(|| format!("stock map {src:#x} header runs past end of ROM"))?
        as usize;
    if stock_xs == 0 {
        return Err(format!("stock map {src:#x} declares xsize 0"));
    }
    let stock_ys = be16(ori, yaxis + 4)? as usize;
    if stock_ys == 0 {
        return Err(format!("stock y-axis {yaxis:#x} declares size 0"));
    }

    if dst.len() < MAP3D8_HEADER || !(dst.len() - MAP3D8_HEADER).is_multiple_of(stock_xs) {
        return Err(format!(
            "seeded map at {:#x} has size {}, which is not {MAP3D8_HEADER} + {stock_xs}*n",
            rec.dst,
            dst.len()
        ));
    }
    let new_ys = (dst.len() - MAP3D8_HEADER) / stock_xs;
    if new_ys < stock_ys {
        return Err(format!(
            "seeded map at {:#x} has {new_ys} rows, fewer than stock's {stock_ys}",
            rec.dst
        ));
    }

    // Header copied verbatim: type, offset, xsrc, ysrc, xsize.
    let hdr = ori
        .get(src..src + MAP3D8_HEADER)
        .ok_or_else(|| format!("stock map {src:#x} header runs past end of ROM"))?;
    dst[0..MAP3D8_HEADER].copy_from_slice(hdr);

    // Body: clamped row/column replication.
    let body_src = src + MAP3D8_HEADER;
    for y in 0..new_ys {
        let sy = y.min(stock_ys - 1);
        for x in 0..stock_xs {
            let sx = x.min(stock_xs - 1);
            let v = *ori.get(body_src + sy * stock_xs + sx).ok_or_else(|| {
                format!("stock map {src:#x} body runs past end of ROM")
            })?;
            dst[MAP3D8_HEADER + y * stock_xs + x] = v;
        }
    }
    Ok(())
}
