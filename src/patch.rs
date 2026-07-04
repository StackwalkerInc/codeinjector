// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchMethod {
    M32rBl,
    M32rLd24R0,
    M32rLd24R4,
    M32rLduhR1,
    M32rSpliceIntoFunction,
    M32rRelocateSection,
    ShJumpToBody,
    ShSpliceIntoFunction,
    ShRelocateSection,
    Generic,
}

static PATCH_MARKERS: &[(&str, PatchMethod)] = &[
    ("[m32r-bl]",                     PatchMethod::M32rBl),
    ("[m32r-ld24-r0]",                PatchMethod::M32rLd24R0),
    ("[m32r-ld24-r4]",                PatchMethod::M32rLd24R4),
    ("[m32r-lduh-r1]",                PatchMethod::M32rLduhR1),
    ("[m32r-splice-into-function]",   PatchMethod::M32rSpliceIntoFunction),
    ("[m32r-relocate-section]",       PatchMethod::M32rRelocateSection),
    ("[sh-jump-to-body]",             PatchMethod::ShJumpToBody),
    ("[sh-splice-into-function]",     PatchMethod::ShSpliceIntoFunction),
    ("[sh-relocate-section]",         PatchMethod::ShRelocateSection),
];

pub fn get_patch_method(name: &str) -> PatchMethod {
    for (marker, method) in PATCH_MARKERS {
        if name.contains(marker) {
            return *method;
        }
    }
    PatchMethod::Generic
}

use crate::ecu::EcuDescription;

fn to_hex_string(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn print_patch_xml(
    section_name: &str,
    patch_address: usize,
    patch_size: usize,
    ori_buf: &[u8],
    out_buf: &[u8],
) {
    let scaling_name = format!("{} _scaling", section_name).replace('.', "_");
    let original = to_hex_string(&ori_buf[patch_address..patch_address + patch_size]);
    let patched  = to_hex_string(&out_buf[patch_address..patch_address + patch_size]);
    println!("<scaling name=\"{scaling_name}\" storagetype=\"bloblist\">\n\t<data name=\"Original\" value=\"{original}\" />\n\t<data name=\"Patched\" value=\"{patched}\" />\n</scaling>\n\n<table name=\"{section_name}\" address=\"{patch_address:x}\" category=\"Patches\" type=\"1D\" scaling=\"{scaling_name}\" />\n");
}

fn encode_m32r_bl(data: &[u8], vma: usize) -> Result<[u8; 4], &'static str> {
    let target = data
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| "Invalid bl injection instruction section size")?;

    let offset = (target.wrapping_sub(vma as u32) >> 2) & 0x00ff_ffff;
    let patch = 0xfe00_0000 | offset;

    Ok(patch.to_be_bytes())
}

fn encode_m32r_ld24(data: &[u8], register_index: u32) -> Result<[u8; 4], &'static str> {
    let target = data
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| "Invalid ld24 injection instruction section size")?;

    let patch = 0xe000_0000u32 | (register_index << 24) | target;
    Ok(patch.to_be_bytes())
}

fn encode_m32r_lduh_r1(data: &[u8]) -> Result<[u8; 4], &'static str> {
    let target = data
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| "Invalid lduh injection instruction section size")?;

    let disp16 = target.wrapping_sub(0x8000_8000) as u16;
    let dst_register: u32 = 1;
    let patch = 0xa0bd_0000u32
        .wrapping_add(dst_register << 24)
        .wrapping_add(disp16 as u32);
    Ok(patch.to_be_bytes())
}

fn encode_m32r_splice(data: &[u8], vma: usize) -> Result<[u8; 8], &'static str> {
    if data.len() < 8 {
        return Err("Invalid splice injection section size");
    }
    let target1 = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let target2 = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let pc1 = vma as u32;
    let pc2 = (vma as u32).wrapping_add(4);
    let p1 = 0xfe00_0000u32.wrapping_add(
        (target1.wrapping_sub(pc1) >> 2) & 0x00ff_ffff,
    );
    let p2 = 0xff00_0000u32.wrapping_add(
        (target2.wrapping_sub(pc2) >> 2) & 0x00ff_ffff,
    );
    let mut result = [0u8; 8];
    result[0..4].copy_from_slice(&p1.to_be_bytes());
    result[4..8].copy_from_slice(&p2.to_be_bytes());
    Ok(result)
}

// Returns (buf, total_patch_size). buf is 14 bytes max; only buf[..size] is valid.
fn encode_sh_jump_to_body(data: &[u8], vma: usize) -> Result<([u8; 14], usize), &'static str> {
    if data.len() < 4 {
        return Err("Invalid jump-to-body injection instruction section size");
    }
    let nop_prefix = match vma % 4 {
        2 => true,
        0 => false,
        _ => return Err("Invalid vma in [sh-jump-to-body]"),
    };
    let static_body: [u8; 8] = [0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09];
    let mut buf = [0u8; 14];
    if nop_prefix {
        buf[0..2].copy_from_slice(&[0x00, 0x09]);
        buf[2..10].copy_from_slice(&static_body);
        buf[10..14].copy_from_slice(&data[0..4]);
        Ok((buf, 14))
    } else {
        buf[0..8].copy_from_slice(&static_body);
        buf[8..12].copy_from_slice(&data[0..4]);
        Ok((buf, 12))
    }
}

// Returns (buf, total_patch_size). buf is 26 bytes max; only buf[..size] is valid.
fn encode_sh_splice(data: &[u8], vma: usize) -> Result<([u8; 26], usize), &'static str> {
    if data.len() < 8 {
        return Err("Invalid splice injection section size");
    }
    let nop_prefix = match vma % 4 {
        2 => true,
        0 => false,
        _ => return Err("Invalid vma in [sh-splice-into-function]"),
    };
    let static_body: [u8; 16] = [
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
    ];
    let mut buf = [0u8; 26];
    if nop_prefix {
        buf[0..2].copy_from_slice(&[0x00, 0x09]);
        buf[2..18].copy_from_slice(&static_body);
        buf[18..26].copy_from_slice(&data[0..8]);
        Ok((buf, 26))
    } else {
        buf[0..16].copy_from_slice(&static_body);
        buf[16..24].copy_from_slice(&data[0..8]);
        Ok((buf, 24))
    }
}

pub fn inject_section(
    name: &str,
    vma: usize,
    section_data: &[u8],
    ecu: &EcuDescription,
    ori_buf: &[u8],
    out_buf: &mut [u8],
) {
    let method = get_patch_method(name);

    if method != PatchMethod::Generic && !name.contains(ecu.patch_method_prefix) {
        eprintln!("patch_method incompatible with arch at {}", name);
        crate::usage_and_exit();
    }

    let sec_size = section_data.len();
    let (patch_address, patch_size): (usize, usize) = match method {
        PatchMethod::Generic => {
            out_buf[vma..vma + sec_size].copy_from_slice(section_data);
            (vma, sec_size)
        }
        PatchMethod::M32rBl => {
            let patch = encode_m32r_bl(section_data, vma).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLd24R0 => {
            let patch = encode_m32r_ld24(section_data, 0u32).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLd24R4 => {
            let patch = encode_m32r_ld24(section_data, 4u32).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLduhR1 => {
            let patch = encode_m32r_lduh_r1(section_data).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rSpliceIntoFunction => {
            let patch = encode_m32r_splice(section_data, vma).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 8].copy_from_slice(&patch);
            (vma, 8)
        }
        PatchMethod::M32rRelocateSection | PatchMethod::ShRelocateSection => {
            if section_data.len() < 4 {
                return;
            }
            let target = u32::from_be_bytes(section_data[0..4].try_into().unwrap()) as usize;
            out_buf[target..target + section_data.len()].copy_from_slice(section_data);
            (target, section_data.len())
        }
        PatchMethod::ShJumpToBody => {
            let (buf, size) = encode_sh_jump_to_body(section_data, vma).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + size].copy_from_slice(&buf[0..size]);
            (vma, size)
        }
        PatchMethod::ShSpliceIntoFunction => {
            let (buf, size) = encode_sh_splice(section_data, vma).unwrap_or_else(|e| {
                eprintln!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + size].copy_from_slice(&buf[0..size]);
            (vma, size)
        }
    };

    print_patch_xml(name, patch_address, patch_size, ori_buf, out_buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_patch_method_all_markers() {
        assert_eq!(get_patch_method("[m32r-bl].text"),                    PatchMethod::M32rBl);
        assert_eq!(get_patch_method("[m32r-ld24-r0].text"),               PatchMethod::M32rLd24R0);
        assert_eq!(get_patch_method("[m32r-ld24-r4].text"),               PatchMethod::M32rLd24R4);
        assert_eq!(get_patch_method("[m32r-lduh-r1].text"),               PatchMethod::M32rLduhR1);
        assert_eq!(get_patch_method("[m32r-splice-into-function].text"),  PatchMethod::M32rSpliceIntoFunction);
        assert_eq!(get_patch_method("[m32r-relocate-section].text"),      PatchMethod::M32rRelocateSection);
        assert_eq!(get_patch_method("[sh-jump-to-body].text"),            PatchMethod::ShJumpToBody);
        assert_eq!(get_patch_method("[sh-splice-into-function].text"),    PatchMethod::ShSpliceIntoFunction);
        assert_eq!(get_patch_method("[sh-relocate-section].text"),        PatchMethod::ShRelocateSection);
        assert_eq!(get_patch_method("generic_section"),                   PatchMethod::Generic);
        assert_eq!(get_patch_method("data_desc"),                        PatchMethod::Generic);
    }

    #[test]
    fn test_encode_m32r_bl() {
        // target=0x2000, vma=0x1000 → offset=(0x1000/4)=0x400 → 0xfe000400
        let result = encode_m32r_bl(&[0x00, 0x00, 0x20, 0x00], 0x1000);
        assert_eq!(result.unwrap(), [0xfe, 0x00, 0x04, 0x00]);
        // Wrong size
        assert!(encode_m32r_bl(&[0x00; 8], 0x1000).is_err());
    }

    #[test]
    fn test_encode_m32r_ld24() {
        // target=0x1234 → r0: 0xe0001234, r4: 0xe4001234
        assert_eq!(encode_m32r_ld24(&[0x00, 0x00, 0x12, 0x34], 0u32).unwrap(), [0xe0, 0x00, 0x12, 0x34]);
        assert_eq!(encode_m32r_ld24(&[0x00, 0x00, 0x12, 0x34], 4u32).unwrap(),  [0xe4, 0x00, 0x12, 0x34]);
        assert!(encode_m32r_ld24(&[0x00; 8], 0u32).is_err());
    }

    #[test]
    fn test_encode_m32r_lduh_r1() {
        // target=0x80009000 → disp16=0x1000 → 0xa1bd1000
        assert_eq!(
            encode_m32r_lduh_r1(&[0x80, 0x00, 0x90, 0x00]).unwrap(),
            [0xa1, 0xbd, 0x10, 0x00]
        );
        assert!(encode_m32r_lduh_r1(&[0x00; 8]).is_err());
    }

    #[test]
    fn test_encode_m32r_splice() {
        // target1=0x2000 pc1=0x1000 → (0x1000/4)=0x400 → 0xfe000400
        // target2=0x3000 pc2=0x1004 → (0x1FFC/4)=0x7ff → 0xff0007ff
        let data = [0x00u8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00];
        let result = encode_m32r_splice(&data, 0x1000).unwrap();
        assert_eq!(&result[0..4], &[0xfe, 0x00, 0x04, 0x00]);
        assert_eq!(&result[4..8], &[0xff, 0x00, 0x07, 0xff]);
        assert!(encode_m32r_splice(&[0u8; 4], 0x1000).is_err());
    }

    #[test]
    fn test_inject_relocate_section() {
        let ori = vec![0u8; 0x2000];
        let mut out = ori.clone();
        let ecu = crate::ecu::find_ecu("mmc-m32r").unwrap();
        inject_section("[m32r-relocate-section].data", 0, &[0x00, 0x00, 0x10, 0x00, 0xAA, 0xBB], ecu, &ori, &mut out);
        assert_eq!(&out[0x1000..0x1006], &[0x00, 0x00, 0x10, 0x00, 0xAA, 0xBB]);
    }

    #[test]
    fn test_sh_jump_to_body() {
        // vma=0x1000 (0x1000 % 4 == 0): no NOP prefix, patch_size=12
        let target = [0x00u8, 0x00, 0x80, 0x00];
        let (body, size) = encode_sh_jump_to_body(&target, 0x1000).unwrap();
        assert_eq!(size, 12);
        assert_eq!(&body[0..8], &[0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09]);
        assert_eq!(&body[8..12], &[0x00, 0x00, 0x80, 0x00]);

        // vma=0x1002 (0x1002 % 4 == 2): NOP prefix prepended, patch_size=14
        let (body2, size2) = encode_sh_jump_to_body(&target, 0x1002).unwrap();
        assert_eq!(size2, 14);
        assert_eq!(&body2[0..2], &[0x00, 0x09]);
        assert_eq!(&body2[2..10], &[0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09]);
        assert_eq!(&body2[10..14], &[0x00, 0x00, 0x80, 0x00]);

        // vma % 4 == 1: error
        assert!(encode_sh_jump_to_body(&target, 0x1001).is_err());
    }

    #[test]
    fn test_sh_splice() {
        // vma=0x1000 (aligned): no NOP prefix, patch_size=24
        let data = [0x00u8, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x00];
        let (body, size) = encode_sh_splice(&data, 0x1000).unwrap();
        assert_eq!(size, 24);
        let expected: [u8; 24] = [
            0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
            0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
            0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x00,
        ];
        assert_eq!(&body[0..24], &expected);

        // NOP-prefix case (vma=0x1002)
        let (body_nop, size_nop) = encode_sh_splice(&data, 0x1002).unwrap();
        assert_eq!(size_nop, 26);
        assert_eq!(&body_nop[0..2], &[0x00, 0x09]);
        assert_eq!(&body_nop[2..18], &[
            0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
            0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
        ]);
        assert_eq!(&body_nop[18..26], &[0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x00]);

        // Error case
        assert!(encode_sh_splice(&data, 0x1001).is_err());
    }
}
