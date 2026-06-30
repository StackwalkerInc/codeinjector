// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

mod datadesc;
mod ecu;
mod patch;

use std::fs;
use std::io::Write;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind};

pub(crate) fn usage_and_exit() -> ! {
    eprintln!("Usage: codeinjector ecu_name original_file injection_file [output_file]");
    eprintln!("\tecu_name - one of supported ecu names: mmc-sh2, mmc-m32r");
    eprintln!("\toriginal_file - binary file of stock ROM");
    eprintln!("\tinjection_file - ELF container with override code");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage_and_exit();
    }

    let ecu = ecu::find_ecu(&args[1]).unwrap_or_else(|| {
        eprintln!("{} ecu not supported", args[1]);
        usage_and_exit();
    });

    let ori_buf = fs::read(&args[2]).unwrap_or_else(|_| {
        eprintln!("No original_file");
        usage_and_exit();
    });
    let mut out_buf = ori_buf.clone();

    let injection_data = fs::read(&args[3]).unwrap_or_else(|_| {
        eprintln!("No injection_file");
        usage_and_exit();
    });

    let injection_file = object::File::parse(injection_data.as_slice()).unwrap_or_else(|_| {
        eprintln!("injection_file isn't BFD object");
        usage_and_exit();
    });

    // Build sorted symbol table (mirrors bfd_canonicalize_symtab + qsort)
    let mut symbols: Vec<datadesc::SymInfo> = injection_file
        .symbols()
        .map(|s| datadesc::SymInfo {
            name: s.name().unwrap_or("").to_string(),
            address: s.address(),
            section_index: s.section_index(),
            is_section_sym: s.kind() == SymbolKind::Section,
        })
        .collect();
    symbols.sort_unstable_by_key(|s| s.name.clone());

    // Process sections (mirrors bfd_map_over_sections)
    for section in injection_file.sections() {
        let name = match section.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        let section_data = section.data().unwrap_or(&[]);

        if name == "data_desc" {
            datadesc::process_section(section_data, section.address(), section.index(), &symbols, ecu, &ori_buf);
            continue;
        }

        // Skip sections without SHF_ALLOC (mirrors SEC_LOAD check)
        let loadable = match section.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
            _ => false,
        };
        if !loadable {
            continue;
        }

        // Skip uninitialized sections (SHT_NOBITS / COMMON allocations in RAM).
        // Matches libbfd SEC_LOAD behaviour: sections with no file content are not patches.
        if section.kind() == object::SectionKind::UninitializedData {
            continue;
        }

        patch::inject_section(
            &name,
            section.address() as usize,
            section_data,
            ecu,
            &ori_buf,
            &mut out_buf,
        );
    }

    if args.len() > 4 {
        fs::write(&args[4], &out_buf).unwrap_or_else(|_| {
            eprintln!("Can't create output_file");
            usage_and_exit();
        });
    } else {
        std::io::stdout().write_all(&out_buf).unwrap_or_else(|e| {
            eprintln!("Unable to write contents to output: {e}");
        });
    }
}
