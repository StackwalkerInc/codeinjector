// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

mod datadesc;
mod ecu;
mod patch;
mod seed;

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
            size: s.size(),
            section_index: s.section_index(),
            is_section_sym: s.kind() == SymbolKind::Section,
        })
        .collect();
    symbols.sort_unstable_by_key(|s| s.name.clone());

    // Pass 1: collect seed records, and the axis descriptors from data_desc
    // sections that seed records will be cross-checked against. Seed records
    // are applied to section bytes before injection so that the patched
    // .bin and the emitted XML agree.
    let mut seed_records: Vec<seed::SeedRecord> = Vec::new();
    let mut axis_descriptors: Vec<datadesc::AxisDescriptor> = Vec::new();
    for section in injection_file.sections() {
        match section.name().unwrap_or("") {
            "data_seed" => {
                let parsed =
                    seed::parse_records(section.data().unwrap_or(&[])).unwrap_or_else(|e| {
                        eprintln!("{e}");
                        usage_and_exit();
                    });
                seed_records.extend(parsed);
            }
            "data_desc" => {
                axis_descriptors.extend(datadesc::collect_axis_descriptors(
                    section.data().unwrap_or(&[]),
                    section.address(),
                    section.index(),
                    &symbols,
                ));
            }
            _ => {}
        }
    }

    // Pre-pass: cross-check seed records against each other and against
    // data_desc, before any seeding is performed. Both are hard-fails
    // required by the seeding design spec -- see seed.rs for why.
    seed::validate_cross_record(&seed_records, &symbols, &ori_buf).unwrap_or_else(|e| {
        eprintln!("{e}");
        usage_and_exit();
    });
    seed::validate_declared_sizes(&seed_records, &symbols, &ori_buf, &axis_descriptors)
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            usage_and_exit();
        });

    // Tracks, across the whole section loop below, which seed records were
    // ever applied to some section. A record whose `dst` lands in no
    // injected section at all (e.g. a mis-wired linker script) would
    // otherwise be silently dropped -- exit 0 with a ROM full of zeroed
    // tables. That failure mode is checked for after the loop.
    let mut seed_applied = vec![false; seed_records.len()];

    // Pass 2: process sections.
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
        if name == "data_seed" {
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

        let mut section_bytes = section_data.to_vec();
        seed::apply_records(
            &seed_records,
            section.address(),
            &mut section_bytes,
            &symbols,
            &ori_buf,
            ecu,
            &mut seed_applied,
        )
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            usage_and_exit();
        });

        patch::inject_section(
            &name,
            section.address() as usize,
            &section_bytes,
            ecu,
            &ori_buf,
            &mut out_buf,
        );
    }

    let unapplied: Vec<String> = seed_records
        .iter()
        .zip(seed_applied.iter())
        .filter(|(_, &applied)| !applied)
        .map(|(rec, _)| format!("{:#x}", rec.dst))
        .collect();
    if !unapplied.is_empty() {
        eprintln!(
            "data_seed record(s) never applied -- dst not in any injected section: {}",
            unapplied.join(", ")
        );
        usage_and_exit();
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
