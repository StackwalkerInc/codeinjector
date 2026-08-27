// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

mod datadesc;
mod ecu;
mod patch;
mod seed;

use std::borrow::Cow;
use std::fs;
use std::io::Write;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind};

/// `Result::unwrap_or_else` specialised to this tool's failure mode: print
/// the error and exit with the usage banner.
pub(crate) trait OrDie<T> {
    fn or_die(self) -> T;
}

impl<T, E: std::fmt::Display> OrDie<T> for Result<T, E> {
    fn or_die(self) -> T {
        self.unwrap_or_else(|e| {
            eprintln!("{e}");
            usage_and_exit();
        })
    }
}

/// One queued piece of XML output: either the `<scaling>`/`<table>` pair for
/// an injected section (by patch extent), or a whole `data_desc` section to
/// walk. Queued in section order during injection, printed afterwards.
enum Emission<'a> {
    Patch(String, usize, usize),
    Desc(&'a [u8], u64, object::SectionIndex),
}

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
    symbols.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    // Pass 1: collect seed records, and the axis descriptors from data_desc
    // sections that seed records will be cross-checked against. Seed records
    // are applied to section bytes before injection so that the patched
    // .bin and the emitted XML agree.
    let mut seed_records: Vec<seed::SeedRecord> = Vec::new();
    let mut axis_descriptors: Vec<datadesc::AxisDescriptor> = Vec::new();
    for section in injection_file.sections() {
        match section.name().unwrap_or("") {
            "data_seed" => {
                seed_records.extend(seed::parse_records(section.data().unwrap_or(&[])).or_die());
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
    let mut seeder = seed::Seeder::new(seed_records);
    seeder.check_arch(ecu).or_die();
    seeder.validate_cross_record(&symbols, &ori_buf).or_die();
    seeder
        .validate_declared_sizes(&symbols, &ori_buf, &axis_descriptors)
        .or_die();

    // Pass 2: inject sections. XML emission is deferred to pass 3 -- an
    // `axisex` descriptor reads its element count out of the described
    // table's own header, which for a table injected into free space only
    // exists once every section has been written. Emissions are queued in
    // section order so the XML comes out in the same order as before.
    let mut emissions: Vec<Emission> = Vec::new();
    for section in injection_file.sections() {
        let name = match section.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        let section_data = section.data().unwrap_or(&[]);

        if name == "data_desc" {
            emissions.push(Emission::Desc(section_data, section.address(), section.index()));
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

        let mut section_bytes = Cow::Borrowed(section_data);
        seeder
            .apply_to_section(section.address(), &mut section_bytes, &symbols, &ori_buf)
            .or_die();

        if let Some((addr, size)) =
            patch::inject_section(&name, section.address() as usize, &section_bytes, ecu, &mut out_buf)
        {
            emissions.push(Emission::Patch(name, addr, size));
        }
    }

    // A record whose `dst` landed in no injected section at all (e.g. a
    // mis-wired linker script) would otherwise be silently dropped -- exit 0
    // with a ROM full of zeroed tables.
    seeder.check_all_applied().or_die();

    // Pass 3: emit the XML, now that `out_buf` is the finished ROM.
    for emission in emissions {
        match emission {
            Emission::Patch(name, addr, size) => {
                patch::print_patch_xml(&name, addr, size, &ori_buf, &out_buf)
            }
            Emission::Desc(data, addr, index) => {
                datadesc::process_section(data, addr, index, &symbols, ecu, &out_buf)
            }
        }
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
