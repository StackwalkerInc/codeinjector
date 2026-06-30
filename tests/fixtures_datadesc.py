# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

"""Generator functions for data-descriptor ELF fixtures."""
from elf_builder import (ELFBuilder, EM_M32R, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB,
                          STB_GLOBAL, STT_OBJECT, SHN_UNDEF,
                          SHN_ABS, SYM_SIZE, pack_sym)


def _build_strtab(names):
    """Return (bytes, dict[name -> offset]) for an ELF string table."""
    strtab = b'\x00'
    offsets = {}
    for n in names:
        if n not in offsets:
            offsets[n] = len(strtab)
            strtab += n.encode() + b'\x00'
    return strtab, offsets


def make_data_desc_elf(descriptors, machine=EM_M32R, section_addr=0):
    """
    Build a data_desc ELF.

    descriptors: list of dicts, each with:
      'desc_sym'   : descriptor symbol name, e.g. 'd_val'
      'desc_str'   : semicolon-delimited descriptor, e.g. 'value;Cat;Name;scl'
      'data_addr'  : absolute ROM address for the data symbol
                     (data sym name = desc_sym[2:])
    section_addr: sh_addr the linker assigns to the data_desc section. Real
      ROM builds place this section at a nonzero address (e.g. 0x60000), so
      descriptor symbol st_value (an absolute address, since this is a linked
      ELF) is section_addr + offset rather than a bare offset.
    Extra symbols (for axes referenced by map descriptors) can be injected via
    the same descriptor list — just include an entry for each axis symbol too.
    """
    b = ELFBuilder(machine)

    # Build data_desc section content
    desc_section = b''
    str_offsets = []
    for d in descriptors:
        str_offsets.append(len(desc_section))
        desc_section += d['desc_str'].encode() + b'\x00'

    data_desc_idx = b.add_section(
        'data_desc', desc_section,
        sh_type=SHT_PROGBITS,
        sh_flags=0, sh_addr=section_addr,
    )

    # Build symbol string table
    all_names = []
    for d in descriptors:
        all_names.append(d['desc_sym'])
        all_names.append(d['desc_sym'][2:])  # data symbol
    strtab, strtab_offsets = _build_strtab(all_names)

    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                                sh_flags=0, sh_addralign=1)

    # Build symbol table: index 0 = undefined, then pairs (desc_sym, data_sym)
    symtab = pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)  # STN_UNDEF
    for i, d in enumerate(descriptors):
        desc_sym_name = d['desc_sym']
        data_sym_name = desc_sym_name[2:]
        info = (STB_GLOBAL << 4) | STT_OBJECT

        # Descriptor symbol: in data_desc section, absolute address
        # section_addr + str_offsets[i] (st_value is absolute in a linked ELF)
        symtab += pack_sym(
            strtab_offsets[desc_sym_name],
            section_addr + str_offsets[i],
            0, info, 0,
            data_desc_idx,
        )
        # Data symbol: absolute
        symtab += pack_sym(
            strtab_offsets[data_sym_name],
            d['data_addr'],
            0, info, 0,
            SHN_ABS,
        )

    # sh_info = 1 (all symbols are global; first global at index 1)
    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)

    return b.build()


def make_no_symtab_datadesc_elf():
    """data_desc section with no .symtab — exercises storage_needed==0 branch."""
    b = ELFBuilder(EM_M32R)
    b.add_section('data_desc', b'value;Cat;Name;scl\x00',
                  sh_type=SHT_PROGBITS, sh_flags=0)
    return b.build()


def make_missing_data_sym_elf():
    """Descriptor whose data symbol (desc_sym[2:]) is absent from the table."""
    b = ELFBuilder(EM_M32R)
    desc_section = b'value;Cat;Name;scl\x00'
    data_desc_idx = b.add_section('data_desc', desc_section,
                                   sh_type=SHT_PROGBITS, sh_flags=0)

    strtab = b'\x00d_orphan\x00'
    strtab_offsets = {'d_orphan': 1}
    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                                sh_flags=0, sh_addralign=1)

    info = (STB_GLOBAL << 4) | STT_OBJECT
    symtab = pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)
    symtab += pack_sym(strtab_offsets['d_orphan'], 0, 0, info, 0, data_desc_idx)

    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)
    return b.build()
