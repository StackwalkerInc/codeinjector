# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

"""Generator functions for data_seed ELF fixtures."""
import struct
from elf_builder import (ELFBuilder, EM_M32R, EM_SH, SHT_PROGBITS, SHT_SYMTAB,
                         SHT_STRTAB, SHF_ALLOC, STB_GLOBAL, STT_OBJECT,
                         SHN_ABS, SYM_SIZE, pack_sym)

SEED_KIND_AXIS = 1
SEED_KIND_MAP3D8 = 2


def seed_record(kind, dst, src, src_yaxis=0):
    return struct.pack('>IIII', kind, dst, src, src_yaxis)


def _build_strtab(names):
    strtab = b'\x00'
    offsets = {}
    for n in names:
        if n not in offsets:
            offsets[n] = len(strtab)
            strtab += n.encode() + b'\x00'
    return strtab, offsets


def make_seed_elf(records, payload_addr, payload, payload_sym='seeded',
                  machine=EM_M32R, sym_size=None):
    """
    Build an ELF with:
      - a loadable payload section at payload_addr holding `payload`
      - a global STT_OBJECT symbol `payload_sym` at payload_addr with
        st_size = len(payload) (or `sym_size` if given, to deliberately
        desync the declared symbol size from the section's actual bytes)
      - a non-alloc 'data_seed' section holding the packed `records`
    """
    return make_multi_seed_elf(
        records, [(payload_addr, payload, payload_sym, sym_size)], machine=machine)


def make_multi_seed_elf(records, payloads, machine=EM_M32R):
    """
    Like make_seed_elf, but for more than one seed destination.

    payloads: list of (addr, data, sym_name) tuples, or (addr, data,
    sym_name, sym_size) to override the declared symbol size. Each becomes
    its own loadable section with a global STT_OBJECT symbol.
    """
    payloads = [p if len(p) == 4 else (*p, None) for p in payloads]

    b = ELFBuilder(machine)
    for i, (addr, data, _name, _size) in enumerate(payloads):
        b.add_section(f'Seeded{i}', data, sh_type=SHT_PROGBITS,
                      sh_flags=SHF_ALLOC, sh_addr=addr)
    b.add_section('data_seed', b''.join(records), sh_type=SHT_PROGBITS,
                  sh_flags=0, sh_addr=0)

    strtab, off = _build_strtab([name for _, _, name, _ in payloads])
    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                               sh_flags=0, sh_addralign=1)
    symtab = pack_sym(0, 0, 0, 0, 0, 0)  # null symbol
    for addr, data, name, size in payloads:
        size = len(data) if size is None else size
        symtab += pack_sym(off[name], addr, size,
                           (STB_GLOBAL << 4) | STT_OBJECT, 0, SHN_ABS)
    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)
    return b.build()


def make_seed_with_desc_elf(records, payload_addr, payload, desc_str,
                            payload_sym='seeded', desc_section_addr=0,
                            machine=EM_M32R):
    """
    Build an ELF combining a data_seed record targeting `payload_sym` with a
    data_desc entry describing that same destination symbol.

    Per the data_desc convention (see fixtures_datadesc.py), the descriptor
    symbol's name is a 2-character prefix plus the data symbol's name, so the
    descriptor symbol here is named 'd_' + payload_sym and its "data symbol"
    (desc_sym[2:]) resolves back to payload_sym itself -- the very symbol the
    seed record fills in.
    """
    b = ELFBuilder(machine)
    b.add_section('Seeded', payload, sh_type=SHT_PROGBITS,
                  sh_flags=SHF_ALLOC, sh_addr=payload_addr)
    b.add_section('data_seed', b''.join(records), sh_type=SHT_PROGBITS,
                  sh_flags=0, sh_addr=0)
    data_desc_idx = b.add_section(
        'data_desc', desc_str.encode() + b'\x00',
        sh_type=SHT_PROGBITS, sh_flags=0, sh_addr=desc_section_addr)

    desc_sym = 'd_' + payload_sym
    strtab, off = _build_strtab([payload_sym, desc_sym])
    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                               sh_flags=0, sh_addralign=1)
    info = (STB_GLOBAL << 4) | STT_OBJECT
    symtab = pack_sym(0, 0, 0, 0, 0, 0)  # null symbol
    symtab += pack_sym(off[payload_sym], payload_addr, len(payload), info, 0, SHN_ABS)
    symtab += pack_sym(off[desc_sym], desc_section_addr, 0, info, 0, data_desc_idx)
    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)
    return b.build()
