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
                  machine=EM_M32R):
    """
    Build an ELF with:
      - a loadable payload section at payload_addr holding `payload`
      - a global STT_OBJECT symbol `payload_sym` at payload_addr with
        st_size = len(payload)
      - a non-alloc 'data_seed' section holding the packed `records`
    """
    b = ELFBuilder(machine)
    b.add_section('Seeded', payload, sh_type=SHT_PROGBITS,
                  sh_flags=SHF_ALLOC, sh_addr=payload_addr)
    b.add_section('data_seed', b''.join(records), sh_type=SHT_PROGBITS,
                  sh_flags=0, sh_addr=0)

    strtab, off = _build_strtab([payload_sym])
    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                               sh_flags=0, sh_addralign=1)
    symtab = pack_sym(0, 0, 0, 0, 0, 0)  # null symbol
    symtab += pack_sym(off[payload_sym], payload_addr, len(payload),
                       (STB_GLOBAL << 4) | STT_OBJECT, 0, SHN_ABS)
    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)
    return b.build()
