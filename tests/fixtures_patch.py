# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

"""Generator functions for patch-method ELF fixtures."""
import struct
from elf_builder import ELFBuilder, EM_M32R, EM_SH, SHF_ALLOC


def _be32(v):
    return struct.pack('>I', v)


def make_m32r_bl_elf(vma=0x1000, target=0x2000):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-bl]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_bra_elf(vma=0x1000, target=0x2000):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-bra]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_ld24_r0_elf(vma=0x1000, target=0x1234):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-ld24-r0]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_ld24_r4_elf(vma=0x1000, target=0x1234):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-ld24-r4]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_lduh_r1_elf(vma=0x1000, target=0x80009000):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-lduh-r1]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_splice_elf(vma=0x1000, target_fn=0x2000, target_ret=0x3000):
    b = ELFBuilder(EM_M32R)
    data = _be32(target_fn) + _be32(target_ret)
    b.add_section('[m32r-splice-into-function]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_M32R)
    data = _be32(target) + payload
    b.add_section('[m32r-relocate-section]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_jump_to_body_elf(vma=0x1000, jump_target=0x8000):
    b = ELFBuilder(EM_SH)
    b.add_section('[sh-jump-to-body]', _be32(jump_target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_splice_elf(vma=0x1000, target_fn=0x5000, target_ret=0x6000):
    b = ELFBuilder(EM_SH)
    data = _be32(target_fn) + _be32(target_ret)
    b.add_section('[sh-splice-into-function]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_SH)
    data = _be32(target) + payload
    b.add_section('[sh-relocate-section]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_generic_patch_elf(vma=0x1000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_M32R)
    b.add_section('generic_section', payload, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_invalid_size_elf():
    """[m32r-bl] with 8 bytes instead of required 4 — triggers size error."""
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-bl]', b'\x00' * 8, sh_flags=SHF_ALLOC, sh_addr=0x1000)
    return b.build()


def make_incompatible_method_elf():
    """[sh-jump-to-body] section used with mmc-m32r ECU — triggers incompatible error."""
    b = ELFBuilder(EM_M32R)
    b.add_section('[sh-jump-to-body]', b'\x00' * 4, sh_flags=SHF_ALLOC, sh_addr=0x1000)
    return b.build()


def make_bad_sh_vma_elf():
    """[sh-jump-to-body] with vma % 4 == 1 — triggers invalid VMA error."""
    b = ELFBuilder(EM_SH)
    b.add_section('[sh-jump-to-body]', b'\x00' * 4, sh_flags=SHF_ALLOC, sh_addr=0x1001)
    return b.build()
