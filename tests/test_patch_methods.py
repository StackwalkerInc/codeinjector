# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

import struct
import subprocess
import pytest
from fixtures_patch import (
    make_m32r_bl_elf, make_m32r_bra_elf, make_m32r_ld24_r0_elf, make_m32r_ld24_r4_elf,
    make_m32r_lduh_r1_elf, make_m32r_splice_elf, make_m32r_relocate_elf,
    make_sh_jump_to_body_elf, make_sh_splice_elf, make_sh_relocate_elf,
    make_generic_patch_elf, make_invalid_size_elf,
    make_incompatible_method_elf, make_bad_sh_vma_elf,
)


# ---------- M32R ----------

def test_m32r_bl(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_bl_elf(vma=0x1000, target=0x2000))
    assert r.returncode == 0
    # BL: 0xfe000000 + ((0x2000 - 0x1000) / 4) = 0xfe000400
    assert rom[0x1000:0x1004] == bytes([0xfe, 0x00, 0x04, 0x00])
    assert '<scaling name="[m32r-bl] _scaling"' in r.stdout
    assert '<table name="[m32r-bl]"' in r.stdout


def test_m32r_bra(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_bra_elf(vma=0x1000, target=0x2000))
    assert r.returncode == 0
    # BRA: 0xff000000 + ((0x2000 - 0x1000) / 4) = 0xff000400
    assert rom[0x1000:0x1004] == bytes([0xff, 0x00, 0x04, 0x00])
    assert '<table name="[m32r-bra]"' in r.stdout


def test_m32r_bra_backward(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_bra_elf(vma=0x2000, target=0x1000))
    assert r.returncode == 0
    # (0x1000 - 0x2000) / 4 = -0x400, masked to 24 bits = 0xfffc00
    assert rom[0x2000:0x2004] == bytes([0xff, 0xff, 0xfc, 0x00])


def test_m32r_ld24_r0(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_ld24_r0_elf(vma=0x1000, target=0x1234))
    assert r.returncode == 0
    # 0xe0000000 + 0x1234
    assert rom[0x1000:0x1004] == bytes([0xe0, 0x00, 0x12, 0x34])


def test_m32r_ld24_r4(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_ld24_r4_elf(vma=0x1000, target=0x1234))
    assert r.returncode == 0
    # 0xe0000000 + 0x1234 + (4 << 24) = 0xe4001234
    assert rom[0x1000:0x1004] == bytes([0xe4, 0x00, 0x12, 0x34])


def test_m32r_lduh_r1(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_lduh_r1_elf(vma=0x1000, target=0x80009000))
    assert r.returncode == 0
    # disp16 = 0x80009000 - 0x80008000 = 0x1000
    # patch = 0xa0bd0000 + (1<<24) + 0x1000 = 0xa1bd1000
    assert rom[0x1000:0x1004] == bytes([0xa1, 0xbd, 0x10, 0x00])


def test_m32r_splice(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_splice_elf(vma=0x1000, target_fn=0x2000, target_ret=0x3000))
    assert r.returncode == 0
    # BL to 0x2000: 0xfe000000 + ((0x2000-0x1000)/4) = 0xfe000400
    # BCL to 0x3000: 0xff000000 + ((0x3000-0x1004)/4) = 0xff000000 + 0x7ff = 0xff0007ff
    assert rom[0x1000:0x1008] == bytes([0xfe, 0x00, 0x04, 0x00, 0xff, 0x00, 0x07, 0xff])


def test_m32r_relocate(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    # Data copied to ROM[0x2000]; first 4 bytes are the target address itself
    assert rom[0x2000:0x2008] == b'\x00\x00\x20\x00\xde\xad\xbe\xef'


# ---------- SH ----------

def test_sh_jump_to_body_aligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_jump_to_body_elf(vma=0x1000, jump_target=0x8000))
    assert r.returncode == 0
    expected = bytes([0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
                      0x00, 0x00, 0x80, 0x00])
    assert rom[0x1000:0x100c] == expected


def test_sh_jump_to_body_misaligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_jump_to_body_elf(vma=0x1002, jump_target=0x8000))
    assert r.returncode == 0
    # NOP prefix at 0x1002, then 12-byte body at 0x1004
    assert rom[0x1002:0x1004] == bytes([0x00, 0x09])
    assert rom[0x1004:0x1010] == bytes([0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
                                        0x00, 0x00, 0x80, 0x00])


def test_sh_splice_aligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_splice_elf(vma=0x1000, target_fn=0x5000, target_ret=0x6000))
    assert r.returncode == 0
    expected = bytes([
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
        0x00, 0x00, 0x50, 0x00,
        0x00, 0x00, 0x60, 0x00,
    ])
    assert rom[0x1000:0x1018] == expected


def test_sh_splice_misaligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_splice_elf(vma=0x1002, target_fn=0x5000, target_ret=0x6000))
    assert r.returncode == 0
    assert rom[0x1002:0x1004] == bytes([0x00, 0x09])
    expected_body = bytes([
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
        0x00, 0x00, 0x50, 0x00,
        0x00, 0x00, 0x60, 0x00,
    ])
    assert rom[0x1004:0x101c] == expected_body


def test_sh_relocate(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    assert rom[0x2000:0x2008] == b'\x00\x00\x20\x00\xde\xad\xbe\xef'


def test_generic_patch(run_ci):
    r, rom = run_ci('mmc-m32r', make_generic_patch_elf(vma=0x1000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    assert rom[0x1000:0x1004] == b'\xde\xad\xbe\xef'


# ---------- Error branches in inject_section ----------

def test_invalid_bl_size(binary, rom, out, tmp_path):
    """[m32r-bl] with 8 bytes → 'Invalid bl injection instruction section size'."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_invalid_size_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Invalid bl injection instruction section size' in r.stderr


def test_incompatible_method(binary, rom, out, tmp_path):
    """[sh-jump-to-body] with mmc-m32r → 'patch_method incompatible'."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_incompatible_method_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'patch_method incompatible' in r.stderr


def test_bad_sh_vma(binary, rom, out, tmp_path):
    """[sh-jump-to-body] with vma%4==1 → 'Invalid vma'."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_bad_sh_vma_elf())
    r = subprocess.run([binary, 'mmc-sh2', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Invalid vma' in r.stderr
