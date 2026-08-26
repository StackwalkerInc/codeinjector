# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

import struct

from fixtures_seed import (make_seed_elf, seed_record, SEED_KIND_AXIS,
                           SEED_KIND_MAP3D8)


def test_unknown_seed_kind_is_rejected(run_ci):
    elf = make_seed_elf(
        records=[seed_record(kind=99, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 16,
    )
    r, rom = run_ci('mmc-m32r', elf)
    assert r.returncode != 0
    assert 'seed' in r.stderr.lower()


def test_misaligned_seed_section_is_rejected(run_ci):
    elf = make_seed_elf(
        records=[b'\x00' * 12],   # not a multiple of 16
        payload_addr=0x2000, payload=b'\x00' * 16,
    )
    r, rom = run_ci('mmc-m32r', elf)
    assert r.returncode != 0


def test_unapplied_seed_record_is_rejected(run_ci):
    # dst points at an address that isn't inside any injected (loadable)
    # section at all -- the payload section lives at 0x2000, but the record
    # targets 0x9000, which is never a section's address range.
    elf = make_seed_elf(
        records=[seed_record(kind=SEED_KIND_AXIS, dst=0x9000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 16,
    )
    r, rom = run_ci('mmc-m32r', elf)
    assert r.returncode != 0
    assert 'seed' in r.stderr.lower()
