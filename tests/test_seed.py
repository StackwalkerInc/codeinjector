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


def _axis(dst, src, values):
    """Pack a stock axis descriptor."""
    return struct.pack('>hhH', dst, src, len(values)) + struct.pack(
        '>%dH' % len(values), *values)


def _rom_with(tmp_path, at, blob, size=0x10000):
    p = tmp_path / 'rom.bin'
    buf = bytearray(b'\x00' * size)
    buf[at:at + len(blob)] = blob
    p.write_bytes(bytes(buf))
    return p


def test_axis_seed_copies_and_extrapolates(binary, tmp_path):
    from conftest import run
    stock_at = 0x3000
    stock = _axis(dst=-13336, src=-13344, values=[10, 20, 30, 40])
    rom = _rom_with(tmp_path, stock_at, stock)

    # New axis: 4 stock entries + 3 extrapolated = 7; header 6 + 2*7 = 20 bytes
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=stock_at)],
        payload_addr=0x2000, payload=b'\x00' * 20,
    )
    out = tmp_path / 'out.bin'
    r, romout = run(binary, 'mmc-m32r', rom, elf, out, tmp_path)
    assert r.returncode == 0, r.stderr

    got = struct.unpack('>hhH7H', romout[0x2000:0x2014])
    assert got[0] == -13336          # dst copied
    assert got[1] == -13344          # src copied
    assert got[2] == 7               # new size written
    # delta = 40 - 30 = 10
    assert list(got[3:]) == [10, 20, 30, 40, 50, 60, 70]


def test_axis_seed_rejects_shrinking(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10, 20, 30, 40])
    rom = _rom_with(tmp_path, 0x3000, stock)
    # payload holds only 3 entries: 6 + 2*3 = 12 bytes
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 12,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def test_axis_seed_rejects_non_ascending_tail(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10, 20, 30, 30])
    rom = _rom_with(tmp_path, 0x3000, stock)
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 20,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def test_axis_seed_rejects_overflow(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[0xff00, 0xff80])
    rom = _rom_with(tmp_path, 0x3000, stock)
    # 2 stock + 2 extrapolated -> 0x10000, overflows u16
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 14,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def test_axis_seed_rejects_single_entry_stock(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10])
    rom = _rom_with(tmp_path, 0x3000, stock)
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 12,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def _map3d8(type_, offset, xsrc, ysrc, xsize, rows):
    """Pack a stock 3dmap8. rows is a list of `xsize`-length lists."""
    body = bytes(v for row in rows for v in row)
    return struct.pack('>BBhhB', type_, offset, xsrc, ysrc, xsize) + body


def _rom_with_many(tmp_path, blobs, size=0x10000):
    p = tmp_path / 'rom.bin'
    buf = bytearray(b'\x00' * size)
    for at, blob in blobs:
        buf[at:at + len(blob)] = blob
    p.write_bytes(bytes(buf))
    return p


def test_map_seed_copies_header_and_replicates_last_row(binary, tmp_path):
    from conftest import run
    stock_map_at, stock_axis_at = 0x3000, 0x3800
    stock_map = _map3d8(3, 20, -13338, -13336, xsize=3,
                        rows=[[1, 2, 3], [4, 5, 6]])
    stock_axis = _axis(dst=-13336, src=-13344, values=[10, 20])
    rom = _rom_with_many(tmp_path, [(stock_map_at, stock_map),
                                    (stock_axis_at, stock_axis)])

    # New map: xsize 3, ysize 4 -> 7 + 12 = 19 bytes
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000,
                             src=stock_map_at, src_yaxis=stock_axis_at)],
        payload_addr=0x2000, payload=b'\x00' * 19,
    )
    r, romout = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode == 0, r.stderr

    hdr = struct.unpack('>BBhhB', romout[0x2000:0x2007])
    assert hdr == (3, 20, -13338, -13336, 3)   # header copied verbatim
    body = list(romout[0x2007:0x2013])
    assert body == [1, 2, 3,
                    4, 5, 6,
                    4, 5, 6,    # last stock row replicated
                    4, 5, 6]


def test_map_seed_rejects_indivisible_size(binary, tmp_path):
    from conftest import run
    stock_map = _map3d8(3, 0, -1, -2, xsize=3, rows=[[1, 2, 3], [4, 5, 6]])
    stock_axis = _axis(dst=-2, src=-3, values=[10, 20])
    rom = _rom_with_many(tmp_path, [(0x3000, stock_map), (0x3800, stock_axis)])
    # 7 + 11 is not 7 + 3*n
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=0x3000,
                             src_yaxis=0x3800)],
        payload_addr=0x2000, payload=b'\x00' * 18,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def test_map_seed_rejects_shrinking(binary, tmp_path):
    from conftest import run
    stock_map = _map3d8(3, 0, -1, -2, xsize=3, rows=[[1, 2, 3], [4, 5, 6]])
    stock_axis = _axis(dst=-2, src=-3, values=[10, 20])
    rom = _rom_with_many(tmp_path, [(0x3000, stock_map), (0x3800, stock_axis)])
    # ysize 1 < stock ysize 2
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=0x3000,
                             src_yaxis=0x3800)],
        payload_addr=0x2000, payload=b'\x00' * 10,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0


def test_seeded_bytes_appear_in_emitted_xml(binary, tmp_path):
    from conftest import run
    stock_map = _map3d8(3, 20, -13338, -13336, xsize=3, rows=[[1, 2, 3], [4, 5, 6]])
    stock_axis = _axis(dst=-13336, src=-13344, values=[10, 20])
    rom = _rom_with_many(tmp_path, [(0x3000, stock_map), (0x3800, stock_axis)])
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=0x3000,
                             src_yaxis=0x3800)],
        payload_addr=0x2000, payload=b'\x00' * 19,
    )
    r, romout = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode == 0, r.stderr
    patched_hex = romout[0x2000:0x2013].hex()
    assert patched_hex in r.stdout.replace('\n', '')
