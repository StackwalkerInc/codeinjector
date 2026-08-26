# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

import struct

from elf_builder import EM_SH
from fixtures_seed import (make_seed_elf, make_multi_seed_elf,
                           make_seed_with_desc_elf, seed_record,
                           SEED_KIND_AXIS, SEED_KIND_MAP3D8)


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
    assert 'not a multiple of' in r.stderr


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


def test_seed_rejected_on_sh2(run_ci):
    # data_seed is m32r-only; apply_records must reject it outright on
    # mmc-sh2 rather than silently skip seeding.
    elf = make_seed_elf(
        records=[seed_record(kind=SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 16,
        machine=EM_SH,
    )
    r, rom = run_ci('mmc-sh2', elf)
    assert r.returncode != 0
    assert 'data_seed is only supported on m32r' in r.stderr


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
    assert 'fewer than stock' in r.stderr


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
    assert 'not ascending' in r.stderr


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
    assert 'overflows u16' in r.stderr


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
    assert 'need at least 2' in r.stderr


def test_axis_seed_rejects_no_sized_symbol(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10, 20, 30, 40])
    rom = _rom_with(tmp_path, 0x3000, stock)
    # The destination symbol exists at 0x2000 but declares st_size == 0,
    # so symbol_size_at can't find a sized symbol there.
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 20, sym_size=0,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'no sized symbol' in r.stderr


def test_axis_seed_rejects_overrunning_section(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10, 20, 30, 40])
    rom = _rom_with(tmp_path, 0x3000, stock)
    # The destination symbol claims 32 bytes, but its section only holds 16.
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 16, sym_size=32,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'overruns its section' in r.stderr


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
    assert 'which is not' in r.stderr


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
    assert 'fewer than stock' in r.stderr


def test_map_seed_rejects_xsize_zero(binary, tmp_path):
    from conftest import run
    # xsize byte in the stock map header is 0.
    stock_map = _map3d8(3, 0, -1, -2, xsize=0, rows=[])
    rom = _rom_with(tmp_path, 0x3000, stock_map)
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=0x3000,
                             src_yaxis=0x3800)],
        payload_addr=0x2000, payload=b'\x00' * 19,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'declares xsize 0' in r.stderr


def test_map_seed_rejects_yaxis_size_zero(binary, tmp_path):
    from conftest import run
    stock_map = _map3d8(3, 0, -1, -2, xsize=3, rows=[[1, 2, 3], [4, 5, 6]])
    # Stock y-axis declares 0 entries.
    stock_axis = _axis(dst=-2, src=-3, values=[])
    rom = _rom_with_many(tmp_path, [(0x3000, stock_map), (0x3800, stock_axis)])
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=0x3000,
                             src_yaxis=0x3800)],
        payload_addr=0x2000, payload=b'\x00' * 19,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'declares size 0' in r.stderr


def test_map_seed_rejects_header_past_end_of_rom(binary, tmp_path):
    from conftest import run
    # Stock map header (7 bytes) starting at 0xA in a 16-byte ROM runs off
    # the end before the xsize byte at offset +6 can even be read.
    stock_map_at = 0xA
    rom = _rom_with(tmp_path, stock_map_at, b'', size=0x10)
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=stock_map_at,
                             src_yaxis=0)],
        payload_addr=0x2000, payload=b'\x00' * 19,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'header runs past end of ROM' in r.stderr


def test_map_seed_rejects_body_past_end_of_rom(binary, tmp_path):
    from conftest import run
    stock_axis_at, stock_map_at = 0x0, 0x10
    stock_axis = _axis(dst=-1, src=-2, values=[10, 20])   # stock_ys = 2
    # Header + exactly one xsize=3 row; the ROM ends right after it, so the
    # second stock row (needed once y >= 1) runs past the end.
    stock_map = _map3d8(3, 0, -1, -2, xsize=3, rows=[[1, 2, 3]])
    rom = _rom_with_many(
        tmp_path, [(stock_axis_at, stock_axis), (stock_map_at, stock_map)],
        size=stock_map_at + len(stock_map))
    # New map: same shape as stock (7 + 3*2 = 13 bytes) -- no shrink, no
    # growth, but the clamped-replication read of stock row 1 still needs
    # bytes that were never in the (truncated) ROM.
    elf = make_seed_elf(
        records=[seed_record(SEED_KIND_MAP3D8, dst=0x2000, src=stock_map_at,
                             src_yaxis=stock_axis_at)],
        payload_addr=0x2000, payload=b'\x00' * 13,
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'body runs past end of ROM' in r.stderr


def test_axis_and_map_row_counts_must_agree(binary, tmp_path):
    from conftest import run
    stock_axis_at, stock_map_at = 0x3000, 0x3800
    stock_axis = _axis(dst=-1, src=-2, values=[10, 20])
    stock_map = _map3d8(3, 0, -1, -2, xsize=3, rows=[[1, 2, 3], [4, 5, 6]])
    rom = _rom_with_many(tmp_path, [(stock_axis_at, stock_axis),
                                    (stock_map_at, stock_map)])

    # Both records seed from the same stock y-axis (stock_axis_at), so the
    # ECU's calc_axis will index the map body with the axis's row index at
    # runtime -- but the axis is seeded to 4 entries (6 + 2*4 = 14 bytes)
    # while the map is seeded to 3 rows (7 + 3*3 = 16 bytes). The two
    # macros in the C source disagree, and nothing else would catch it.
    elf = make_multi_seed_elf(
        records=[
            seed_record(SEED_KIND_AXIS, dst=0x2000, src=stock_axis_at),
            seed_record(SEED_KIND_MAP3D8, dst=0x2100, src=stock_map_at,
                        src_yaxis=stock_axis_at),
        ],
        payloads=[
            (0x2000, b'\x00' * 14, 'axis17'),
            (0x2100, b'\x00' * 16, 'map4fb5c'),
        ],
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert '0x2000' in r.stderr and '0x2100' in r.stderr
    assert '4 entries' in r.stderr and '3 rows' in r.stderr


def test_axis_declared_size_disagrees_with_symbol_size(binary, tmp_path):
    from conftest import run
    stock = _axis(dst=-1, src=-2, values=[10, 20, 30, 40])
    rom = _rom_with(tmp_path, 0x3000, stock)
    # Destination symbol is 20 bytes -> new_n = (20 - 6) / 2 = 7, but the
    # data_desc descriptor for the same destination declares elements="8":
    # the array literal that sizes the symbol and the descriptor's size
    # argument were edited independently and now disagree.
    elf = make_seed_with_desc_elf(
        records=[seed_record(SEED_KIND_AXIS, dst=0x2000, src=0x3000)],
        payload_addr=0x2000, payload=b'\x00' * 20,
        desc_str='axis;AxName;scl;8',
    )
    r, _ = run(binary, 'mmc-m32r', rom, elf, tmp_path / 'o.bin', tmp_path)
    assert r.returncode != 0
    assert 'will hold 7 entries' in r.stderr
    assert 'declares elements="8"' in r.stderr


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
