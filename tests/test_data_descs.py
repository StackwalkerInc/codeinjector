# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

import struct
import subprocess
import pytest
from fixtures_datadesc import (
    make_data_desc_elf, make_no_symtab_datadesc_elf, make_missing_data_sym_elf,
)


def _run_datadesc(binary, rom, out, tmp_path, descriptors, ecu='mmc-m32r', **kw):
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_data_desc_elf(descriptors, **kw))
    r = subprocess.run([binary, ecu, str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    return r


def test_value(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_val', 'desc_str': 'value;Cat;ValName;scl', 'data_addr': 0x1234},
    ])
    assert r.returncode == 0
    assert 'type="1D"' in r.stdout
    assert 'ValName' in r.stdout
    assert '1234' in r.stdout


def test_array(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_arr', 'desc_str': 'array;Cat;ArrName;scl;<table inline/>', 'data_addr': 0x2000},
    ])
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout
    assert 'ArrName' in r.stdout
    assert '<table inline/>' in r.stdout


def test_3darray(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_3a', 'desc_str': '3darray;Cat;3DArr;scl;<xaxis/>;< yaxis/>', 'data_addr': 0x3000},
    ])
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout
    assert '3DArr' in r.stdout


def test_2dmap8(binary, rom, out, tmp_path):
    # Map descriptor references axis symbol 'd_ax8'; data sym for axis = 'ax8'
    descriptors = [
        {'desc_sym': 'd_m8',  'desc_str': '2dmap8;Cat;Map8;map_scl;d_ax8', 'data_addr': 0x2000},
        {'desc_sym': 'd_ax8', 'desc_str': 'axis;AxName;ax_scl;8',           'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout
    assert 'Map8' in r.stdout
    assert 'AxName' in r.stdout


def test_3dmap8(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m38',  'desc_str': '3dmap8;Cat;Map38;scl;d_xax;d_yax', 'data_addr': 0x2000},
        {'desc_sym': 'd_xax',  'desc_str': 'axis;XAx;x_scl;4',                  'data_addr': 0x3000},
        {'desc_sym': 'd_yax',  'desc_str': 'axis;YAx;y_scl;8',                  'data_addr': 0x4000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout
    assert 'Map38' in r.stdout


def test_2dmap16(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m16',  'desc_str': '2dmap16;Cat;Map16;scl;d_a16', 'data_addr': 0x2000},
        {'desc_sym': 'd_a16',  'desc_str': 'axis;A16;a16_scl;4',           'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout


def test_3dmap16(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m316', 'desc_str': '3dmap16;Cat;Map316;scl;d_x16;d_y16', 'data_addr': 0x2000},
        {'desc_sym': 'd_x16',  'desc_str': 'axis;X16;x16_scl;4',                   'data_addr': 0x3000},
        {'desc_sym': 'd_y16',  'desc_str': 'axis;Y16;y16_scl;8',                   'data_addr': 0x4000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout


def test_axis_skipped(binary, rom, out, tmp_path):
    """Standalone axis descriptor produces no output (skipped explicitly)."""
    descriptors = [
        {'desc_sym': 'd_ax', 'desc_str': 'axis;AxName;scl;8', 'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'AxName' not in r.stdout


def test_axisex_skipped(binary, rom, out, tmp_path):
    """Standalone axisex descriptor produces no output (skipped explicitly)."""
    descriptors = [
        {'desc_sym': 'd_axex', 'desc_str': 'axisex;AxExName;scl', 'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'AxExName' not in r.stdout


def test_axisex_in_map(binary, tmp_path):
    """Axis with name[1]=='X' triggers emit_axis_ex_desc; reads axis size from ROM."""
    # d_Xax has 'X' at index 1 → axisex path; data sym = 'ax' (d_Xax[2:])
    # ROM[data_addr + 2*short_pointer_size] = big-endian uint16 axis size = 5
    # For M32R: short_pointer_size=2, so offset = data_addr + 4
    rom_data = bytearray(0x10000)
    struct.pack_into('>H', rom_data, 0x3004, 5)
    rom_path = tmp_path / 'rom.bin'
    rom_path.write_bytes(bytes(rom_data))

    descriptors = [
        {'desc_sym': 'd_m8x', 'desc_str': '2dmap8;Cat;MapX;scl;dXax', 'data_addr': 0x2000},
        {'desc_sym': 'dXax',  'desc_str': 'axisex;XAxName;ax_scl',     'data_addr': 0x3000},
    ]
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_data_desc_elf(descriptors))
    r = subprocess.run(
        [binary, 'mmc-m32r', str(rom_path), str(inj), str(tmp_path / 'out.bin')],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert 'XAxName' in r.stdout
    assert 'elements="5"' in r.stdout


def test_unknown_desc_type(binary, rom, out, tmp_path):
    """Unknown type → <comment> output."""
    descriptors = [
        {'desc_sym': 'd_unk', 'desc_str': 'unknown_type;Cat;Name;scl', 'data_addr': 0x1000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert '<comment' in r.stdout


def test_no_symtab(binary, rom, out, tmp_path):
    """data_desc ELF with no .symtab → storage_needed==0 branch, no output."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_no_symtab_datadesc_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0


def test_missing_data_sym(binary, rom, out, tmp_path):
    """Desc symbol whose data symbol is absent → comment 'unable to find data symbol'."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_missing_data_sym_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert 'unable to find data symbol' in r.stdout


def test_value_nonzero_section_base(binary, rom, out, tmp_path):
    """data_desc section linked at a nonzero address (as real ROM builds do):
    descriptor symbol st_value is absolute (section_addr + offset), so the
    offset into section_data must be computed relative to the section base."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_data_desc_elf(
        [{'desc_sym': 'd_val', 'desc_str': 'value;Cat;ValName;scl', 'data_addr': 0x1234}],
        section_addr=0x60000,
    ))
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert "unable to find desc string" not in r.stdout
    assert 'type="1D"' in r.stdout
    assert 'ValName' in r.stdout
    assert '1234' in r.stdout


def test_axis_missing_symbols(binary, rom, out, tmp_path):
    """Map descriptor references axis symbol that doesn't exist → fallback <table> tag."""
    descriptors = [
        {'desc_sym': 'd_m8m', 'desc_str': '2dmap8;Cat;MapMiss;scl;d_Zmissing', 'data_addr': 0x2000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    # emit_axis_desc falls back to: <table name="d_Zmissing" type="Y Axis"/>
    assert 'd_Zmissing' in r.stdout
