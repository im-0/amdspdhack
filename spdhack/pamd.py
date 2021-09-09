# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Parser AMD BIOS images.
"""
import copy
import itertools
from collections import OrderedDict
import os
from typing import Any, Iterable

import spdhack.chksum as chksum
import spdhack.pspd as pspd
import spdhack.strct as strct


# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L204
_AMD_FW_HDR_MAGIC = bytes.fromhex('aa55aa55')

# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/Documentation/soc/amd/psp_integration.md
# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L84
_AMD_FW_HDR_DESCRIPTION = (
    # typedef struct _embedded_firmware {
    # 	uint32_t signature; /* 0x55aa55aa */
    ('I', 'signature', strct.IntHex(8)),
    # 	uint32_t imc_entry;
    ('I', 'imc_entry', strct.IntHex(8)),
    # 	uint32_t gec_entry;
    ('I', 'gec_entry', strct.IntHex(8)),
    # 	uint32_t xhci_entry;
    ('I', 'xhci_entry', strct.IntHex(8)),
    # 	uint32_t psp_entry;
    ('I', 'psp_entry', strct.IntHex(8)),
    # 	uint32_t comboable;
    ('I', 'comboable', strct.IntHex(8)),
    # 	uint32_t bios0_entry;
    ('I', 'bios0_entry', strct.IntHex(8)),
    # 	uint32_t bios1_entry;
    ('I', 'bios1_entry', strct.IntHex(8)),
    # 	uint32_t bios2_entry;
    ('I', 'bios2_entry', strct.IntHex(8)),
    # 	struct second_gen_efs efs_gen;
    ('I', 'efs_gen', strct.IntHex(8)),
    # 	uint32_t bios3_entry;
    ('I', 'bios3_entry', strct.IntHex(8)),
    # 	uint32_t reserved_2Ch;
    # 	uint32_t promontory_fw_ptr;
    # 	uint32_t lp_promontory_fw_ptr;
    # 	uint32_t reserved_38h;
    # 	uint32_t reserved_3Ch;
    # 	uint8_t spi_readmode_f15_mod_60_6f;
    # 	uint8_t fast_speed_new_f15_mod_60_6f;
    # 	uint8_t reserved_42h;
    # 	uint8_t spi_readmode_f17_mod_00_2f;
    # 	uint8_t spi_fastspeed_f17_mod_00_2f;
    # 	uint8_t qpr_dummy_cycle_f17_mod_00_2f;
    # 	uint8_t reserved_46h;
    # 	uint8_t spi_readmode_f17_mod_30_3f;
    # 	uint8_t spi_fastspeed_f17_mod_30_3f;
    # 	uint8_t micron_detect_f17_mod_30_3f;
    # 	uint8_t reserved_4Ah;
    # 	uint8_t reserved_4Bh;
    # 	uint32_t reserved_4Ch;
    # } __attribute__((packed, aligned(16))) embedded_firmware;
)
_AMD_FW_HDR = strct.Struct('Embedded Firmware Header', _AMD_FW_HDR_DESCRIPTION)

# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L116
_PSP_DIR_HDR_MAGIC = b'$PSP'
_PSP_DIR_HDR_DESCRIPTION = (
    # typedef struct _psp_directory_header {
    # 	uint32_t cookie;
    ('I', 'cookie', strct.IntBytes(4)),
    # 	uint32_t checksum;
    ('I', 'checksum', strct.IntHex(8)),
    # 	uint32_t num_entries;
    ('I', 'num_entries', None),
    # 	uint32_t additional_info;
    ('I', 'additional_info', strct.IntHex(8)),
    # } __attribute__((packed, aligned(16))) psp_directory_header;
)
_PSP_DIR_HDR = strct.Struct('PSP Directory Table Header', _PSP_DIR_HDR_DESCRIPTION)

# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L123
_PSP_DIR_ENTRY_DESCRIPTION = (
    # typedef struct _psp_directory_entry {
    # 	uint8_t type;
    ('B', 'type', strct.IntHex(2)),
    # 	uint8_t subprog;
    ('B', 'subprog', strct.IntHex(2)),
    # 	uint16_t rsvd;
    ('H', 'rsvd', strct.IntHex(4)),
    # 	uint32_t size;
    ('I', 'size', None),
    # 	uint64_t addr; /* or a value in some cases */
    ('Q', 'addr', strct.IntHex(16)),
    # } __attribute__((packed)) psp_directory_entry;
)
_PSP_DIR_ENTRY = strct.Struct('PSP Directory Table Entry', _PSP_DIR_ENTRY_DESCRIPTION)

# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L159
_BIOS_DIR_HDR_MAGIC_PRIMARY = b'$BHD'
_BIOS_DIR_HDR_MAGIC_SECONDARY = b'$BL2'
_BIOS_DIR_HDR_MAGIC = (_BIOS_DIR_HDR_MAGIC_PRIMARY, _BIOS_DIR_HDR_MAGIC_SECONDARY)
_BIOS_DIR_HDR_DESCRIPTION = (
    # typedef struct _bios_directory_hdr {
    # 	uint32_t cookie;
    ('I', 'cookie', strct.IntBytes(4)),
    # 	uint32_t checksum;
    ('I', 'checksum', strct.IntHex(8)),
    # 	uint32_t num_entries;
    ('I', 'num_entries', None),
    # 	uint32_t additional_info;
    ('I', 'additional_info', strct.IntHex(8)),
    # } __attribute__((packed, aligned(16))) bios_directory_hdr;
)
_BIOS_DIR_HDR = strct.Struct('BIOS Directory Table Header', _BIOS_DIR_HDR_DESCRIPTION)

# https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.h#L166
_BIOS_DIR_ENTRY_DESCRIPTION = (
    # typedef struct _bios_directory_entry {
    # 	uint8_t type;
    ('B', 'type', strct.IntHex(2)),
    # 	uint8_t region_type;
    ('B', 'region_type', strct.IntHex(2)),
    # 	int reset:1;
    # 	int copy:1;
    # 	int ro:1;
    # 	int compressed:1;
    # 	int inst:4;
    ('B', 'flags_reset_copy_ro_compressed_inst', strct.IntBin(8)),
    # 	uint8_t subprog; /* b[7:3] reserved */
    ('B', 'subprog', strct.IntBin(8)),
    # 	uint32_t size;
    ('I', 'size', None),
    # 	uint64_t source;
    ('Q', 'source', strct.IntHex(16)),
    # 	uint64_t dest;
    ('Q', 'dest', strct.IntHex(16)),
    # } __attribute__((packed)) bios_directory_entry;
)
_BIOS_DIR_ENTRY = strct.Struct('BIOS Directory Table Entry', _BIOS_DIR_ENTRY_DESCRIPTION)

# Source field points to the AGESA PSP Customization Block (APCB) data.
_BIOS_ENTRY_TYPE_APCB_DATA = 0x60
# Source field points to the backup copy of the AGESA PSP Customization Block (APCB) data.
_BIOS_ENTRY_TYPE_BACKUP_APCB_DATA = 0x68
# Pointer to BIOS Directory Table level 2.
_BIOS_ENTRY_TYPE_SECONDARY = 0x70

_INVALID_U32_OFF = (0, 0xffffffff)

_APCB_HDR_MAGIC = b'APCB'
_APCB_HDR_DESCRIPTION = (
    ('I', 'magic', strct.IntBytes(4)),
    ('H', 'unknown_0', strct.IntHex(4)),
    ('H', 'unknown_1', strct.IntHex(4)),
    ('I', 'size', None),
    ('H', 'random', strct.IntHex(4)),
    ('H', 'unknown_2', strct.IntHex(4)),
    ('B', 'checksum_u8', strct.IntHex(2)),
    ('15s', 'unknown_3', strct.BytesHex()),
)
_APCB_HDR = strct.Struct('AMD PSP Customization Block', _APCB_HDR_DESCRIPTION)

_APCB_SUB_HDR_DESCRIPTION = (
    ('I', 'magic', strct.IntBytes(4)),
    ('Q', 'unknown', strct.IntHex(16)),
    ('I', 'size', None),
)
_APCB_SUB_HDR = strct.Struct('Inside AMD PSP Customization Block', _APCB_SUB_HDR_DESCRIPTION)

_MEMG_HDR_MAGIC = int.from_bytes(b'MEMG', 'little')


def _find_all(image: bytes, magic: bytes) -> list[tuple[int, bytes]]:
    occurrences = []
    start = 0
    while (pos := image.find(magic, start)) >= 0:
        start = pos + 1
        occurrences.append((pos, magic))
    return occurrences


def _find_main_amd_fw_header_and_base_offset(image: bytes) -> tuple[OrderedDict[str, Any], int]:
    occurrences_list = []
    occurrences_list.extend(_find_all(image, _PSP_DIR_HDR_MAGIC))
    occurrences_list.extend(_find_all(image, _BIOS_DIR_HDR_MAGIC_PRIMARY))

    assert len(occurrences_list) >= 2, \
        f'Not enough magic values found: {len(occurrences_list)} < 2'

    occurrences_list.sort(key=lambda offset_and_magic: offset_and_magic[0])
    occurrences = OrderedDict(occurrences_list)

    start = 0
    results = []
    while (fw_hdr_pos := image.find(_AMD_FW_HDR_MAGIC, start)) >= 0:
        start = fw_hdr_pos + 1

        print(f'[ ] Possible {_AMD_FW_HDR.get_name()} at 0x{fw_hdr_pos:08x}')
        amd_fw_hdr = _AMD_FW_HDR.unpack(image[fw_hdr_pos:fw_hdr_pos + _AMD_FW_HDR.get_len()])

        offsets = [
            (amd_fw_hdr['psp_entry'], _PSP_DIR_HDR_MAGIC),
            (amd_fw_hdr['comboable'], _PSP_DIR_HDR_MAGIC),
            (amd_fw_hdr['bios0_entry'], _BIOS_DIR_HDR_MAGIC_PRIMARY),
            (amd_fw_hdr['bios1_entry'], _BIOS_DIR_HDR_MAGIC_PRIMARY),
            (amd_fw_hdr['bios2_entry'], _BIOS_DIR_HDR_MAGIC_PRIMARY),
            (amd_fw_hdr['bios3_entry'], _BIOS_DIR_HDR_MAGIC_PRIMARY),
        ]
        offsets = [
            offset_and_magic
            for offset_and_magic in offsets
            if offset_and_magic[0] not in _INVALID_U32_OFF
        ]

        if len(offsets) < 2:
            print(f'[ ] Not enough offsets to validate: {len(offsets)} < 2')
            continue

        offsets.sort(key=lambda offset_and_magic: offset_and_magic[0])
        if any(om_a[0] == om_b[0] for om_a, om_b in zip(offsets, offsets[1:])):
            print(f'[ ] Unable to validate because of duplicate offsets: {offsets}')
            continue

        # Try to match offsets from structure with found occurrences of magic vales.
        base_offset = None
        for occurrence_off in occurrences.keys():
            possible_base_offset = offsets[0][0] - occurrence_off
            if possible_base_offset < 0:
                continue
            for offset, magic in offsets:
                if occurrences.get(offset - possible_base_offset) != magic:
                    possible_base_offset = None
                    break
            if possible_base_offset is not None:
                assert base_offset is None, \
                    f'Another possible base offset for same header: 0x{possible_base_offset:08x}'
                base_offset = possible_base_offset
        if base_offset is None:
            print('[ ] No possible base offset')
            continue

        print(f'[ ] Got {_AMD_FW_HDR.get_name()} at 0x{fw_hdr_pos:08x}:')
        _AMD_FW_HDR.print(amd_fw_hdr)
        results.append((amd_fw_hdr, base_offset))

    assert len(results) > 0, \
        'No valid firmware headers'
    assert len(results) < 2, \
        f'Too many valid firmware headers: {len(results)} > 1'

    amd_fw_hdr, base_offset = results.pop()
    print(f'[*] Found offset of firmware in memory: {base_offset} (0x{base_offset:016x})')
    return amd_fw_hdr, base_offset


def _parse_psp_dir(
        image: bytes,
        offset: int) -> tuple[OrderedDict[str, Any], list[OrderedDict[str, Any]]]:
    magic = image[offset:offset + 4]
    assert magic == _PSP_DIR_HDR_MAGIC, \
        f'Wrong magic value in {_PSP_DIR_HDR.get_name()}: {magic!r} != {_PSP_DIR_HDR_MAGIC!r}'

    # Read header.
    psp_dir_hdr = _PSP_DIR_HDR.unpack(image[offset:offset + _PSP_DIR_HDR.get_len()])
    n_entries = psp_dir_hdr['num_entries']

    # Verify checksum.
    full_len = _PSP_DIR_HDR.get_len() + n_entries * _PSP_DIR_ENTRY.get_len()
    calc_checksum = chksum.fletcher32(image[offset + 8:offset + full_len])
    read_checksum = psp_dir_hdr['checksum']
    assert calc_checksum == read_checksum, \
        f'Checksum mismatch for {_PSP_DIR_HDR.get_name()}: {calc_checksum} != {read_checksum}'

    print(f'[ ] Got {_PSP_DIR_HDR.get_name()} at 0x{offset:08x}:')
    _PSP_DIR_HDR.print(psp_dir_hdr)

    # Read entries.
    entries = []
    for i in range(n_entries):
        psp_dir_entry = _PSP_DIR_ENTRY.unpack(
            image[
                offset + _PSP_DIR_HDR.get_len() + i * _PSP_DIR_ENTRY.get_len()
                :offset + _PSP_DIR_HDR.get_len() + (i + 1) * _PSP_DIR_ENTRY.get_len()
            ])
        print(f'[ ] Got {_PSP_DIR_ENTRY.get_name()} {i + 1}/{n_entries}:')
        _PSP_DIR_ENTRY.print(psp_dir_entry)
        entries.append(psp_dir_entry)

    return psp_dir_hdr, entries


def _parse_bios_dir(
        image: bytes,
        offset: int) -> Iterable[OrderedDict[str, Any]]:
    print(f'[ ] Trying to decode possible {_BIOS_DIR_HDR.get_name()} at 0x{offset:08x}')

    magic = image[offset:offset + 4]
    assert magic in _BIOS_DIR_HDR_MAGIC, \
        f'Wrong magic value in {_BIOS_DIR_HDR.get_name()}: {magic!r} not in {_BIOS_DIR_HDR_MAGIC!r}'

    # Read header.
    bios_dir_hdr = _BIOS_DIR_HDR.unpack(image[offset:offset + _BIOS_DIR_HDR.get_len()])
    n_entries = bios_dir_hdr['num_entries']

    # Verify checksum.
    full_len = _BIOS_DIR_HDR.get_len() + n_entries * _BIOS_DIR_ENTRY.get_len()
    calc_checksum = chksum.fletcher32(image[offset + 8:offset + full_len])
    read_checksum = bios_dir_hdr['checksum']
    assert calc_checksum == read_checksum, \
        f'Checksum mismatch for {_BIOS_DIR_HDR.get_name()}: {calc_checksum} != {read_checksum}'

    print(f'[ ] Got {_BIOS_DIR_HDR.get_name()} at 0x{offset:08x}:')
    _BIOS_DIR_HDR.print(bios_dir_hdr)

    # Read entries.
    for i in range(n_entries):
        bios_dir_entry = _BIOS_DIR_ENTRY.unpack(
            image[
                offset + _BIOS_DIR_HDR.get_len() + i * _BIOS_DIR_ENTRY.get_len()
                :offset + _BIOS_DIR_HDR.get_len() + (i + 1) * _BIOS_DIR_ENTRY.get_len()
            ])
        print(f'[ ] Got {_BIOS_DIR_ENTRY.get_name()} {i + 1}/{n_entries}:')
        _BIOS_DIR_ENTRY.print(bios_dir_entry)
        yield bios_dir_entry


def parse_apcb(
        image: bytes,
        offset: int,
        size: int,
        apcb_checksum_u8_initial: int,
        spd_checksums: bool) -> tuple[OrderedDict[str, Any], list[int]]:
    """
    Parse APCB.

    :param image: Binary image.
    :param offset: Offset to APCB section in image.
    :param size: Maximum size of APCB.
    :param apcb_checksum_u8_initial: Initial value for simple u8 checksum in APCB sections.
    :param spd_checksums: Whether to validate SPD checksums.
    :return: Parsed structures.
    """

    magic = image[offset:offset + 4]
    assert magic == _APCB_HDR_MAGIC, \
        f'Wrong magic of APCB section: {magic!r} != {_APCB_HDR_MAGIC!r}'

    # Read header.
    assert size >= _APCB_HDR.get_len(), \
        f'Not enough length for APCB header: {size} < {_APCB_HDR.get_len()}'
    apcb_hdr = _APCB_HDR.unpack(image[offset:offset + _APCB_HDR.get_len()])

    # Verify checksum.
    calc_checksum = chksum.simple8(
        image[offset:offset + apcb_hdr['size']],
        apcb_checksum_u8_initial)
    assert calc_checksum == 0, \
        f'U8 checksum mismatch in APCB: 0x{calc_checksum:02x} != 0; try running with ' \
        f'`--apcb-checksum-u8-initial 0x{(calc_checksum + apcb_checksum_u8_initial) & 0xff:02x}`'

    print(f'[*] Got {_APCB_HDR.get_name()} at 0x{offset:08x}:')
    _APCB_HDR.print(apcb_hdr)

    # Check that the rest is just padding bytes.
    assert all(byte == 0xff for byte in image[offset + apcb_hdr['size']:offset + size]), \
        'Extra data in padding'

    # Parse inner data headers.
    has_memg = False
    spd_offsets = []
    inner_size = apcb_hdr['size'] - _APCB_HDR.get_len()
    inner_off = offset + _APCB_HDR.get_len()
    while inner_size >= _APCB_SUB_HDR.get_len():
        apcb_sub_hdr = _APCB_SUB_HDR.unpack(image[inner_off:inner_off + _APCB_SUB_HDR.get_len()])
        print(f'[ ] Got {_APCB_SUB_HDR.get_name()} at 0x{inner_off:08x}:')
        _APCB_SUB_HDR.print(apcb_sub_hdr)

        if apcb_sub_hdr['magic'] == _MEMG_HDR_MAGIC:
            assert has_memg is False, \
                'Duplicate MEMG inside APCB'
            has_memg = True

            # Find SPDs.
            for spd_offset, _ in pspd.find_spds(
                    image, inner_off, apcb_sub_hdr['size'], spd_checksums):
                spd_offsets.append(spd_offset)

        inner_size -= apcb_sub_hdr['size']
        inner_off += apcb_sub_hdr['size']
    assert inner_size == 0, \
        f'Unable to parse inner data of APCB section, size mismatch: {inner_size} != 0'

    return apcb_hdr, spd_offsets


def _find_apcbs(
        image: bytes,
        amd_fw_hdr: OrderedDict[str, Any],
        base_offset: int,
        apcb_checksum_u8_initial: int,
        spd_checksums: bool) -> Iterable[tuple[int, int, list[int]]]:
    bios_dir_offs = [
        amd_fw_hdr['bios0_entry'],
        amd_fw_hdr['bios1_entry'],
        amd_fw_hdr['bios2_entry'],
        amd_fw_hdr['bios3_entry'],
    ]
    bios_dir_offs = [
        offset - base_offset
        for offset in bios_dir_offs
        if offset not in _INVALID_U32_OFF
    ]
    assert len(bios_dir_offs) > 0, 'No BIOS Directory Tables found'
    print(f'[ ] BIOS Directory Table offsets: {bios_dir_offs}')

    n_apcb_sections = 0
    while bios_dir_offs:
        next_off = bios_dir_offs.pop()

        for entry in _parse_bios_dir(image, next_off):
            if entry['type'] in (_BIOS_ENTRY_TYPE_APCB_DATA, _BIOS_ENTRY_TYPE_BACKUP_APCB_DATA):
                apcb_offset = entry['source'] - base_offset
                apcb_size = entry['size']
                assert len(image) - apcb_offset >= apcb_size, \
                    f'Wrong size of APCB section: {len(image) - apcb_offset} < {apcb_size}'

                apcb_hdr, spd_offsets = parse_apcb(
                    image, apcb_offset, apcb_size, apcb_checksum_u8_initial, spd_checksums)
                yield apcb_offset, apcb_hdr['size'], spd_offsets
                n_apcb_sections += 1
            elif entry['type'] == _BIOS_ENTRY_TYPE_SECONDARY:
                print('[ ] Found secondary BIOS Directory Table entry')
                bios_dir_offs.append(entry['source'] - base_offset)
    print(f'[*] Found {n_apcb_sections} APCB sections')


def _parse_base(image: bytes) -> tuple[OrderedDict[str, Any], int]:
    amd_fw_hdr, base_offset = _find_main_amd_fw_header_and_base_offset(image)

    if amd_fw_hdr['psp_entry'] not in _INVALID_U32_OFF:
        _parse_psp_dir(image, amd_fw_hdr['psp_entry'] - base_offset)
    if amd_fw_hdr['comboable'] not in _INVALID_U32_OFF:
        _parse_psp_dir(image, amd_fw_hdr['comboable'] - base_offset)

    return amd_fw_hdr, base_offset


def find_apcbs(
        image: bytes,
        apcb_checksum_u8_initial: int,
        spd_checksums: bool) -> Iterable[tuple[int, int, list[int]]]:
    """
    Find all APCB sections in image.

    :param image: Binary data.
    :param apcb_checksum_u8_initial: Initial value for simple u8 checksum in APCB sections.
    :param spd_checksums: Whether to validate SPD checksums.
    :return: Iterable over tuples (offset, size, SPD offsets).
    """

    amd_fw_hdr, base_offset = _parse_base(image)
    yield from _find_apcbs(
        image,
        amd_fw_hdr,
        base_offset,
        apcb_checksum_u8_initial,
        spd_checksums)


def _prepare_apcb_modifications(
        orig_image: bytes,
        new_spds: Iterable[tuple[int, int, int, OrderedDict[str, Any]]],
        orig_spd_checksums: bool
) -> tuple[
    list[tuple[int, OrderedDict[str, Any], frozenset[int]]],
    list[tuple[int, OrderedDict[str, Any]]]
]:
    affected_apcbs = {}
    replacements: OrderedDict[int, list[tuple[int, OrderedDict[str, Any]]]] = OrderedDict()

    for apcb_offset, apcb_size, spd_offset, spd in new_spds:
        if apcb_offset not in affected_apcbs:
            apcb, orig_spd_offsets = parse_apcb(
                orig_image,
                apcb_offset,
                apcb_size,
                0,
                orig_spd_checksums)
            affected_apcbs[apcb_offset] = apcb, frozenset(orig_spd_offsets)
            replacements[apcb_offset] = []

        assert spd_offset in affected_apcbs[apcb_offset][1], \
            f'SPD at 0x{spd_offset:08x} is not within APCB at 0x{apcb_offset:08x}'
        orig_spd = pspd.parse_spd(orig_image, spd_offset, orig_spd_checksums)
        if spd != orig_spd:
            replacements[apcb_offset].append((spd_offset, spd))

    return [
                (apcb_offset, *apcb_and_spd_offsets)
                for apcb_offset, apcb_and_spd_offsets in affected_apcbs.items()
                if len(replacements[apcb_offset]) > 0
           ], list(itertools.chain(*replacements.values()))


def _fix_apcb_checksum(image: bytes, offset: int, size: int) -> bytes:
    new_checksum = chksum.simple8(image[offset:offset + 16] + image[offset + 17:offset + size], 0)
    return image[:offset + 16] + bytes((new_checksum, )) + image[offset + 17:]


def replace_apcbs_spds(
        orig_image: bytes,
        new_spds: Iterable[tuple[int, int, int, OrderedDict[str, Any]]],
        orig_spd_checksums: bool) -> bytes:
    """
    Replace SPDs in AMD bios image inside APCB sections.

    :param orig_image: Original binary image.
    :param new_spds: Iterable over tuples containing SPD offsets and SPD structs.
    :param orig_spd_checksums: Whether to validate checksums of original SPDs before replacing.
    :return: New binary image.
    """

    print('[ ] Preparing replacements...')

    affected_apcbs, replacements = _prepare_apcb_modifications(
        orig_image,
        new_spds,
        orig_spd_checksums)

    print('[ ] Replacing SPDs...')
    new_image = orig_image
    for spd_off, new_spd in replacements:
        # Replace SPD.
        new_spd_bin = pspd.DDR4_SPD.pack(new_spd)
        new_image = new_image[:spd_off] + new_spd_bin + new_image[spd_off + pspd.DDR4_SPD_LEN:]

    assert len(new_image) == len(orig_image), \
        f'Logic error: image size changed ({len(new_image)} != {len(orig_image)})'

    print('[ ] Fixing APCB checksums...')
    for apcb_offset, apcb, _ in affected_apcbs:
        new_image = _fix_apcb_checksum(new_image, apcb_offset, apcb['size'])

    print('[ ] Validating modified APCBs...')
    for apcb_offset, apcb, spd_offsets in affected_apcbs:
        print(f'[ ] Validating modified APCB at 0x{apcb_offset:08x}')
        _, new_spd_offsets = parse_apcb(new_image, apcb_offset, apcb['size'], 0, True)
        assert spd_offsets == frozenset(new_spd_offsets), \
            f'APCB\'s SPD offsets changed: {spd_offsets} != {frozenset(new_spd_offsets)}'

    print(f'[*] Done, replaced {len(replacements)} SPDs inside {len(affected_apcbs)} APCBs')
    return new_image


def test_find_apcbs() -> None:
    """
    Test find_apcbs() on various dumps.

    :return: None.
    """

    images = (
        ('BIOS106.fd', 28),
        ('BIOS106.fd', 28),
        ('BIOS111.fd', 28),
        ('BOAPC305.fd', 28),
    )
    for image_name, expected_apcbs in images:
        print(f'! Trying to find APCBs in "{image_name}"...')
        with open(os.path.join('test-data', image_name), 'rb') as image_f:
            image = image_f.read()
        apcbs = list(find_apcbs(image, 0, True))
        assert len(apcbs) == expected_apcbs, \
            f'Wrong number of APCBs found: {len(apcbs)} != {expected_apcbs}'


def test_parse_apcb() -> None:
    """
    Test _parse_apcb on APCB images from Coreboot.

    :return: None.
    """

    images = (
        ('APCB_bilby.bin', 2),
        ('APCB_cereme.bin', 2),
        ('APCB_CZN_D4.bin', 0),  # DDR3
        ('APCB_mandolin.bin', 2),
        ('google-APCB_CZN_D4.bin', 0),  # DDR3
    )
    for image_name, n_spds in images:
        print(f'! Trying to parse APCB from "{image_name}"...')
        with open(os.path.join('test-data', 'apcb', image_name), 'rb') as image_f:
            image = image_f.read()
        apcb_hdr, spd_offsets = parse_apcb(image, 0, len(image), 0, True)
        assert apcb_hdr['size'] == len(image)
        assert len(spd_offsets) == n_spds


def test_find_apcbs_spds() -> None:
    """
    Test that find_apcbs() finds the same SPDs as full brute-force search.

    :return: None.
    """

    image_path = os.path.join('test-data', 'BIOS111.fd')
    with open(image_path, 'rb') as image_f:
        image = image_f.read()

    apcbs_spd_offsets = set()
    for _, _, spd_offsets in find_apcbs(image, 0, True):
        apcbs_spd_offsets |= set(spd_offsets)

    bf_offsets = set(spd_offset for spd_offset, _ in pspd.find_spds(image, 0, len(image), True))

    assert apcbs_spd_offsets == bf_offsets


def test_fix_apcb_checksum() -> None:
    """
    Test _fix_apcb_checksum() on APCB image from Coreboot.

    :return: None.
    """

    with open(os.path.join('test-data', 'apcb', 'APCB_bilby.bin'), 'rb') as image_f:
        image = image_f.read()
    orig_apcb, _ = parse_apcb(image, 0, len(image), 0, True)

    new_apcb = copy.deepcopy(orig_apcb)
    new_apcb['checksum_u8'] = 0
    new_image = _APCB_HDR.pack(new_apcb) + image[_APCB_HDR.get_len():]
    assert new_image != image

    try:
        parse_apcb(new_image, 0, len(new_image), 0, True)
    except AssertionError:
        # As expected, bad checksum.
        pass
    else:
        assert False, 'No error!'

    fixed_image = _fix_apcb_checksum(new_image, 0, len(new_image))
    # Should be no error.
    parse_apcb(fixed_image, 0, len(fixed_image), 0, True)

    assert fixed_image == image


def test_replace_apcbs_spds() -> None:
    """
    Test replace_apcbs_spds() on APCB image from Coreboot.

    :return: None.
    """

    with open(os.path.join('test-data', 'apcb', 'APCB_bilby.bin'), 'rb') as image_f:
        image = image_f.read()
    _, spd_offsets = parse_apcb(image, 0, len(image), 0, True)

    spd = pspd.parse_spd(image, spd_offsets[0], True)
    spd['module_part_number'] = b'testpn              '
    assert b'testpn' not in image

    new_image = replace_apcbs_spds(image, [(0, len(image), spd_offsets[0], spd)], True)
    assert new_image != image
    assert b'testpn' in new_image
