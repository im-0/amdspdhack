# SPDX-License-Identifier: AGPL-3.0-or-later
"""
CLI tool for modifying DDR4 SPD inside AMD BIOS images.
"""

import glob
import hashlib
import itertools
import os
import pprint

import click

from amdspdhack import pamd
from amdspdhack import pspd


def _get_prefix(dump_file_name: str) -> str:
    prefix = os.path.basename(dump_file_name)
    prefix = prefix.split('.', 1)[0]
    prefix = prefix.replace('-', '_')
    return prefix


def _extract_apcb_spds(  # pylint: disable=too-many-arguments
        dump_bin: bytes,
        out_dir: str,
        prefix: str,
        apcb_offset: int,
        apcb_size: int,
        spd_offsets: list[int],
        checksums: bool) -> None:
    for spd_offset in spd_offsets:
        spd = pspd.parse_spd(dump_bin, spd_offset, checksums)
        json_path = os.path.join(
            out_dir,
            f'{prefix}-apcb-{apcb_offset}-{apcb_size}-spd-{spd_offset}.json')
        print(f'[*] Writing "{json_path}"...')
        with open(json_path, 'w') as json_f:
            pspd.DDR4_SPD.json_dump(spd, json_f)


@click.command(
    name='extract-apcbs',
    help='Extract all APCB sections with contained SPDs from AMD BIOS image.\n'
         '\n'
         'DUMP - path to a dump of AMD BIOS flash.\n'
         'OUT_DIR - output directory for extracted files.\n',
)
@click.option(
    '--apcb-checksum-u8-initial',
    '-8',
    default='0x00',
    show_default=True,
    help='Initial value for simple 1-byte checksum used in APCB.',
)
@click.option(
    '--no-spd-checksums',
    '-C',
    is_flag=True,
    help='Do not validate SPD checksums.',
)
@click.argument(
    'dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'out-dir',
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True),
    required=True,
)
def _extract_apcbs(apcb_checksum_u8_initial: str, no_spd_checksums: bool, dump: str, out_dir: str):
    with open(dump, 'rb') as dump_f:
        dump_bin = dump_f.read()

    if apcb_checksum_u8_initial.startswith('0x'):
        apcb_checksum_u8_initial_val = int(apcb_checksum_u8_initial, 16)
    else:
        apcb_checksum_u8_initial_val = int(apcb_checksum_u8_initial)

    os.makedirs(out_dir, exist_ok=True)

    prefix = _get_prefix(dump)

    for apcb_offset, apcb_size, spd_offsets in \
            pamd.find_apcbs(dump_bin, apcb_checksum_u8_initial_val, not no_spd_checksums):
        bin_path = os.path.join(out_dir, f'{prefix}-apcb-{apcb_offset}-{apcb_size}.bin')
        print(f'[*] Writing "{bin_path}"...')
        with open(bin_path, 'wb') as apcb_f:
            apcb_f.write(dump_bin[apcb_offset:apcb_offset + apcb_size])
        _extract_apcb_spds(
            dump_bin,
            out_dir,
            prefix,
            apcb_offset,
            apcb_size,
            spd_offsets,
            not no_spd_checksums)


@click.command(
    name='parse-apcb',
    help='Parse APCB section from APCB image.\n'
         '\n'
         'APCB_DUMP - path to a dump of AMD BIOS flash.\n',
)
@click.option(
    '--apcb-checksum-u8-initial',
    '-8',
    default='0x00',
    show_default=True,
    help='Initial value for simple 1-byte checksum used in APCB.',
)
@click.option(
    '--no-spd-checksums',
    '-C',
    is_flag=True,
    help='Do not validate SPD checksums.',
)
@click.argument(
    'apcb_dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
def _parse_apcb(apcb_checksum_u8_initial: str, no_spd_checksums: bool, apcb_dump: str) -> None:
    if apcb_checksum_u8_initial.startswith('0x'):
        apcb_checksum_u8_initial_val = int(apcb_checksum_u8_initial, 16)
    else:
        apcb_checksum_u8_initial_val = int(apcb_checksum_u8_initial)

    with open(apcb_dump, 'rb') as apcb_dump_f:
        apcb_dump_bin = apcb_dump_f.read()

    pamd.parse_apcb(
        apcb_dump_bin,
        0,
        len(apcb_dump_bin),
        apcb_checksum_u8_initial_val,
        not no_spd_checksums)


def _analyze_apcb_checksum(
        apcbs: dict[str, bytes],
        spd_checksums: bool) -> tuple[dict[int, set[str]], dict[int, set[str]]]:
    by_u8_checksum: dict[int, set[str]] = {}
    by_random_val: dict[int, set[str]] = {}
    for apcb_path, apcb_bin in apcbs.items():
        apcb, _ = pamd.parse_apcb(apcb_bin, 0, len(apcb_bin), 0, spd_checksums)

        checksum = apcb['checksum_u8']
        if checksum not in by_u8_checksum:
            by_u8_checksum[checksum] = set()
        by_u8_checksum[checksum].add(apcb_path)

        random_val = apcb['random']
        if random_val not in by_random_val:
            by_random_val[random_val] = set()
        by_random_val[random_val].add(apcb_path)

    by_u8_checksum = dict(
        (checksum, paths)
        for checksum, paths in by_u8_checksum.items()
        if len(paths) > 1
    )

    by_random_val = dict(
        (random_val, paths)
        for random_val, paths in by_random_val.items()
        if len(paths) > 1
    )

    return by_u8_checksum, by_random_val


def _analyze_apcb_changes(apcbs: dict[str, bytes]) -> list[tuple[int, tuple[str, str]]]:
    by_n_changed_bits = []
    for (apcb_path_a, apcb_bin_a), (apcb_path_b, apcb_bin_b) in \
            itertools.combinations(apcbs.items(), 2):
        changed_bytes = (
            (byte_a ^ byte_b)
            for byte_a, byte_b in zip(apcb_bin_a, apcb_bin_b)
            if byte_a ^ byte_b != 0
        )
        n_changed_bits = sum(bin(byte).count('1') for byte in changed_bytes)
        by_n_changed_bits.append((n_changed_bits, (apcb_path_a, apcb_path_b)))

    by_n_changed_bits.sort(key=lambda n_bits_and_paths: n_bits_and_paths[0])
    return by_n_changed_bits


def _analyze_apcbs_minus_checksums(apcbs: dict[str, bytes]) -> list[list[str]]:
    by_sha1_of_data: dict[str, list[str]] = {}
    for apcb_path, apcb_bin in apcbs.items():
        apcb_minus_checksums = apcb_bin[:12] + apcb_bin[14:16] + apcb_bin[17:]
        apcb_hash = hashlib.sha1(apcb_minus_checksums).hexdigest()
        if apcb_hash not in by_sha1_of_data:
            by_sha1_of_data[apcb_hash] = []
        by_sha1_of_data[apcb_hash].append(apcb_path)

    same_data = [
        apcb_paths
        for apcb_paths in by_sha1_of_data.values()
        if len(apcb_paths) > 1
    ]
    return same_data


@click.command(
    name='analyze-apcbs',
    help='Analyze extracted APCB images.\n'
         '\n'
         'APCBS_DIR - path to directory with extracted APCB images.\n',
)
@click.option(
    '--no-spd-checksums',
    '-C',
    is_flag=True,
    help='Do not validate SPD checksums.',
)
@click.argument(
    'apcbs-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=False, readable=True),
    required=True,
)
def _analyze_apcbs(no_spd_checksums: bool, apcbs_dir: str) -> None:
    # Load files.
    hashes = set()
    lengths = set()
    apcbs = {}
    for apcb_path in glob.glob(os.path.join(apcbs_dir, '*.bin')):
        with open(apcb_path, 'rb') as apcb_f:
            apcb_bin = apcb_f.read()

        apcb_hash = hashlib.sha1(apcb_bin).hexdigest()
        print(f'[ ] sha1({apcb_path}) == {apcb_hash}')
        if apcb_hash in hashes:
            print('[ ] Duplicate, skipping')
            continue

        hashes.add(apcb_hash)
        lengths.add(len(apcb_bin))
        apcbs[apcb_path] = apcb_bin

    assert len(lengths) == 1, \
        f'Different file lengths are not supported: {lengths}'

    # Find different images with same checksum or random value.
    by_u8_checksum, by_random_val = _analyze_apcb_checksum(apcbs, not no_spd_checksums)

    # Measure amount of changes in pairs.
    by_n_changed_bits = _analyze_apcb_changes(apcbs)

    # Find APCBs where only checksums are changed.
    same_data = _analyze_apcbs_minus_checksums(apcbs)

    # Print results.
    print('[*] Different APCBs with the same u8 checksum:')
    pprint.pprint(by_u8_checksum)
    print('[*] Different APCBs with the same random value:')
    pprint.pprint(by_random_val)

    print('[*] Top 10 pairs with smallest number of changed bits:')
    pprint.pprint(by_n_changed_bits[:10])

    print('[*] APCB dumps with same data but different checksum and/or random value:')
    pprint.pprint(same_data)


@click.command(
    name='replace-apcbs-spds',
    help='Replace SPDs in AMD bios image inside APCB sections.\n'
         '\n'
         'ORIG_DUMP - path to original firmware dump.\n'
         'JSON_SPDS_DIR - path to directory containing modified SPDs in JSON format.\n'
         'NEW_IMAGE - where to write modified image.\n',
)
@click.option(
    '--no-orig-spd-checksums',
    '-C',
    is_flag=True,
    help='Do not validate checksums of original SPDs before replacing.',
)
@click.argument(
    'orig_dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'json_spds_dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=False, readable=True),
    required=True,
)
@click.argument(
    'new_image',
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=False),
    required=True,
)
def _replace_apcbs_spds(
        no_orig_spd_checksums: bool,
        orig_dump: str,
        json_spds_dir: str,
        new_image: str) -> None:
    with open(orig_dump, 'rb') as orig_f:
        orig_bin_image = orig_f.read()

    replacement_spds = []
    for spd_json_path in glob.glob(os.path.join(json_spds_dir, '*.json')):
        splitted_fname = os.path.basename(spd_json_path).split('.', 1)[0].rsplit('-', 4)
        with open(spd_json_path, 'r') as json_f:
            spd = pspd.DDR4_SPD.json_load(json_f)
        replacement_spds.append(
            (
                int(splitted_fname[1]),
                int(splitted_fname[2]),
                int(splitted_fname[4]),
                spd,
            )
        )

    new_bin_image = pamd.replace_apcbs_spds(
        orig_bin_image,
        replacement_spds,
        not no_orig_spd_checksums)

    with open(new_image, 'wb') as new_f:
        new_f.write(new_bin_image)


@click.command(
    name='extract-spds',
    help='Find and extract all SPDs from image using brute-force search.\n'
         '\n'
         'DUMP - path to a dump of flash.\n'
         'OUT_DIR - output directory for extracted files.\n',
)
@click.option(
    '--no-checksums',
    '-C',
    is_flag=True,
    help='Do not validate SPD checksums.',
)
@click.argument(
    'dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'out-dir',
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True),
    required=True,
)
def _extract_spds(no_checksums: bool, dump: str, out_dir: str):
    with open(dump, 'rb') as dump_f:
        dump_bin = dump_f.read()

    os.makedirs(out_dir, exist_ok=True)

    prefix = _get_prefix(dump)

    for spd_offset, spd in pspd.find_spds(dump_bin, 0, len(dump_bin), not no_checksums):
        json_path = os.path.join(out_dir, f'{prefix}-spd-{spd_offset}.json')
        print(f'[*] Writing "{json_path}"...')
        with open(json_path, 'w') as spd_f:
            pspd.DDR4_SPD.json_dump(spd, spd_f)


@click.command(
    name='parse-spd',
    help='Parse binary SPD image.\n'
         '\n'
         'SPD_DUMP - path to a dump of AMD BIOS flash.\n',
)
@click.option(
    '--no-checksums',
    '-C',
    is_flag=True,
    help='Do not validate SPD checksums.',
)
@click.argument(
    'spd_dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
def _parse_spd(no_checksums: bool, spd_dump: str) -> None:
    with open(spd_dump, 'rb') as spd_dump_f:
        spd_dump_bin = spd_dump_f.read()

    assert len(spd_dump_bin) == pspd.DDR4_SPD_LEN, \
        f'Wrong length of SPD dump: {len(spd_dump_bin)} != {pspd.DDR4_SPD_LEN}'
    pspd.parse_spd(spd_dump_bin, 0, not no_checksums)


@click.command(
    name='json2spd',
    help='Convert JSON SPD into normal binary SPD.\n'
         '\n'
         'JSON_PATH - path to SPD in JSON format.\n'
         'SPD_PATH - where to write binary SPD.\n',
)
@click.argument(
    'json_path',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'spd_path',
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=False),
    required=True,
)
def _json_to_spd(json_path: str, spd_path: str) -> None:
    with open(json_path, 'r') as json_f:
        spd = pspd.DDR4_SPD.json_load(json_f)
    spd_bin = pspd.DDR4_SPD.pack(spd)
    with open(spd_path, 'wb') as spd_f:
        spd_f.write(spd_bin)


@click.command(
    name='spd2json',
    help='Convert normal binary SPD into JSON.\n'
         '\n'
         'SPD_PATH - path to source binary SPD.\n'
         'JSON_PATH - where to write JSON.\n',
)
@click.argument(
    'spd_path',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'json_path',
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=False),
    required=True,
)
def _spd_to_json(spd_path: str, json_path: str) -> None:
    with open(spd_path, 'rb') as spd_f:
        spd_bin = spd_f.read()
    spd = pspd.DDR4_SPD.unpack(spd_bin)
    with open(json_path, 'w') as json_f:
        pspd.DDR4_SPD.json_dump(spd, json_f)


@click.command(
    name='fix-spd-checksums',
    help='Fix checksums in SPD.\n'
         '\n'
         'ORIG_JSON_PATH - path to SPD in JSON format.\n'
         'NEW_JSON_PATH - where to write fixed SPD in JSON format.\n',
)
@click.argument(
    'orig_json_path',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'new_json_path',
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=False),
    required=True,
)
def _fix_spd_checksums(orig_json_path: str, new_json_path: str) -> None:
    with open(orig_json_path, 'r') as orig_json_f:
        orig_spd = pspd.DDR4_SPD.json_load(orig_json_f)

    new_spd = pspd.fix_checksums(orig_spd)
    if new_spd == orig_spd:
        print('[*] Checksums already valid, no changes')
    else:
        print('[*] Done recalculating checksums, changes:')
        for field_name, field_val in orig_spd.items():
            if field_val != new_spd[field_name]:
                print(f'        {field_name}: 0x{field_val:04x} -> 0x{new_spd[field_name]:04x}')

    with open(new_json_path, 'w') as new_json_f:
        pspd.DDR4_SPD.json_dump(new_spd, new_json_f)


@click.command(
    name='replace-spds',
    help='Replace SPDs in arbitrary image.\n'
         '\n'
         'ORIG_DUMP - path to original firmware dump.\n'
         'JSON_SPDS_DIR - path to directory containing modified SPDs in JSON format.\n'
         'NEW_IMAGE - where to write modified image.\n',
)
@click.option(
    '--no-orig-checksums',
    '-C',
    is_flag=True,
    help='Do not validate checksums of original SPDs before replacing.',
)
@click.argument(
    'orig_dump',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True),
    required=True,
)
@click.argument(
    'json_spds_dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=False, readable=True),
    required=True,
)
@click.argument(
    'new_image',
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=False),
    required=True,
)
def _replace_spds(
        no_orig_checksums: bool,
        orig_dump: str,
        json_spds_dir: str,
        new_image: str) -> None:
    with open(orig_dump, 'rb') as orig_f:
        orig_bin_image = orig_f.read()

    replacement_spds = []
    for spd_json_path in glob.glob(os.path.join(json_spds_dir, '*.json')):
        spd_json_fname = os.path.basename(spd_json_path)
        spd_offset = int(spd_json_fname.split('.', 1)[0].rsplit('-', 1)[1])
        with open(spd_json_path, 'r') as json_f:
            spd = pspd.DDR4_SPD.json_load(json_f)
        replacement_spds.append((spd_offset, spd))

    new_bin_image = pspd.replace_spds(orig_bin_image, replacement_spds, not no_orig_checksums)

    with open(new_image, 'wb') as new_f:
        new_f.write(new_bin_image)


@click.group(
    context_settings={
        'help_option_names': ['-h', '--help'],
    },
)
def _main():
    pass


def cli_main() -> None:
    """
    CLI entry point.

    :return: None.
    """

    _main.add_command(_extract_apcbs)
    _main.add_command(_parse_apcb)
    _main.add_command(_analyze_apcbs)
    _main.add_command(_replace_apcbs_spds)

    _main.add_command(_extract_spds)
    _main.add_command(_parse_spd)
    _main.add_command(_json_to_spd)
    _main.add_command(_spd_to_json)
    _main.add_command(_fix_spd_checksums)
    _main.add_command(_replace_spds)

    _main()


if __name__ == '__main__':
    cli_main()
