# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Parser for SPD images.
"""

from collections import OrderedDict
import copy
import multiprocessing
import os
from typing import Any, Iterable

import spdhack.chksum as chksum
import spdhack.strct as strct


DDR4_SPD_LEN = 512
_PART_NUMBER_OFFSET = 329
_PART_NUMBER_LEN = 20


class BytesPartNumber(strct.BaseFormatterReader):
    """
    Format/read bytes as part number.
    """

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        assert len(value) == _PART_NUMBER_LEN, \
            f'Wrong length of part number: {len(value)} != {_PART_NUMBER_LEN}'
        return value.decode().rstrip()

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        value = str_value.encode()
        assert len(value) <= _PART_NUMBER_LEN, \
            f'Part number longer than {_PART_NUMBER_LEN}: {value!r} ({len(value)} bytes)'
        return value + (b' ' * (_PART_NUMBER_LEN - len(value)))


_DDR4_SPD_DESCRIPTION = (
    # pylint: disable=line-too-long
    #
    # https://en.wikipedia.org/wiki/Serial_presence_detect
    #
    # {|class=wikitable
    # |+ SPD contents for DDR4 SDRAM<ref name=spd_ddr4_docs>[https://www.jedec.org/system/files/docs/4_01_02_AnnexL-5R29.pdf JESD21-C Annex L: Serial Presence Detect for DDR4 SDRAM Modules], Release 5</ref>
    # |-
    # ! colspan=2 | Byte
    # ! colspan=8 | Bit
    # ! rowspan=2 | Notes
    # |-
    # ! Dec !! Hex !! 7 !! 6 !! 5 !! 4 !! 3 !! 2 !! 1 !! 0
    # |-
    # |  0 || 0x00 ||colspan=8| SPD bytes used
    ('B', 'spd_bytes_used', None),
    # |-
    # |  1 || 0x01 ||colspan=8| SPD revision n || Typically 0x10, 0x11, 0x12
    ('B', 'spd_revision_n', None),
    # |-
    # |  2 || 0x02 ||colspan=8| Basic memory type (12 = DDR4 SDRAM) || Type of RAM chips
    ('B', 'type_of_ram_chips', None),
    # |-
    # |  3 || 0x03 ||colspan=4 {{n/a|Reserved}} ||colspan=4| Module type || Type of module; e.g., 2 = Unbuffered DIMM, 3 = SO-DIMM, 11=LRDIMM
    ('B', 'reserved | type_of_module', strct.IntBin(8)),
    # |-
    # |  4 || 0x04 ||colspan=2| Bank group bits ||colspan=2| Bank address bits−2 ||colspan=4| Total SDRAM capacity per die in Mb || Zero means no bank groups, 4 banks, 256 Mibit.
    ('B', 'bank_group_bits | bank_address_bits_2 | total_capacity_per_die_mb', strct.IntBin(8)),
    # |-
    # |  5 || 0x05 ||colspan=2 {{n/a|Reserved}} ||colspan=3| Row address bits−12 ||colspan=3| Column address bits−9 ||
    ('B', 'reserved | row_addr_bits_12 | column_addr_bits_9', strct.IntBin(8)),
    # |-
    # |  6 || 0x06 || Primary SDRAM package type ||colspan=3| Die count ||colspan=2 {{n/a|Reserved}} ||colspan=2| Signal loading
    ('B', 'primary_sdram_pkg_type | die_count | signal_loading', strct.IntBin(8)),
    # |-
    # |  7 || 0x07 ||colspan=2 {{n/a|Reserved}} ||colspan=2| Maximum activate window (tMAW) ||colspan=4| Maximum activate count (MAC) || SDRAM optional features
    ('B', 'reserved | max_activate_window_tMAW | max_activate_count_MAC', strct.IntBin(8)),
    # |-
    # |  8 || 0x08 ||colspan=8 {{n/a|Reserved}} || SDRAM thermal and refresh options
    ('B', 'sdram_thermal_and_refresh_options', strct.IntHex(2)),
    # |-
    # |  9 || 0x09 ||colspan=2| Post package repair (PPR) || Soft PPR ||colspan=5 {{n/a|Reserved}} || Other SDRAM optional features
    ('B', 'post_package_repair_PPR | soft_PPR | reserved', strct.IntBin(8)),
    # |-
    # | 10 || 0x0a || SDRAM package type ||colspan=3| Die count−1 ||colspan=2| DRAM density ratio ||colspan=2| Signal loading || Secondary SDRAM package type
    ('B', 'sdram_pkg_type | die_count_1 | dram_density_ratio | signal_loading', strct.IntBin(8)),
    # |-
    # | 11 || 0x0b ||colspan=6 {{n/a|Reserved}} || Endurant flag || Operable flag || Module nominal voltage, VDD
    ('B', 'reserved | endurant_flag | operable_flag', strct.IntBin(8)),
    # |-
    # | 12 || 0x0c || {{n/a|Reserved}} || Rank mix ||colspan=3| Package ranks per DIMM−1 ||colspan=3| SDRAM device width || Module organization
    ('B', 'reserved | rank_mix | pkg_ranks_per_dimm_1 | sdram_dev_width', strct.IntBin(8)),
    # |-
    # | 13 || 0x0d ||colspan=3 {{n/a|Reserved}} ||colspan=2| Bus width extension||colspan=3|Primary bus width||Module memory bus width in bits
    ('B', 'reserved | bus_width_extension | primary_bus_width', strct.IntBin(8)),
    # |-
    # | 14 || 0x0e || Thermal sensor ||colspan=7 {{n/a|Reserved}} || Module thermal sensor
    ('B', 'thermal_sensor | reserved', strct.IntBin(8)),
    # |-
    # | 15 || 0x0f ||colspan=4 {{n/a|Reserved}} ||colspan=4|Extended base module type
    ('B', 'reserved | extended_base_module_type', strct.IntBin(8)),
    # |-
    # | 16 || 0x10 ||colspan=8 {{n/a|Reserved}}
    ('B', 'reserved_0', strct.IntHex(2)),
    # |-
    # | 17 || 0x11 ||colspan=4 {{n/a|Reserved}} ||colspan=2| Medium timebase (MTB)||colspan=2| Fine timebase (FTB) || Measured in ps.
    ('B', 'reserved | medium_timebase | fine_timebase', strct.IntBin(8)),
    # |-
    # | 18 || 0x12 ||colspan=8| Minimum SDRAM cycle time, t<sub>CKAVG</sub>min || In multiples of MTB; e.g., 100/8 ns.
    ('B', 'minimum_sdram_cycle_time_TckavgMIN', None),
    # |-
    # | 19 || 0x13 ||colspan=8| Maximum SDRAM cycle time, t<sub>CKAVG</sub>max || In multiples of MTB; e.g., 60/8 ns.
    ('B', 'maximum_sdram_cycle_time_TckavgMAX', None),
    # |-
    # | 20 || 0x14 || 14 || 13 || 12 || 11 || 10 || 9 || 8 || 7 || CAS latencies supported bit-mask
    ('B', 'cas_latencies_supported_0', strct.IntBin(8)),
    # |-
    # | 21 || 0x15 || 22 || 21 || 20 || 19 || 18 || 17 || 16 || 15 || CAS latencies supported bit-mask
    ('B', 'cas_latencies_supported_1', strct.IntBin(8)),
    # |-
    # | 22 || 0x16 || 30 || 29 || 28 || 27 || 26 || 25 || 24 || 23 || CAS latencies supported bit-mask
    ('B', 'cas_latencies_supported_2', strct.IntBin(8)),
    # |-
    # | 23 || 0x17 ||Low CL range|| {{n/a|Reserved}} || 36 || 35 || 34 || 33 || 32 || 31 || CAS latencies supported bit-mask
    ('B', 'low_cl_range | reserved | cas_latencies_supported_3', strct.IntBin(8)),
    # |-
    # | 24 || 0x18 ||colspan=8| Minimum CAS latency time, t<sub>AA</sub>min || In multiples of MTB; e.g., 1280/8 ns.
    ('B', 'minimum_cas_latency_time_TaaMIN', None),
    # |-
    # | 25 || 0x19 ||colspan=8| Minimum RAS to CAS delay time, t<sub>RCD</sub>min || In multiples of MTB; e.g., 60/8 ns.
    ('B', 'minimum_ras_to_cas_delay_time_TrcdMIN', None),
    # |-
    # | 26 || 0x1a ||colspan=8| Minimum row precharge delay time, t<sub>RP</sub>min || In multiples of MTB; e.g., 60/8 ns.
    ('B', 'minimum_row_precharge_delay_time_TrpMIN', None),
    # |-
    # | 27 || 0x1b ||colspan=8| Upper nibbles for t<sub>RAS</sub>min and t<sub>RC</sub>min
    ('B', 'upper_nibbles_for_TrasMIN_and_TrcMIN', None),
    # |-
    # | 28 || 0x1c ||colspan=8| Minimum active to precharge delay time, t<sub>RAS</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_active_to_precharge_delay_TrasMIN_lsb', None),
    # |-
    # | 29 || 0x1d ||colspan=8| Minimum active to active/refresh delay time, t<sub>RC</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_active_to_active_refresh_delay_TrcMIN_lsb', None),
    # |-
    # | 30 || 0x1e ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC1</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc1MIN_lsb', None),
    # |-
    # | 31 || 0x1f ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC1</sub>min most significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc1MIN_msb', None),
    # |-
    # | 32 || 0x20 ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC2</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc2MIN_lsb', None),
    # |-
    # | 33 || 0x21 ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC2</sub>min most significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc2MIN_msb', None),
    # |-
    # | 34 || 0x22 ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC4</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc4MIN_lsb', None),
    # |-
    # | 35 || 0x23 ||colspan=8| Minimum refresh recovery delay time, t<sub>RFC4</sub>min most significant byte || In multiples of MTB
    ('B', 'minimum_refresh_recovery_delay_time_Trfc4MIN_msb', None),
    # |-
    # | 36 || 0x24 ||colspan=4 {{n/a|Reserved}} ||colspan=4| t<sub>FAW</sub>min most significant nibble
    ('B', 'reserved | TfawMIN_most_significant_nibble', strct.IntBin(8)),
    # |-
    # | 37 || 0x25 ||colspan=8| Minimum four activate window delay time, t<sub>FAW</sub>min least significant byte || In multiples of MTB
    ('B', 'minimum_four_activate_delay_time_TfawMIN_lsb', None),
    # |-
    # | 38 || 0x26 ||colspan=8| Minimum activate to activate delay time, t<sub>RRD_S</sub>min, different bank group || In multiples of MTB
    ('B', 'minimum_activate_to_activate_delay_time_Trrd_sMIN_different_bank_group', None),
    # |-
    # | 39 || 0x27 ||colspan=8| Minimum activate to activate delay time, t<sub>RRD_L</sub>min, same bank group || In multiples of MTB
    ('B', 'minimum_activate_to_activate_delay_time_Trrd_lMIN_same_bank_group', None),
    # |-
    # | 40 || 0x28 ||colspan=8| Minimum CAS to CAS delay time, t<sub>CCD_L</sub>min, same bank group || In multiples of MTB
    ('B', 'minimum_cas_to_cas_delay_time_Tccd_lMIN_same_bank_group', None),
    # |-
    # | 41 || 0x29 ||colspan=8| Upper nibble for t<sub>WR</sub>min
    ('B', 'upper_nibble_for_TwrMIN', None),
    # |-
    # | 42 || 0x2a ||colspan=8| Minimum write recovery time, t<sub>WR</sub>min || In multiples of MTB
    ('B', 'minimum_write_recovery_time_TwrMIN', None),
    # |-
    # | 43 || 0x2b ||colspan=8| Upper nibbles for t<sub>WTR</sub>min
    ('B', 'upper_nibbles_for_TwtrMIN', None),
    # |-
    # | 44 || 0x2c ||colspan=8| Minimum write to read time, t<sub>WTR_S</sub>min, different bank group || In multiples of MTB
    ('B', 'minimum_write_to_read_time_Twtr_sMIN', None),
    # |-
    # | 45 || 0x2d ||colspan=8| Minimum write to read time, t<sub>WTR_L</sub>min, same bank group || In multiples of MTB
    ('B', 'minimum_write_to_read_time_Twtr_lMIN', None),
    # |-
    # | 49–59 || 0x2e–0x3b ||colspan=8 {{n/a|Reserved}} || Base configuration section
    ('14s', 'base_configuration_section_0', strct.BytesHex()),
    # |-
    # | 60–77 || 0x3c–0x4d || colspan=8| Connector to SDRAM bit mapping
    ('18s', 'connector_to_sdram_bi_mapping', strct.BytesHex()),
    # |-
    # | 78–116 || 0x4e–0x74 ||colspan=8 {{n/a|Reserved}} || Base configuration section
    ('39s', 'base_configuration_section_1', strct.BytesHex()),
    # |-
    # | 117 || 0x75 ||colspan=8| Fine offset for minimum CAS to CAS delay time, t<sub>CCD_L</sub>min, same bank || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_cas_to_cas_delay_time_Tccd_l_lMIN_same_bank', None),
    # |-
    # | 118 || 0x76 ||colspan=8| Fine offset for minimum activate to activate delay time, t<sub>RRD_L</sub>min, same bank group || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_activate_to_activate_delay_time_Trrd_lMIN_same_bank', None),
    # |-
    # | 119 || 0x77 ||colspan=8| Fine offset for minimum activate to activate delay time, t<sub>RRD_S</sub>min, different bank group || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_activate_to_activate_delay_time_Trrd_sMIN_different_bank', None),
    # |-
    # | 120 || 0x78 ||colspan=8| Fine offset for minimum active to active/refresh delay time, t<sub>RC</sub>min || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_active_to_active_refresh_delay_time_TrcMIN', None),
    # |-
    # | 121 || 0x79 ||colspan=8| Fine offset for minimum row precharge delay time, t<sub>RP</sub>min || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_row_precharge_delay_time_TrpMIN', None),
    # |-
    # | 122 || 0x7a ||colspan=8| Fine offset for minimum RAS to CAS delay time, t<sub>RCD</sub>min || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_ras_to_cas_delay_time_TrcdMIN', None),
    # |-
    # | 123 || 0x7b ||colspan=8| Fine offset for minimum CAS latency time, t<sub>AA</sub>min || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_minimum_cas_latency_time_TaaMIN', None),
    # |-
    # | 124 || 0x7c ||colspan=8| Fine offset for SDRAM maximum cycle time, t<sub>CKAVG</sub>max || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_sdram_maximum_cycle_time_TckavgMAX', None),
    # |-
    # | 125 || 0x7d ||colspan=8| Fine offset for SDRAM minimum cycle time, t<sub>CKAVG</sub>min || Two's complement multiplier for FTB units
    ('B', 'fine_offset_for_sdram_minimum_cycle_time_TckavgMIN', None),
    # |-
    # | 126 || 0x7e ||colspan=8| Cyclic rendundancy code (CRC) for base config section, least significant byte || CRC16 algorithm
    # |-
    # | 127 || 0x7f ||colspan=8| Cyclic rendundancy code (CRC) for base config section, most significant byte || CRC16 algorithm
    ('H', 'crc_for_base_conf_section', strct.IntHex(4)),
    # |-
    # | 128–191 || 0x80–0xbf ||colspan=8| Module-specific section || Dependent upon memory module family (UDIMM, RDIMM, LRDIMM)
    ('64s', 'module_specific_section', strct.BytesHex()),
    # |-
    # | 192–255 || 0xc0–0xff ||colspan=8| Hybrid memory architecture specific parameters
    ('62s', 'hybrid_memory_architecture_specific_parameters', strct.BytesHex()),
    ('H', 'crc_for_spd_block_1', strct.IntHex(4)),
    # |-
    # | 256–319 || 0x100–0x13f ||colspan=8| Extended function parameter block
    ('64s', 'extended_function_parameter_block', strct.BytesHex()),
    # |-
    # | 320–321 || 0x140–0x141 ||colspan=8| Module manufacturer || See JEP-106
    ('H', 'module_manufacturer_code', strct.IntHex(4)),
    # |-
    # | 322 || 0x142 ||colspan=8| Module manufacturing location || Manufacturer-defined manufacturing location code
    ('B', 'module_manufacturing_location', strct.IntHex(2)),
    # |-
    # | 323 || 0x143 ||colspan=8| Module manufacturing year || Represented in Binary Coded Decimal (BCD)
    ('B', 'module_manufacturing_year_bcd', strct.IntHex(2)),
    # |-
    # | 324 || 0x144 ||colspan=8| Module manufacturing week || Represented in Binary Coded Decimal (BCD)
    ('B', 'module_manufacturing_week_bcd', strct.IntHex(2)),
    # |-
    # | 325–328 || 0x145–0x148 ||colspan=8| Module serial number || Manufacturer-defined format for a unique serial number across part numbers
    ('I', 'module_serial_number', strct.IntHex(8)),
    # |-
    # | 329–348 || 0x149–0x15c ||colspan=8| Module part number || ASCII part number, unused digits should be set to 0x20
    ('20s', 'module_part_number', BytesPartNumber()),
    # |-
    # | 349 || 0x15d ||colspan=8| Module revision code || Manufacturer-defined revision code
    ('B', 'module_revision_code', strct.IntHex(2)),
    # |-
    # | 350–351 || 0x15e–0x15f ||colspan=8| DRAM manufacturer ID code || See JEP-106
    ('H', 'dram_manufacturer_id_code', strct.IntHex(4)),
    # |-
    # | 352 || 0x160 ||colspan=8| DRAM stepping || Manufacturer-defined stepping or 0xFF if not used
    ('B', 'dram_stepping', strct.IntHex(2)),
    # |-
    # | 353–381 || 0x161–0x17d ||colspan=8| Manufacturer's specific data
    ('29s', 'manufacturers_specific_data', strct.BytesHex()),
    # |-
    # | 382–383 || 0x17e–0x17f ||colspan=8 {{n/a|Reserved}}
    ('2s', 'reserved_1', strct.BytesHex()),
    # |}
    ('128s', 'user_data', strct.BytesHex()),
)
DDR4_SPD = strct.Struct('DDR4 Serial Presence Detect',
                        _DDR4_SPD_DESCRIPTION,
                        expected_len=DDR4_SPD_LEN)

# http://www.softnology.biz/pdf/4_01_02_AnnexL-R25_SPD_for_DDR4_SDRAM_Release_3_Sep2015.pdf
# Byte 2 (0x002): Key Byte / DRAM Device Type
_CHIP_TYPE_DDR4 = 0x0c
_CHIP_TYPE_DDR4E = 0x0e
_CHIP_TYPE_LPDDR4 = 0x10
_CHIP_TYPES_DDR4 = (_CHIP_TYPE_DDR4, _CHIP_TYPE_DDR4E, _CHIP_TYPE_LPDDR4)

_SPD_BYTES_TOTAL_512 = 0b010


def _calc_crcs(spd_bin: bytes) -> dict[str, int]:
    return {
        'crc_for_base_conf_section': chksum.crc16_ccitt_xmodem(spd_bin[:126]),
        'crc_for_spd_block_1': chksum.crc16_ccitt_xmodem(spd_bin[128:254]),
    }


def fix_checksums(spd: OrderedDict[str, Any]) -> OrderedDict[str, Any]:
    """
    Fix checksums inside SPD.

    :param spd: Original SPD, will remain intact.
    :return: New SPD with fixed checksums.
    """

    spd_bin = DDR4_SPD.pack(spd)
    new_spd = copy.deepcopy(spd)
    for crc_var_name, crc_value in _calc_crcs(spd_bin).items():
        new_spd[crc_var_name] = crc_value
    return new_spd


def parse_spd(
        image: bytes,
        offset: int,
        checksums: bool) -> OrderedDict[str, Any]:
    """
    Parse SPD.

    :param image: Binary image.
    :param offset: Offset to SPD.
    :param checksums: Whether to validate checksums.
    :return: SPD structure.
    """

    spd_bin = image[offset:offset + DDR4_SPD_LEN]
    spd = DDR4_SPD.unpack(spd_bin)

    type_of_ram_chips = spd['type_of_ram_chips']
    print(f'[ ] Type of chips in possible SPD at 0x{offset:08x}: 0x{type_of_ram_chips:02x}')
    assert type_of_ram_chips in _CHIP_TYPES_DDR4, \
        f'Unsupported RAM type: {type_of_ram_chips} not in {_CHIP_TYPES_DDR4} (DDR4)'

    # Byte 0 (0x000): Number of Bytes Used / Number of Bytes in SPD Device
    spd_bytes_used = spd['spd_bytes_used']
    spd_bytes_total = (spd_bytes_used >> 4) & 0b111
    print(f'[ ] Total bytes in possible SPD at 0x{offset:08x}: 0b{spd_bytes_total:03b}')
    assert spd_bytes_total == _SPD_BYTES_TOTAL_512,\
        f'Unsupported SPD length: 0b{spd_bytes_total:03b} != 0x{_SPD_BYTES_TOTAL_512:03b} (512b)'

    print(f'[ ] Validating checksums in possible SPD at 0x{offset:08x}')
    for crc_var_name, crc_value in _calc_crcs(spd_bin).items():
        if checksums:
            assert spd[crc_var_name] == crc_value, \
                f'Invalid {crc_var_name}: {spd[crc_var_name]} != {crc_value}'
        elif spd[crc_var_name] != crc_value:
            print(f'[!] Invalid {crc_var_name}: {spd[crc_var_name]} != {crc_value}')

    print(f'[*] Got {DDR4_SPD.get_name()} at 0x{offset:08x}:')
    DDR4_SPD.print(spd)

    return spd


def _split_range(start: int, end: int, num_parts: int) -> list[range]:
    full_len = end - start
    range_len = full_len // num_parts
    ranges = [[i * range_len, (i + 1) * range_len] for i in range(num_parts)]
    ranges[-1][1] += full_len % num_parts
    return [range(*part) for part in ranges]


class _PartialFindSPDs:
    def __init__(self, image: bytes, checksums: bool):
        self._image = image
        self._checksums = checksums

    def find(self, partial_range: range) -> Iterable[tuple[int, OrderedDict[str, Any]]]:
        """
        Find SPDs in range.

        :param partial_range: Range to search.
        :return: Iterable of offsets and SPD structures.
        """

        for part_number_start in partial_range:
            # Part number should be all in printable characters.
            part_number = self._image[part_number_start:part_number_start + _PART_NUMBER_LEN]
            if not all((0x20 <= byte <= 0x7e) for byte in part_number):
                continue

            spd_offset = part_number_start - _PART_NUMBER_OFFSET
            try:
                spd = parse_spd(self._image, spd_offset, self._checksums)
                yield spd_offset, spd
            except AssertionError:
                continue

    def __call__(self, partial_range: range) -> list[tuple[int, OrderedDict[str, Any]]]:
        return list(self.find(partial_range))


def find_spds(
        image: bytes,
        offset: int,
        size: int,
        checksums: bool) -> Iterable[tuple[int, OrderedDict[str, Any]]]:
    """
    Find SPDs im image by brute force.

    :param image: Binary image.
    :param offset: Where to start.
    :param size: Maximum size.
    :param checksums: Whether to validate checksums.
    :return: Iterable of offsets and SPD structures.
    """

    assert size >= DDR4_SPD_LEN, \
        f'Not enough space for SPD: {size} < {DDR4_SPD_LEN}'

    pn_range_start = offset + _PART_NUMBER_OFFSET
    pn_range_end = offset + size - DDR4_SPD_LEN + _PART_NUMBER_OFFSET + 1

    n_spds = 0
    spd_finder = _PartialFindSPDs(image, checksums)
    if size > 2 ** 16:
        n_procs = multiprocessing.cpu_count()
        print(f'[ ] Spawning {n_procs} parallel processes...')
        pool = multiprocessing.Pool(n_procs)

        for spds in pool.imap_unordered(
                spd_finder,
                _split_range(pn_range_start, pn_range_end, n_procs),
                1):
            for spd_offset, spd in spds:
                n_spds += 1
                yield spd_offset, spd
    else:
        for spd_offset, spd in spd_finder.find(range(pn_range_start, pn_range_end)):
            n_spds += 1
            yield spd_offset, spd

    print(f'[*] Found {n_spds} SPDs')


def replace_spds(
        orig_image: bytes,
        new_spds: Iterable[tuple[int, OrderedDict[str, Any]]],
        orig_checksums: bool) -> bytes:
    """
    Replace SPDs inside image.

    :param orig_image: Original binary image.
    :param new_spds: Iterable over tuples containing SPD offsets and SPD structs.
    :param orig_checksums: Whether to validate checksums of original SPDs before replacing.
    :return: New binary image.
    """

    print('[ ] Replacing SPDs...')
    new_image = orig_image
    spd_offsets_to_validate = []
    for spd_offset, new_spd in new_spds:
        # Check that offset is valid.
        print(f'[ ] Validating original SPD at offset 0x{spd_offset:08x}')
        orig_spd = parse_spd(orig_image, spd_offset, orig_checksums)

        if new_spd == orig_spd:
            print(f'[ ] Same SPD at 0x{spd_offset:08x}, skipping')
            continue

        # Replace SPD.
        new_spd_bin = DDR4_SPD.pack(new_spd)
        new_image = new_image[:spd_offset] + new_spd_bin + new_image[spd_offset + DDR4_SPD_LEN:]

        spd_offsets_to_validate.append(spd_offset)

    assert len(new_image) == len(orig_image), \
        f'Logic error: image size changed ({len(new_image)} != {len(orig_image)})'

    print('[ ] Validating SPDs...')
    for spd_offset in spd_offsets_to_validate:
        print(f'[ ] Validating replaced SPD at 0x{spd_offset:08x}')
        parse_spd(new_image, spd_offset, True)

    print(f'[*] Done, replaced {len(spd_offsets_to_validate)} SPDs')
    return new_image


def test_bytes_part_number() -> None:
    """
    Test BytesPartNumber.

    :return: None.
    """

    val = b'test123             '
    str_val = BytesPartNumber().format(val)
    assert str_val == 'test123'
    assert BytesPartNumber().read(str_val) == val


def test_spd_unpack_and_pack() -> None:
    """
    Unpack known SPD, pack again, check that result is the same.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image_f.seek(4010700)
        orig_spd_bin = image_f.read(DDR4_SPD_LEN)

    spd = parse_spd(orig_spd_bin, 0, True)
    new_spd_bin = DDR4_SPD.pack(spd)
    assert orig_spd_bin == new_spd_bin


def test_parse_spd_checksums() -> None:
    """
    Test parse_spd() with and without checksum validation.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image_f.seek(4010700)
        orig_spd_bin = image_f.read(DDR4_SPD_LEN)

    # Should be ok.
    parse_spd(orig_spd_bin, 0, False)
    # Also should be ok.
    orig_spd = parse_spd(orig_spd_bin, 0, True)

    bad_spd = copy.deepcopy(orig_spd)
    bad_spd['spd_revision_n'] += 1

    bad_spd_bin = DDR4_SPD.pack(bad_spd)
    assert bad_spd_bin != orig_spd_bin
    try:
        parse_spd(bad_spd_bin, 0, True)
    except AssertionError:
        # As expected, bad checksum.
        pass
    else:
        assert False, 'No error!'

    # Should be ok.
    bad_checksum_spd = parse_spd(bad_spd_bin, 0, False)
    assert bad_checksum_spd == bad_spd


def test_fix_checksums() -> None:
    """
    Test fix_checksums().

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image_f.seek(4010700)
        orig_spd_bin = image_f.read(DDR4_SPD_LEN)

    orig_spd = parse_spd(orig_spd_bin, 0, True)
    bad_spd = copy.deepcopy(orig_spd)
    bad_spd['spd_revision_n'] += 1

    bad_spd_bin = DDR4_SPD.pack(bad_spd)
    assert bad_spd_bin != orig_spd_bin
    try:
        parse_spd(bad_spd_bin, 0, True)
    except AssertionError:
        # As expected, bad checksum.
        pass
    else:
        assert False, 'No error!'

    fixed_spd = fix_checksums(bad_spd)
    assert fixed_spd != orig_spd
    assert fixed_spd != bad_spd
    fixed_spd_bin = DDR4_SPD.pack(fixed_spd)
    assert fixed_spd_bin != orig_spd_bin
    assert fixed_spd_bin != bad_spd_bin

    new_spd = parse_spd(fixed_spd_bin, 0, True)
    assert new_spd == fixed_spd
    assert new_spd != orig_spd
    assert new_spd != bad_spd


def test_spd_json() -> None:
    """
    Test JSON serialization and deserialization.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image_f.seek(4010700)
        orig_spd_bin = image_f.read(DDR4_SPD_LEN)

    orig_spd = parse_spd(orig_spd_bin, 0, True)
    json = DDR4_SPD.json_dumps(orig_spd)
    new_spd = DDR4_SPD.json_loads(json)
    assert orig_spd == new_spd


def test_split_range() -> None:
    """
    Test _split_range().

    :return: None.
    """

    def _to_list(rng: range) -> list:
        return list(rng)

    assert list(map(_to_list, _split_range(0, 4, 4))) == [[0], [1], [2], [3]]
    assert list(map(_to_list, _split_range(0, 4, 3))) == [[0], [1], [2, 3]]
    assert list(map(_to_list, _split_range(0, 0, 4))) == [[], [], [], []]
    assert list(map(_to_list, _split_range(0, 1, 4))) == [[], [], [], [0]]
    assert list(map(_to_list, _split_range(0, 4, 1))) == [[0, 1, 2, 3]]
    assert list(map(_to_list, _split_range(0, 4, 2))) == [[0, 1], [2, 3]]


def test_find_spds() -> None:
    """
    Test find_spds().

    :return: None.
    """

    boalz100_spd_offsets = [
        3646516,
        3647596,
        3648696,
        3649776,
        3650876,
        3651956,
        3655236,
        3656316,
        3657416,
        3658496,
        3659596,
        3660676,
        7087156,
        7088236,
        7089336,
        7090416,
        7091516,
        7092596,
        7095876,
        7096956,
        7098056,
        7099136,
        7100236,
        7101316,
    ]

    with open(os.path.join('test-data', 'BOALZ100.fd'), 'rb') as image_f:
        image = image_f.read()
    spd_offsets = [offset for offset, _ in find_spds(image, 0, len(image), True)]
    spd_offsets.sort()
    assert spd_offsets == boalz100_spd_offsets


def test_replace_spds_bad_offset() -> None:
    """
    Test replace_spds() with bad offset.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image = image_f.read()
    spd = parse_spd(image, 4010700, True)

    try:
        replace_spds(image, [(123, spd)], True)
    except AssertionError:
        # As expected, bad offset.
        pass
    else:
        assert False, 'No error!'


def test_replace_spds_bad_spd() -> None:
    """
    Test replace_spds() with bad SPD (invalid checksum).

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image = image_f.read()
    spd = parse_spd(image, 4010700, True)

    spd['spd_revision_n'] += 1
    try:
        replace_spds(image, [(4010700, spd)], True)
    except AssertionError:
        # As expected, bad checksum.
        pass
    else:
        assert False, 'No error!'


def test_replace_spds_same() -> None:
    """
    Test replace_spds() with same SPD.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image = image_f.read()
    spd = parse_spd(image, 4010700, True)

    new_image = replace_spds(image, [(4010700, spd)], True)
    assert new_image == image


def test_replace_spds_modified() -> None:
    """
    Test replace_spds() with modified SPD.

    :return: None.
    """

    # Read known SPD from test image.
    with open(os.path.join('test-data', 'BOAPC305.fd'), 'rb') as image_f:
        image = image_f.read()
    spd = parse_spd(image, 4010700, True)

    spd['spd_revision_n'] += 1
    spd = fix_checksums(spd)

    new_image = replace_spds(image, [(4010700, spd)], True)
    assert new_image != image
