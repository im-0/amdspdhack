# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Various checksum functions.
"""

import os


def fletcher32(data: bytes) -> int:
    """
    Fletcher's checksum [2]. Based on amdfwtool from Coreboot [1].

    [1]: https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/amdfwtool/amdfwtool.c#L94  # pylint: disable=line-too-long
    [2]: https://en.wikipedia.org/wiki/Fletcher%27s_checksum

    :param data: Binary data.
    :return: Checksum.
    """

    assert len(data) % 2 == 0, \
        f'Fletcher32 checksum requires even length, but odd length given: {len(data)}'
    csum0 = 0
    csum1 = 0
    for byte0, byte1 in zip(data[::2], data[1::2]):
        word = (byte1 << 8) | byte0
        csum0 = (csum0 + word) % 65535
        csum1 = (csum1 + csum0) % 65535
    return (csum1 << 16) | csum0


def simple8(data: bytes, initial: int) -> int:
    """
    Simple checksum.

    [1]: https://github.com/coreboot/coreboot/blob/275ade9539cd315cf72c4126ebcce714dc3102ee/util/apcb/apcb_edit.py#L92  # pylint: disable=line-too-long

    :param data: Binary data.
    :param initial: Initial value.
    :return: Checksum.
    """

    csum = initial
    for byte in data:
        csum = (csum + byte) & 0xff
    return (0x100 - csum) & 0xff


def crc16_ccitt_xmodem(data: bytes) -> int:
    """
    Calculate CRC16-CCITT, variant used for XMODEM.

    Used by JEDEC in SPD[1].

    [1]: http://www.softnology.biz/pdf/4_01_02_AnnexL-R25_SPD_for_DDR4_SDRAM_Release_3_Sep2015.pdf

    :param data: Binary data.
    :return: Checksum.
    """

    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc <<= 1
            if crc & 0x10000:
                crc ^= 0x1021
        crc &= 0xffff
    return crc


def test_fletcher32() -> None:
    """
    Test fletcher32().

    :return: None.
    """

    # https://en.wikipedia.org/wiki/Fletcher%27s_checksum#Test_vectors
    assert fletcher32(b'abcde\0') == 0xF04FC729
    assert fletcher32(b'abcdef') == 0x56502D2A
    assert fletcher32(b'abcdefgh') == 0xEBE19591


def test_simple8() -> None:
    """
    Test simple8().

    :return: None.
    """

    assert simple8(b'', 0) == 0
    assert simple8(b'', 123) == 256 - 123
    assert simple8(b'\0\0\0\0\0\0', 0) == 0
    assert simple8(b'\xff\xff\xff\xff\xff\xff\xff', 7) == 0

    data = os.urandom(128)
    assert simple8(data, simple8(data, 0)) == 0


def test_crc16_ccitt_xmodem() -> None:
    """
    Test crc16_ccitt_xmodem().

    :return: None.
    """

    assert crc16_ccitt_xmodem(b'123456789') == 0x31c3
