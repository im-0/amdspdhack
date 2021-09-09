# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Convenience wrapper for reading/writing binary structures.
"""

import abc
import ast
from collections import OrderedDict
import io
import json
import struct
from typing import Any, Iterable, Optional, TextIO


class BaseFormatterReader:
    """
    Base class for field value conversions to/from string.
    """

    @abc.abstractmethod
    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

    @abc.abstractmethod
    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """


class IntBin(BaseFormatterReader):
    """
    Binary formatter/reader for field values.
    """

    def __init__(self, padding: int) -> None:
        self._fmt = f'0b{{:0{padding}b}}'

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        return self._fmt.format(value)

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        return int(str_value, 2)


class IntHex(BaseFormatterReader):
    """
    Hexadecimal formatter/reader for field values.
    """

    def __init__(self, padding: int) -> None:
        self._fmt = f'0x{{:0{padding}x}}'

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        return self._fmt.format(value)

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        return int(str_value, 16)


class IntBytes(BaseFormatterReader):
    """
    Format/read int as bytes.
    """

    def __init__(self, length: int, byteorder: str = 'little') -> None:
        self._length = length
        self._byteorder = byteorder

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        return f'{value.to_bytes(self._length, self._byteorder)!r}'

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        result = ast.literal_eval(str_value)
        assert isinstance(result, bytes), \
            f'Invalid type after reading bytes literal {str_value!r}'
        return int.from_bytes(result, self._byteorder)


class BytesHex(BaseFormatterReader):
    """
    Format/read bytes as hex.
    """

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        hex_str = value.hex()
        return ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        return bytes.fromhex(str_value)


def _bit_mask(num: int) -> int:
    return (1 << num) - 1


class IntBitFieldStruct(BaseFormatterReader):
    """
    Format/read int as bit field structure.
    """

    def __init__(self, fields: list[tuple[str, int, str, int]]) -> None:
        self._fields = fields

    def format(self, value: Any) -> str:
        """
        Convert value into string.

        :param value: Value.
        :return: Value as string.
        """

        result = []
        total_len = 0
        for field_name, field_len, field_fmt, _ in reversed(self._fields):
            total_len += field_len
            field_value = value & _bit_mask(field_len)
            value >>= field_len
            result.append(field_name + '=' + field_fmt.format(field_value))

        assert total_len in (8, 16, 32, 64), \
            f'Wrong total bit filed length: {total_len}'
        assert value == 0, \
            f'Non-zero leftover after parsing bit field: {value} != 0'

        return ' '.join(reversed(result))

    def read(self, str_value: str) -> Any:
        """
        Convert string to value.

        :param str_value: Value as string.
        :return: Value.
        """

        str_fields = list(str_value.split())
        value = 0
        for str_filed_val, (field_name, field_len, _, field_base) in zip(str_fields, self._fields):
            str_field_name, str_field_val = str_filed_val.split('=', 1)
            assert str_field_name == field_name, \
                f'Wrong bit field name in this position: {str_field_name} != {field_name}'
            field_val = int(str_field_val, field_base)
            assert (field_val >> field_len) == 0, \
                f'Value of field "{field_name}" is too long: {field_val} (must be {field_len} bits)'

            value = (value << field_len) | field_val

        return value


class Struct:
    """
    Convenience wrapper for reading/writing binary structures.
    """

    def __init__(self,
                 name: str,
                 description: Iterable[tuple[str, str, Optional[BaseFormatterReader]]],
                 endianness: str = '<',
                 expected_len: Optional[int] = None):
        self._name = name
        self._struct_fmt = endianness
        self._fields: OrderedDict[str, Optional[BaseFormatterReader]] = OrderedDict()
        self._max_field_name_len = 0

        for field_fmt, field_name, field_conv in description:
            assert field_name, \
                f'Empty field name in description of structure "{self._name}"'
            assert field_fmt, \
                f'Empty format for field "{field_name}" in description of structure "{self._name}"'
            assert field_name not in self._fields, \
                f'Duplicate field name "{field_name}" in description of structure "{self._name}"'

            self._struct_fmt += field_fmt
            self._fields[field_name] = field_conv
            self._max_field_name_len = max(self._max_field_name_len, len(field_name))

        self._struct_len = struct.calcsize(self._struct_fmt)
        if expected_len is not None:
            assert self._struct_len == expected_len, \
                f'Invalid format length of structure "{self._name}": ' \
                f'{self._struct_len} != {expected_len}'

    def get_name(self) -> str:
        """
        Get name of structure.

        :return: Name.
        """

        return self._name

    def get_len(self) -> int:
        """
        Get length of structure.

        :return: Length.
        """

        return self._struct_len

    def unpack(self, data: bytes) -> OrderedDict[str, Any]:
        """
        Parse structure.

        :param data: Binary data.
        :return: Ordered dict of fields.
        """

        assert len(data) == self._struct_len, \
            f'Unable to unpack, wrong size of data for "{self._name}": ' \
            f'{len(data)} != {self._struct_len}'

        values = struct.unpack(self._struct_fmt, data)

        struct_dict = OrderedDict()
        for field_name, field_value in zip(self._fields.keys(), values):
            struct_dict[field_name] = field_value

        return struct_dict

    def json_load(self, file_obj: TextIO) -> OrderedDict[str, Any]:
        """
        Load structure from JSON file.

        :param file_obj: File to read from.
        :return: Ordered dict of fields.
        """

        raw_struct = json.load(file_obj)
        struct_dict = OrderedDict()
        for field_name, field_conv in self._fields.items():
            field_value = raw_struct[field_name]
            if field_conv is None:
                struct_dict[field_name] = field_value
            else:
                struct_dict[field_name] = field_conv.read(field_value)
        return struct_dict

    def json_loads(self, json_str: str) -> OrderedDict[str, Any]:
        """
        Load structure from JSON string.

        :param json_str: String containing JSON.
        :return: Ordered dict of fields.
        """

        str_buf = io.StringIO(json_str)
        return self.json_load(str_buf)

    def pack(self, struct_dict: OrderedDict[str, Any]) -> bytes:
        """
        Generate structure.

        :param struct_dict: Ordered dict of fields.
        :return: Binary data.
        """

        values = []
        for field_name in self._fields.keys():
            values.append(struct_dict[field_name])
        return struct.pack(self._struct_fmt, *values)

    def json_dump(self, struct_dict: OrderedDict[str, Any], file_obj: TextIO) -> None:
        """
        Dump structure into JSON file.

        :param struct_dict: Ordered dict of fields.
        :param file_obj: File to write into.
        :return: None.
        """

        file_obj.write('{')
        first = True
        for field_name, field_value in struct_dict.items():
            if first:
                file_obj.write('\n    ')
                first = False
            else:
                file_obj.write(',\n    ')
            json.dump(field_name, file_obj)
            file_obj.write(': ')

            field_conv = self._fields[field_name]
            if field_conv is not None:
                field_value = field_conv.format(field_value)
            json.dump(field_value, file_obj)

        file_obj.write('\n}\n')

    def json_dumps(self, struct_dict: OrderedDict[str, Any]) -> str:
        """
        Dump structure into JSON string.

        :param struct_dict: Ordered dict of fields.
        :return: JSON.
        """

        str_buf = io.StringIO()
        self.json_dump(struct_dict, str_buf)
        return str_buf.getvalue()

    def print(self, struct_dict: OrderedDict[str, Any]) -> None:
        """
        Pretty-print structure with padding.

        :param struct_dict: Ordered dict of fields.
        :return: None.
        """

        for field_name, field_value in struct_dict.items():
            field_conv = self._fields[field_name]
            if field_conv is not None:
                field_value = field_conv.format(field_value)
            field_name = (' ' * (self._max_field_name_len - len(field_name))) + field_name
            print(f'        {field_name}: {field_value}')


def test_int_bin() -> None:
    """
    Test IntBin.

    :return: None.
    """

    val = 123
    str_val = IntBin(8).format(val)
    assert IntBin(8).read(str_val) == val


def test_int_hex() -> None:
    """
    Test IntHex.

    :return: None.
    """

    val = 123456789
    str_val = IntHex(8).format(val)
    assert IntHex(8).read(str_val) == val


def test_int_bytes() -> None:
    """
    Test IntBytes.

    :return: None.
    """

    val = 123456789
    str_val = IntBytes(4).format(val)
    assert IntBytes(4).read(str_val) == val


def test_bytes_hex() -> None:
    """
    Test Byteshex.

    :return: None.
    """

    val = b'test123'
    str_val = BytesHex().format(val)
    assert BytesHex().read(str_val) == val


def test_int_bit_field_struct() -> None:
    """
    Test IntBitFieldStruct.

    :return: None.
    """

    fmt = IntBitFieldStruct([
        ('a', 8, '0b{:08b}', 2),
        ('b', 3, '0b{:03b}', 2),
        ('c', 4, '0b{:04b}', 2),
        ('d', 1, '0b{:01b}', 2),
        ('e', 16, '0x{:04x}', 16),
    ])
    val = 0b10101010_110_0110_0_0000111111110000
    str_val = fmt.format(val)
    assert str_val == 'a=0b10101010 b=0b110 c=0b0110 d=0b0 e=0x0ff0'
    assert fmt.read(str_val) == val
