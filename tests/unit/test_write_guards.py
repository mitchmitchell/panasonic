"""Blocker from Architect review 5622605387: writes/plans only for 0x24/0x25 (G6/H8)."""

import pytest

from panasonic.kxtd1232.client import Client
from panasonic.kxtd1232.fields import decode_ext_name, encode_ext_name
from panasonic.kxtd1232.frame import (
    READ_ONLY_COMMANDS,
    WRITE_COMMANDS,
    Encoder,
    NotAllowedError,
)
from panasonic.kxtd1232.tables import EDITABLE_TABLES
from panasonic.kxtd1232.writeplan import Patch, build_plan
from panasonic.sim import LoopbackTransport, SimPBX, synthetic_db

RW = Encoder(READ_ONLY_COMMANDS | WRITE_COMMANDS)
OTHERS = [t for t in range(0x100) if t not in (0x24, 0x25)]


def test_editable_is_caller_id_only():
    assert EDITABLE_TABLES == {0x24, 0x25}


@pytest.mark.parametrize("table", OTHERS)
def test_every_other_table_write_and_plan_refused(table):
    with pytest.raises(NotAllowedError):
        RW.write(table, 0, 0, b"\x00\x00")
    with pytest.raises(NotAllowedError):
        build_plan(table, 2, b"\x00" * 4, [Patch(table, 0, b"\x01")])


@pytest.mark.parametrize("table", [0x24, 0x25])
def test_caller_id_writes_allowed(table):
    assert RW.write(table, 0, 0, b"\x00\x00")[1] == 0x00


@pytest.mark.parametrize("table", [0x40, 0x41, 0x4E, 0xC3])
def test_half_table_rule_message(table):
    with pytest.raises(NotAllowedError, match="half-table"):
        RW.write(table, 0, 0, b"\x00\x00")


def test_reads_and_decodes_of_other_tables_still_work():
    db = synthetic_db()
    db[0x41] = bytearray(range(40))
    db[0x02] = bytearray(encode_ext_name("SPEED A") * 4)
    c = Client(LoopbackTransport(SimPBX(db=db)))
    c.login("0000")
    assert decode_ext_name(c.read_records(0x05, 10, 1, 1)) == "EXT 101"
    assert c.read(0x41, 0, 0, 4) == bytes(range(8))
    assert Encoder().read(0xC3, 0, 0, 10)[1] == 0x01
