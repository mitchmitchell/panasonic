import json

import pytest

from panasonic.kxtd1232.cli import main


def test_version(capsys):
    assert main(["version"]) == 0
    assert "PXXXXXXXXXX" in capsys.readouterr().out


def test_read(capsys):
    assert main(["read", "cid_number", "--count", "2"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "0\t123"


def test_plan_dry_run(capsys):
    assert main(["plan", "cid_name", "1", "NEW"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["writes"] == 1 and out["diff"]


def test_plan_rejects_bad_value(capsys):
    assert main(["plan", "cid_number", "0", "abc"]) == 2


def test_plan_refuses_ext_name_until_g6(capsys):
    assert main(["plan", "ext_name", "0", "X"]) == 1
    assert "not on the editable list" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["plan", "cid_name", "9999", "x"],
        ["read", "cid_name", "--first", "-1"],
        ["read", "cid_name", "--first", "abc"],
        ["read", "cid_name", "--count", "0"],
        ["read", "cid_name", "--first", "499", "--count", "2"],
    ],
)
def test_bad_ranges_are_usage_errors(argv, capsys):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "usage:" in err and "Traceback" not in err


def test_last_cid_name_record_matches_sim(capsys):
    # 499 is the last record in both the CLI limit and the simulator (RE spec: 500 records)
    assert main(["read", "cid_name", "--first", "499", "--count", "1"]) == 0
    assert capsys.readouterr().out.startswith("499\t")


def test_protocol_error_is_one_line_and_ends_binary(capsys, monkeypatch):
    from panasonic.kxtd1232 import cli
    from panasonic.kxtd1232.client import Client
    from panasonic.sim import LoopbackTransport, SimPBX, synthetic_db

    sim = SimPBX(db=synthetic_db(cid_records=50))  # smaller than the spec, so reads refuse

    def small():
        c = Client(LoopbackTransport(sim))
        c.login("0000")
        return c

    monkeypatch.setattr(cli, "_connect", small)
    assert main(["read", "cid_name", "--first", "100", "--count", "1"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("kxtd1232: error:") and err.count("\n") == 1
    assert sim.mode == "await_password_again"  # end_binary ran on the error path


def test_invalid_value_uses_error_prefix(capsys):
    assert main(["plan", "cid_number", "0", "abc"]) == 2
    assert capsys.readouterr().err.startswith("kxtd1232: error:")


def _patched(monkeypatch, client_factory):
    from panasonic.kxtd1232 import cli

    monkeypatch.setattr(cli, "_connect", client_factory)


def test_transport_timeout_is_one_line(capsys, monkeypatch):
    from panasonic.kxtd1232.client import Client
    from panasonic.sim import LoopbackTransport, SimPBX

    class Dead(LoopbackTransport):
        def recv(self, timeout):
            raise TimeoutError

    def factory():
        c = Client(LoopbackTransport(SimPBX()))
        c.login("0000")
        c.t = Dead(SimPBX())
        return c

    _patched(monkeypatch, factory)
    assert main(["version"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("kxtd1232: error:") and "Traceback" not in err


def test_malformed_record_is_one_line(capsys, monkeypatch):
    from panasonic.kxtd1232.client import Client
    from panasonic.sim import LoopbackTransport, SimPBX, synthetic_db

    db = synthetic_db()
    db[0x24][0:6] = b"\xff" * 6  # digit count 15: not decodable
    sim = SimPBX(db=db)

    def factory():
        c = Client(LoopbackTransport(sim))
        c.login("0000")
        return c

    _patched(monkeypatch, factory)
    assert main(["read", "cid_number", "--count", "1"]) == 1
    assert "does not decode" in capsys.readouterr().err
