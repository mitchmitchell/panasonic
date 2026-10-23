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


def test_protocol_error_is_one_line(capsys):
    # within the spec range but past the 50-record synthetic sim table
    assert main(["read", "cid_name", "--first", "100", "--count", "1"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("kxtd1232: error:") and err.count("\n") == 1
