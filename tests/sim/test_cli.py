import json

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
    assert main(["plan", "ext_name", "0", "X"]) == 2
