import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from filecleaner import output as output_mod


@dataclass
class _Simple:
    name: str
    count: int


def test_to_jsonable_handles_path():
    assert output_mod.to_jsonable(Path("/a/b")) == "/a/b"


def test_to_jsonable_handles_datetime():
    dt = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert output_mod.to_jsonable(dt) == dt.isoformat()


def test_to_jsonable_handles_date():
    d = date(2024, 1, 2)
    assert output_mod.to_jsonable(d) == d.isoformat()


def test_to_jsonable_handles_plain_dataclass():
    obj = _Simple(name="x", count=3)
    assert output_mod.to_jsonable(obj) == {"name": "x", "count": 3}


def test_to_jsonable_prefers_to_dict_when_present():
    class WithToDict:
        def to_dict(self):
            return {"custom": True}

    assert output_mod.to_jsonable(WithToDict()) == {"custom": True}


def test_to_jsonable_recurses_into_containers():
    data = {"paths": [Path("/a"), Path("/b")], "nested": {"p": Path("/c")}}
    result = output_mod.to_jsonable(data)
    assert result == {"paths": ["/a", "/b"], "nested": {"p": "/c"}}


def test_to_jsonable_handles_set():
    result = output_mod.to_jsonable({1, 2, 3})
    assert sorted(result) == [1, 2, 3]


def test_dumps_produces_valid_json():
    text = output_mod.dumps({"a": Path("/x"), "b": [1, 2]})
    parsed = json.loads(text)
    assert parsed == {"a": "/x", "b": [1, 2]}


def test_emit_writes_to_given_stream():
    import io

    buf = io.StringIO()
    output_mod.emit({"ok": True}, stream=buf)
    assert json.loads(buf.getvalue()) == {"ok": True}
