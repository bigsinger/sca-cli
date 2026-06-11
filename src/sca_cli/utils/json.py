from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import orjson
except Exception:  # pragma: no cover - optional acceleration
    orjson = None


def dumps(data: Any, *, indent: int | None = 2) -> str:
    if orjson is not None:
        option = orjson.OPT_SORT_KEYS
        if indent:
            option |= orjson.OPT_INDENT_2
        return orjson.dumps(data, option=option).decode("utf-8")
    return json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True)


def loads(data: str | bytes) -> Any:
    if orjson is not None:
        return orjson.loads(data)
    return json.loads(data)


def read_json(path: Path) -> Any:
    return loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(data), encoding="utf-8")
