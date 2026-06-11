from __future__ import annotations

import hashlib
from typing import Any

from sca_cli.utils.json import dumps


def stable_hash(value: Any, *, length: int = 16) -> str:
    if not isinstance(value, str):
        value = dumps(value, indent=None)
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return digest[:length]
