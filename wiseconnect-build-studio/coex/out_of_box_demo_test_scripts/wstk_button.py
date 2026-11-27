"""Studio Out of Box module recovered from the Backup build."""
from __future__ import annotations

import marshal
from pathlib import Path

_PYC = Path(__file__).resolve().parent / "_bytecode" / "wstk_button.pyc"
if not _PYC.is_file():
    raise ImportError(f"Missing bytecode payload: {_PYC}")
_code = marshal.loads(_PYC.read_bytes()[16:])
exec(_code, globals())
del _code, marshal, Path, _PYC
