"""Studio Out of Box module recovered from the Backup build.

The recovered deployer is kept, then taught to delete a previous
provision_result.json so a crashed run cannot report an older DUT.
"""
from __future__ import annotations

import marshal
import shlex
from pathlib import Path

_PYC = Path(__file__).resolve().parent / "_bytecode" / "pi_ble.pyc"
if not _PYC.is_file():
    raise ImportError(f"Missing bytecode payload: {_PYC}")
_code = marshal.loads(_PYC.read_bytes()[16:])
exec(_code, globals())
del _code, marshal, _PYC

_orig_deploy = _deploy


def _deploy(client, workdir, payload):
    quoted = shlex.quote(workdir)
    code, _out, err = _run(
        client,
        "rm -f {0}/provision_result.json".format(quoted),
        timeout=30,
    )
    if code == 0:
        log("Removed stale provision_result.json")
    else:
        log("Could not remove stale provision_result.json: {0}".format((err or "").strip()))
    _orig_deploy(client, workdir, payload)
