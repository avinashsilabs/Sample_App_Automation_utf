#!/usr/bin/env python3
"""Turn the SDK's AWS certificate headers back into PEM files.

The DUT gets its client certificate and private key compiled in as C arrays
from `<SDK>/resources/certificates`. The host side needs the same identity in
PEM form to open its own AWS IoT session, so rather than asking anyone to keep
a second copy in sync, this decodes the very headers the firmware was built
with. Whatever the device presents, the host presents too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

CHAR_TOKEN = re.compile(r"'(\\.|[^'])'")
ESCAPES = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, "'": 39, '"': 34}


def decode_c_array(path: Path) -> bytes:
    """Read a `unsigned char name[] = { 'a', 'b', ... }` header back to bytes."""
    text = path.read_text(errors="replace")
    try:
        body = text[text.index("{") + 1 : text.rindex("}")]
    except ValueError as exc:
        raise ValueError(f"{path.name} does not contain a C array") from exc

    out = bytearray()
    for match in CHAR_TOKEN.finditer(body):
        token = match.group(1)
        if token.startswith("\\"):
            if token[1] not in ESCAPES:
                raise ValueError(f"{path.name}: unsupported escape {token!r}")
            out.append(ESCAPES[token[1]])
        else:
            out.append(ord(token))

    if not out:
        # Some headers store the material as 0x-prefixed bytes instead.
        out = bytearray(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", body))
    if not out:
        raise ValueError(f"{path.name}: no certificate bytes found")
    return bytes(out).rstrip(b"\x00")


def export_client_identity(cfg: dict[str, Any], out_dir: Path) -> dict[str, str]:
    """Write the DUT's client certificate and key to PEM files for the host."""
    cert_dir = Path(cfg["certificates_dir"]).expanduser()
    if not cert_dir.is_dir():
        raise FileNotFoundError(f"AWS certificates folder not found: {cert_dir}")

    sources = {
        "certfile": cert_dir / cfg.get("client_certificate", "aws_client_certificate.pem.crt.h"),
        "keyfile": cert_dir / cfg.get("client_private_key", "aws_client_private_key.pem.key.h"),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    exported: dict[str, str] = {}
    for kind, source in sources.items():
        if not source.is_file():
            raise FileNotFoundError(f"AWS certificate header missing: {source}")
        pem = decode_c_array(source)
        if b"-----BEGIN" not in pem:
            raise ValueError(f"{source.name} did not decode to PEM text")
        target = out_dir / (source.stem.replace(".pem", "") + ".pem")
        target.write_bytes(pem)
        exported[kind] = str(target)
        print(f"[aws] Decoded {source.name} -> {target.name}", flush=True)
    return exported


def describe_certificate(path: str) -> str:
    """Best-effort human summary of the client certificate."""
    try:
        from cryptography import x509
    except ImportError:
        return "install 'cryptography' to see certificate details"
    try:
        cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    except Exception as exc:  # noqa: BLE001
        return f"unreadable: {exc}"
    return (
        f"{cert.subject.rfc4514_string()} "
        f"(serial {cert.serial_number:x}, expires {cert.not_valid_after_utc:%Y-%m-%d})"
    )


if __name__ == "__main__":
    import json
    import sys

    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name(
        "config.local.json"
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    files = export_client_identity(config["aws"], Path(__file__).with_name(".certs"))
    print(json.dumps(files, indent=2))
    print(describe_certificate(files["certfile"]))
