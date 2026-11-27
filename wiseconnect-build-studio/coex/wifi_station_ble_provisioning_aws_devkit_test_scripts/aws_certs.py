#!/usr/bin/env python3
"""Turn the SDK's AWS certificate headers back into PEM / PKCS#12 files.

The DUT gets its client certificate and private key compiled in as C arrays
from `<SDK>/resources/certificates`. The host side needs the same identity in
PEM form to open its own AWS IoT session, so rather than asking anyone to keep
a second copy in sync, this decodes the very headers the firmware was built
with. Whatever the device presents, the host presents too.

The example readme also asks the Si Connect mobile app for a PKCS#12 (``.p12``)
bundle plus its export password. ``export_pkcs12`` builds that file from the
same PEMs so the automation covers the certificate-preparation step as well.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

CHAR_TOKEN = re.compile(r"'(\\.|[^'])'")
ESCAPES = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, "'": 39, '"': 34}
DEFAULT_P12_PASSWORD = "123456789"


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


def export_pkcs12(
    certfile: str | Path,
    keyfile: str | Path,
    out_dir: Path,
    *,
    password: str = DEFAULT_P12_PASSWORD,
    filename: str = "aws_device_cert.p12",
    use_legacy: bool = True,
) -> dict[str, str]:
    """Build the Si Connect ``.p12`` bundle from the same device PEMs.

    Matches the readme OpenSSL command:

        openssl pkcs12 -export -out aws_device_cert.p12 \\
          -inkey <device-private-key>.pem.key \\
          -in <device-certificate>.pem.crt

    OpenSSL 3.x often needs ``-legacy`` for mobile keystores, so that flag is
    on by default. Returns paths plus the export password the app would enter.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        raise FileNotFoundError(
            "OpenSSL is required to create aws_device_cert.p12 "
            "(see the example readme: Prepare the AWS Certificate for the Si Connect Mobile App)"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    p12_path = out_dir / filename
    cmd = [
        openssl,
        "pkcs12",
        "-export",
        "-out",
        str(p12_path),
        "-inkey",
        str(keyfile),
        "-in",
        str(certfile),
        "-passout",
        f"pass:{password}",
    ]
    if use_legacy:
        cmd.insert(3, "-legacy")

    try:
        completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as first_exc:
        # Older OpenSSL builds reject -legacy; retry without it.
        if use_legacy:
            cmd = [c for c in cmd if c != "-legacy"]
            try:
                completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as second_exc:
                detail = (second_exc.stderr or second_exc.stdout or str(second_exc)).strip()
                raise RuntimeError(f"openssl pkcs12 failed: {detail}") from second_exc
        else:
            detail = (first_exc.stderr or first_exc.stdout or str(first_exc)).strip()
            raise RuntimeError(f"openssl pkcs12 failed: {detail}") from first_exc

    if completed.stderr.strip():
        print(f"[aws] openssl: {completed.stderr.strip()}", flush=True)
    if not p12_path.is_file() or p12_path.stat().st_size == 0:
        raise RuntimeError(f"openssl did not create a usable PKCS#12 file at {p12_path}")

    print(
        f"[aws] Created {p12_path.name} for Si Connect "
        f"(certificate password configured)",
        flush=True,
    )
    return {
        "p12file": str(p12_path),
        "p12_password": password,
    }


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
    out_dir = Path(__file__).with_name(".certs")
    files = export_client_identity(config["aws"], out_dir)
    password = str(config["aws"].get("p12_password") or DEFAULT_P12_PASSWORD)
    files.update(
        export_pkcs12(
            files["certfile"],
            files["keyfile"],
            out_dir,
            password=password,
        )
    )
    print(json.dumps(files, indent=2))
    print(describe_certificate(files["certfile"]))
