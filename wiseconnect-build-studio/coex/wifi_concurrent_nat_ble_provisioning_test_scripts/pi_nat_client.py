#!/usr/bin/env python3
"""Connect a Pi Wi-Fi interface to the DUT SoftAP and verify NAT.

Runs on the Raspberry Pi as root. The original Wi-Fi connection is restored
in a finally block so both passing and failing tests leave the bench usable.
Compatible with Raspberry Pi OS Buster / Python 3.7.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SOFTAP_FREQS = " ".join(str(2407 + 5 * ch) for ch in range(1, 14))
ASSOC_ATTEMPTS = 4


def log(message: str) -> None:
    print("[pi-nat] " + message, flush=True)


def run(args: List[str], timeout: int = 30, check: bool = True) -> str:
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    if check and proc.returncode != 0:
        raise RuntimeError("command failed (%s): %s" % (proc.returncode, out))
    return out


def interface_ipv4(interface: str) -> Optional[str]:
    out = run(
        ["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"],
        check=False,
    )
    for line in out.splitlines():
        fields = line.split()
        if "inet" in fields:
            return fields[fields.index("inet") + 1].split("/", 1)[0]
    return None


def wait_for_ssid(interface: str, ssid: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = run(["iwgetid", interface, "-r"], check=False).strip()
        if current == ssid:
            return
        time.sleep(1)
    raise TimeoutError("Wi-Fi interface %s did not associate with %r" % (interface, ssid))


def wpa_cli(interface: str, *args: str, check_ok: bool = False) -> str:
    """Run wpa_cli and reject its common exit-0/FAIL response."""
    out = run(["wpa_cli", "-i", interface] + list(args), check=False)
    if check_ok and (not out or out.splitlines()[-1].strip() != "OK"):
        raise RuntimeError("wpa_cli %s failed: %s" % (" ".join(args), out or "(no output)"))
    return out


def wait_for_ap_visible(interface: str, ssid: str, timeout: float) -> None:
    """Require the DUT SoftAP to be visible before attempting association."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        scan = wpa_cli(interface, "scan")
        scan_status = scan.splitlines()[-1].strip() if scan else ""
        if scan_status not in ("OK", "FAIL-BUSY"):
            raise RuntimeError("wpa_cli scan failed: %s" % (scan or "(no output)"))
        time.sleep(3)
        last = wpa_cli(interface, "scan_results")
        for line in last.splitlines()[1:]:
            fields = line.split("\t", 4)
            if len(fields) == 5 and fields[4] == ssid:
                log("DUT SoftAP %r is visible on %s" % (ssid, interface))
                return
    nearby = [line for line in last.splitlines()[1:] if line.strip()][-8:]
    raise TimeoutError(
        "DUT SoftAP %r was not visible on %s; nearby=%s"
        % (ssid, interface, nearby or ["(none)"])
    )


def renew_dhcp(interface: str) -> None:
    """Best-effort renewal used while restoring the Pi's original network."""
    if shutil.which("dhcpcd"):
        run(["dhcpcd", "-n", interface], timeout=45, check=False)
    elif shutil.which("dhclient"):
        run(["dhclient", "-1", interface], timeout=60, check=False)
    else:
        raise RuntimeError("Neither dhcpcd nor dhclient is installed")


def acquire_dhcp_ipv4(
    interface: str,
    prefix: str,
    timeout: float,
    allow_dhcpcd: bool = True,
) -> Optional[str]:
    """Try each installed DHCP client and return a matching lease, if any.

    Raspberry Pi images vary: some run dhcpcd as a daemon, some use
    dhclient, and minimal images often provide udhcpc.  Merely finding a
    dhcpcd binary does not mean that daemon owns this interface, so do not
    stop after a silent ``dhcpcd -n``.
    """
    clients: List[List[str]] = []
    # Standalone clients do not reload the transient wpa_cli profile.  Prefer
    # them over the system dhcpcd daemon for this isolated test connection.
    if shutil.which("dhclient"):
        clients.append(["dhclient", "-1", "-v", interface])
    if shutil.which("udhcpc"):
        clients.append(["udhcpc", "-n", "-q", "-i", interface, "-t", "4", "-T", "3"])
    if allow_dhcpcd and shutil.which("dhcpcd"):
        clients.append(["dhcpcd", "-n", interface])
    if not clients:
        if not allow_dhcpcd and shutil.which("dhcpcd"):
            log(
                "Skipping system dhcpcd because it can reload and remove the "
                "temporary wpa_cli network; proceeding to static fallback"
            )
        else:
            log("No safe DHCP client is installed (tried dhclient and udhcpc)")
        return None

    deadline = time.time() + max(1.0, timeout)
    for command in clients:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        log("Requesting DHCP lease with %s" % command[0])
        try:
            output = run(command, timeout=max(1, min(8, int(remaining))), check=False)
            if output:
                log("%s: %s" % (command[0], output[-600:].replace("\n", " | ")))
        except subprocess.TimeoutExpired:
            log("%s timed out without a lease" % command[0])
        try:
            return wait_for_ipv4(
                interface, prefix, max(1.0, min(4.0, deadline - time.time()))
            )
        except TimeoutError:
            log("%s did not provide a %s* address" % (command[0], prefix))
    return None


def configure_static_ipv4(interface: str, cidr: str, prefix: str) -> str:
    """Install the explicit diagnostic fallback address on the DUT subnet."""
    if "/" not in cidr:
        raise ValueError("static_client_cidr must include a prefix length: %r" % cidr)
    address = cidr.split("/", 1)[0]
    if not address.startswith(prefix):
        raise ValueError(
            "static_client_cidr %r is outside expected subnet prefix %r" % (cidr, prefix)
        )
    run(["ip", "-4", "addr", "flush", "dev", interface, "scope", "global"], check=False)
    run(["ip", "addr", "add", cidr, "dev", interface])
    return address


def ensure_iperf3(auto_install: bool) -> None:
    """Ensure the Pi throughput client exists before wlan0 is switched."""
    if shutil.which("iperf3"):
        log("iperf3 prerequisite is available")
        return
    if not auto_install:
        raise RuntimeError(
            "iperf3 is not installed on the Raspberry Pi and auto_install_iperf3 is false"
        )
    if os.geteuid() != 0:
        raise RuntimeError("iperf3 installation requires root privileges")
    if not shutil.which("apt-get"):
        raise RuntimeError(
            "iperf3 is missing and apt-get is unavailable; install iperf3 on the Pi"
        )
    log("iperf3 is missing; installing it over the Pi management network")
    run(
        ["apt-get", "-o", "Acquire::Retries=3", "update"],
        timeout=240,
    )
    run(
        [
            "env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
            "-o", "DPkg::Lock::Timeout=60", "install", "-y", "iperf3",
        ],
        timeout=240,
    )
    if not shutil.which("iperf3"):
        raise RuntimeError("iperf3 installation completed but the executable is unavailable")
    log("iperf3 installed successfully")


def wait_for_ipv4(interface: str, prefix: str, timeout: float) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        address = interface_ipv4(interface)
        if address and address.startswith(prefix):
            return address
        time.sleep(1)
    raise TimeoutError(
        "No %s* address on %s (last=%r)" % (prefix, interface, interface_ipv4(interface))
    )


class WifiSwitch:
    def __init__(self, interface: str, ssid: str, password: str):
        self.interface = interface
        self.ssid = ssid
        self.password = password
        self.backend = "nmcli" if shutil.which("nmcli") else "wpa_cli"
        self.original_ssid = run(["iwgetid", interface, "-r"], check=False).strip()
        self.original_connection = ""
        self.original_network_id = ""
        self.temp_network_id = ""

    def create_wpa_network(self) -> None:
        """Create the non-persistent directed SoftAP profile in wpa_supplicant."""
        self.temp_network_id = wpa_cli(
            self.interface, "add_network"
        ).splitlines()[-1].strip()
        if not self.temp_network_id.isdigit():
            raise RuntimeError("wpa_cli add_network failed: %s" % self.temp_network_id)
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "ssid", json.dumps(self.ssid), check_ok=True,
        )
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "psk", json.dumps(self.password), check_ok=True,
        )
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "key_mgmt", "WPA-PSK", check_ok=True,
        )
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "scan_ssid", "1", check_ok=True,
        )
        # The Si91x SoftAP is 2.4 GHz only; skipping 5 GHz keeps each directed
        # scan short enough to catch its beacons while BLE shares the radio.
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "scan_freq", SOFTAP_FREQS, check_ok=True,
        )
        wpa_cli(
            self.interface, "set_network", self.temp_network_id,
            "freq_list", SOFTAP_FREQS, check_ok=True,
        )
        wpa_cli(
            self.interface, "enable_network", self.temp_network_id, check_ok=True,
        )

    def connect(self) -> None:
        log("Wi-Fi backend=%s original_ssid=%r" % (self.backend, self.original_ssid))
        if shutil.which("rfkill"):
            run(["rfkill", "unblock", "wifi"], check=False)
        run(["ip", "link", "set", "dev", self.interface, "up"], check=False)
        if self.backend == "nmcli":
            self.original_connection = run(
                ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", self.interface],
                check=False,
            ).strip()
            run(["nmcli", "connection", "delete", "wcbs-nat-test"], check=False)
            run(
                [
                    "nmcli", "device", "wifi", "connect", self.ssid,
                    "password", self.password, "ifname", self.interface,
                    "name", "wcbs-nat-test",
                ],
                timeout=60,
            )
        else:
            status = wpa_cli(self.interface, "status")
            for line in status.splitlines():
                if line.startswith("id="):
                    self.original_network_id = line.split("=", 1)[1].strip()
            try:
                wait_for_ap_visible(self.interface, self.ssid, 30)
            except TimeoutError as exc:
                # A hidden/malformed SSID beacon can still accept a directed
                # association. Visibility is useful diagnostics, but DHCP and
                # the routed probe are the authoritative NAT checks.
                log("SoftAP visibility warning: %s" % exc)
                log("Trying directed association with scan_ssid=1")
            self.create_wpa_network()
            last_error: Optional[Exception] = None
            for attempt in range(1, ASSOC_ATTEMPTS + 1):
                log("SoftAP association attempt %d/%d" % (attempt, ASSOC_ATTEMPTS))
                wpa_cli(
                    self.interface, "select_network", self.temp_network_id,
                    check_ok=True,
                )
                wpa_cli(self.interface, "reassociate", check_ok=True)
                try:
                    wait_for_ssid(self.interface, self.ssid, 30)
                    last_error = None
                    break
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    status = wpa_cli(self.interface, "status")
                    log("Association state after attempt %d:\n%s" % (attempt, status))
                    if attempt < ASSOC_ATTEMPTS:
                        wpa_cli(self.interface, "scan")
                        time.sleep(3)
            if last_error:
                raise RuntimeError(
                    "%s; final wpa_supplicant state:\n%s"
                    % (last_error, wpa_cli(self.interface, "status"))
                )
        if self.backend == "nmcli":
            wait_for_ssid(self.interface, self.ssid, 45)

    def reassociate(self) -> None:
        """Perform one bounded re-association to the already configured SoftAP."""
        log("Re-associating once before applying the static diagnostic fallback")
        if self.backend == "nmcli":
            run(["nmcli", "connection", "up", "wcbs-nat-test"], timeout=45)
        else:
            if not self.temp_network_id:
                raise RuntimeError("temporary SoftAP network is not configured")
            network_ids = {
                line.split("\t", 1)[0].strip()
                for line in wpa_cli(self.interface, "list_networks").splitlines()[1:]
                if line.strip()
            }
            if self.temp_network_id not in network_ids:
                log("Temporary wpa_cli profile was removed; recreating it")
                self.create_wpa_network()
            wpa_cli(
                self.interface, "select_network", self.temp_network_id, check_ok=True
            )
            wpa_cli(self.interface, "reassociate", check_ok=True)
        wait_for_ssid(self.interface, self.ssid, 30)

    def restore(self) -> None:
        log("Restoring original Pi Wi-Fi connection")
        # Remove a DHCP lease or the controlled static fallback before the
        # original connection is selected again.
        run(
            ["ip", "-4", "addr", "flush", "dev", self.interface, "scope", "global"],
            check=False,
        )
        if self.backend == "nmcli":
            run(["nmcli", "connection", "down", "wcbs-nat-test"], check=False)
            run(["nmcli", "connection", "delete", "wcbs-nat-test"], check=False)
            if self.original_connection and self.original_connection != "--":
                run(
                    ["nmcli", "connection", "up", self.original_connection],
                    timeout=60,
                    check=False,
                )
        else:
            if self.temp_network_id:
                wpa_cli(
                    self.interface, "remove_network", self.temp_network_id,
                    check_ok=False,
                )
            if self.original_network_id:
                wpa_cli(
                    self.interface, "select_network", self.original_network_id,
                    check_ok=False,
                )
            else:
                wpa_cli(self.interface, "reconfigure", check_ok=False)
        if self.original_ssid:
            try:
                wait_for_ssid(self.interface, self.original_ssid, 45)
                renew_dhcp(self.interface)
                log("Restored SSID %r" % self.original_ssid)
            except Exception as exc:  # noqa: BLE001
                log("Restore warning: %s" % exc)
        else:
            renew_dhcp(self.interface)


def ping(interface: str, host: str) -> bool:
    proc = subprocess.run(
        ["ping", "-I", interface, "-c", "1", "-W", "3", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    return proc.returncode == 0


def tcp_probe(interface: str, source_ip: str, host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        # Root-only Linux option: guarantee the NAT probe leaves via DUT SoftAP.
        sock.setsockopt(socket.SOL_SOCKET, 25, interface.encode("ascii") + b"\0")
        sock.bind((source_ip, 0))
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def iperf3_test(
    interface: str,
    source_ip: str,
    host: str,
    port: int,
    duration: int,
    omit: int,
    parallel: int,
    reverse: bool,
    binary: str = "iperf3",
) -> float:
    """Run one JSON iperf3 test and return receiver throughput in Mbit/s."""
    if "/" not in binary and not shutil.which(binary):
        raise RuntimeError("iperf3 is not installed on the Raspberry Pi")
    command = [
        binary, "-c", host, "-p", str(port), "-B", source_ip,
        "-t", str(duration), "-O", str(omit), "-P", str(parallel), "-J",
    ]
    if reverse:
        command.append("-R")
    output = run(command, timeout=duration + omit + 45)
    try:
        payload = json.loads(output)
        if payload.get("error"):
            raise RuntimeError("iperf3 reported: %s" % payload["error"])
        end = payload.get("end") or {}
        summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
        bits_per_second = float(summary.get("bits_per_second") or 0.0)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Could not parse iperf3 JSON output: %s" % output[-1000:]) from exc
    mbps = bits_per_second / 1000000.0
    direction = "downlink" if reverse else "uplink"
    log("iperf3 TCP %s: %.2f Mbit/s" % (direction, mbps))
    return mbps


def verify(config: Dict[str, Any]) -> Dict[str, Any]:
    interface = str(config.get("wifi_interface") or "wlan0")
    ssid = str(config["softap_ssid"])
    password = str(config["softap_password"])
    gateway = str(config.get("gateway") or "192.168.10.10")
    prefix = str(config.get("client_subnet_prefix") or "192.168.10.")
    target = str(config.get("probe_host") or "192.168.50.36")
    port = int(config.get("probe_port") or 22)
    duration = float(config.get("duration_s") or 60)
    interval = max(1.0, float(config.get("interval_s") or 2))
    minimum = float(config.get("min_success_rate") or 0.90)
    throughput_enabled = bool(config.get("throughput_enabled", True))
    iperf_host = str(config.get("iperf_host") or target)
    iperf_port = int(config.get("iperf_port") or 5201)
    throughput_duration = max(1, int(config.get("throughput_duration_s") or 60))
    throughput_omit = max(0, int(config.get("throughput_omit_s") or 2))
    throughput_parallel = max(1, int(config.get("throughput_parallel_streams") or 1))
    min_uplink = float(config.get("min_uplink_mbps") or 0.1)
    min_downlink = float(config.get("min_downlink_mbps") or 0.1)
    auto_install_iperf3 = bool(config.get("auto_install_iperf3", True))
    dhcp_required = bool(config.get("dhcp_required", False))
    static_client_cidr = str(config.get("static_client_cidr") or "192.168.10.20/24")
    dhcp_timeout = max(1.0, float(config.get("dhcp_timeout_s") or 20))

    if throughput_enabled:
        # Do this while the Pi still has its normal management-network route.
        ensure_iperf3(auto_install_iperf3)

    switch = WifiSwitch(interface, ssid, password)
    result: Dict[str, Any] = {
        "ok": False,
        "interface": interface,
        "softap_ssid": ssid,
        "probe_host": target,
        "probe_port": port,
        "duration_s": duration,
        "throughput_enabled": throughput_enabled,
        "dhcp_required": dhcp_required,
    }
    route_target = ""
    try:
        switch.connect()
        address = acquire_dhcp_ipv4(
            interface,
            prefix,
            dhcp_timeout,
            allow_dhcpcd=(switch.backend != "wpa_cli"),
        )
        if address:
            result["dhcp_ok"] = True
            result["address_source"] = "dhcp"
            log("DUT DHCP lease acquired: %s" % address)
        else:
            result["dhcp_ok"] = False
            if dhcp_required:
                raise RuntimeError(
                    "Associated with DUT SoftAP but its DHCP server did not provide a %s* lease"
                    % prefix
                )
            current_ssid = run(["iwgetid", interface, "-r"], check=False).strip()
            if current_ssid != ssid:
                log(
                    "SoftAP association dropped while waiting for DHCP (current=%r)"
                    % current_ssid
                )
                switch.reassociate()
            address = configure_static_ipv4(interface, static_client_cidr, prefix)
            result["address_source"] = "static_fallback"
            result["dhcp_warning"] = (
                "DUT DHCP lease was not received; NAT was tested with an explicit static address"
            )
            log(
                "WARNING: DUT DHCP lease not received; using diagnostic static fallback %s"
                % static_client_cidr
            )
        result["client_ip"] = address
        log("Connected to DUT SoftAP with IPv4 %s" % address)
        if not ping(interface, gateway):
            raise RuntimeError("DUT SoftAP gateway %s is not reachable" % gateway)
        result["gateway_ok"] = True
        log("DUT gateway %s reachable" % gateway)

        # Force all probe/iperf traffic to the upstream host through the DUT.
        # Without this /32 route, the Pi's Ethernet management default route
        # could bypass NAT even when iperf3 is bound to the wlan0 source IP.
        route_target = socket.gethostbyname(iperf_host)
        run(
            [
                "ip", "route", "replace", route_target + "/32", "via", gateway,
                "dev", interface, "src", address,
            ]
        )
        route_check = run(["ip", "route", "get", route_target, "from", address])
        if ("dev %s" % interface) not in route_check:
            raise RuntimeError("Throughput route does not use %s: %s" % (interface, route_check))
        log("NAT traffic route pinned to %s via %s" % (interface, gateway))

        attempts = 0
        successes = 0
        deadline = time.time() + duration
        while time.time() < deadline:
            attempts += 1
            ok = tcp_probe(interface, address, target, port)
            successes += 1 if ok else 0
            log(
                "NAT TCP %s:%d %s (%d/%d)"
                % (target, port, "PASS" if ok else "FAIL", successes, attempts)
            )
            time.sleep(min(interval, max(0.0, deadline - time.time())))
        rate = (float(successes) / attempts) if attempts else 0.0
        result.update(
            {"attempts": attempts, "successes": successes, "success_rate": rate}
        )
        if not successes or rate < minimum:
            raise RuntimeError(
                "NAT success rate %.1f%% is below required %.1f%%"
                % (rate * 100, minimum * 100)
            )

        if throughput_enabled:
            iperf_bin = str(config.get("iperf3_bin") or "iperf3")
            last_error = None
            uplink = downlink = 0.0
            for attempt in range(1, 3):
                try:
                    uplink = iperf3_test(
                        interface, address, iperf_host, iperf_port,
                        throughput_duration, throughput_omit, throughput_parallel,
                        False, iperf_bin,
                    )
                    time.sleep(1)
                    downlink = iperf3_test(
                        interface, address, iperf_host, iperf_port,
                        throughput_duration, throughput_omit, throughput_parallel,
                        True, iperf_bin,
                    )
                    last_error = None
                    break
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    log("iperf3 attempt %d/2 failed: %s" % (attempt, exc))
                    time.sleep(3)
            if last_error is not None:
                raise last_error
            result["throughput"] = {
                "host": iperf_host,
                "port": iperf_port,
                "duration_s": throughput_duration,
                "uplink_mbps": uplink,
                "downlink_mbps": downlink,
                "min_uplink_mbps": min_uplink,
                "min_downlink_mbps": min_downlink,
            }
            if uplink < min_uplink or downlink < min_downlink:
                raise RuntimeError(
                    "NAT throughput below requirement: uplink %.2f/%.2f Mbit/s, "
                    "downlink %.2f/%.2f Mbit/s"
                    % (uplink, min_uplink, downlink, min_downlink)
                )
            log(
                "NAT throughput PASS: uplink %.2f Mbit/s, downlink %.2f Mbit/s"
                % (uplink, downlink)
            )
        result["ok"] = True
        log("NAT stable for %.0fs: %d/%d TCP probes passed" % (duration, successes, attempts))
        return result
    finally:
        if route_target:
            run(
                ["ip", "route", "del", route_target + "/32", "via", gateway,
                 "dev", interface],
                check=False,
            )
        switch.restore()
        result["restored"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    try:
        result = verify(config)
    except Exception as exc:  # noqa: BLE001
        result = {"ok": False, "error": str(exc)}
        log("FAILED: %s" % exc)
        Path(args.result).write_text(json.dumps(result, indent=2), encoding="utf-8")
        return 1
    Path(args.result).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
