"""
WLAN MC/BC filter functional automation
(active IDs: C1726541-C1726543, C1726545-C1726549, C1726552-C1726554).

DUT boots in coex WLAN+BLE, joins AP, enters TA powersave, then:
  - Sniffer assert: power-save (PM) bit set on DUT frames
  - Filter STATISTICS PASS/FAIL (primary functional check):

  BC ON  -> block ALL BC   (bc_pass == 0, bc_drop >= min)
  BC OFF -> allow ALL BC   (bc_pass/rx >= min, bc_drop == 0)
  MC ON  + allowlist IPs   -> those IPs pass; other MC blocked
  MC ON  + empty allowlist -> block ALL MC
  MC OFF -> allow ALL MC   (allowlist unused)

Procedure (most cases):
  1. DUT (WLAN+BLE coex) + Raspi join same AP
  2. Configure beacon drop + groupcast filter + allowlist
  3. Enter TA powersave (WLAN + BLE); sniffer captures PM bit
  4. Clear FW counters; idle while Raspi generates BC/MC (DUT stays in PS)
  5. Read stats and PASS/FAIL; then assert sniffer PM bit

Special scenarios:
  C1726553 — AP Wi-Fi radio OFF/ON -> filter cleared -> re-apply -> filtering resumes
  C1726554 — AP Wi-Fi radio OFF/ON -> filter cleared after reconnect (no re-apply)

Author: Anil Kumar A
"""

import re
import time
import textwrap
from dataclasses import dataclass

import pytest

from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)


def logger():
    return get_logger(__name__)


class SuiteConfig:
    PORT = 5001
    MC_ALLOWLIST_IPS = [
        "224.0.0.50",
        "224.0.0.51",
        "224.0.0.52",
        "224.0.0.53",
        "224.0.0.54",
        "224.0.0.55",
    ]
    MC_NONALLOW_IPS = ["224.0.0.60"]
    MC_ALLOWLIST_IPV6_IPS = [
        "ff15::50",
        "ff15::51",
        "ff15::52",
        "ff15::53",
        "ff15::54",
        "ff15::55",
    ]
    MC_NONALLOW_IPV6_IPS = ["ff15::60"]
    PACKETS_PER_GROUP = 100
    PPS = 50
    GAP_BETWEEN_GROUPS_SEC = 2
    PAYLOAD_SIZE = 200
    BEACON_DROP_THRESHOLD = 5000
    IDLE_TRAFFIC_WAIT_SEC = 30
    MIN_FILTER_STAT_PACKETS = 10


# ---------------------------------------------------------------------------
# Expected filter behaviour (statistics)
# ---------------------------------------------------------------------------
@dataclass
class ExpectedFilterBehavior:
    expect_bc_drop: bool = False
    expect_bc_pass: bool = False
    expect_mc_allow_pass: bool = False
    expect_mc_nonallow_drop: bool = False
    expect_mc_pass_when_filter_off: bool = False
    # PPE configured with >2 MC IPs: FW falls back; NWP must own filter counters.
    expect_nwp_ownership: bool = False
    min_packets: int = SuiteConfig.MIN_FILTER_STAT_PACKETS
    notes: str = ""


def filter_path(enable_bcast, enable_mcast, filter_mode, allowlist_count):
    if not enable_bcast and not enable_mcast:
        return "none"
    if filter_mode == 1 or (filter_mode == 0 and enable_mcast and allowlist_count > 2):
        return "nwp"
    return "ppe"


def build_expected(
    enable_bcast_filter,
    enable_mcast_filter,
    filter_mode,
    allowlist_ips,
    send_broadcast,
):
    allow = list(allowlist_ips or [])
    path = filter_path(
        enable_bcast_filter, enable_mcast_filter, filter_mode, len(allow)
    )
    exp = ExpectedFilterBehavior(
        notes=(
            f"path={path} BC={enable_bcast_filter} MC={enable_mcast_filter} "
            f"mode={filter_mode} allow={len(allow)}"
        )
    )

    if send_broadcast:
        if enable_bcast_filter:
            exp.expect_bc_drop = True
        else:
            exp.expect_bc_pass = True

    if enable_mcast_filter:
        if allow:
            exp.expect_mc_allow_pass = True
            exp.expect_mc_nonallow_drop = True
        else:
            exp.expect_mc_nonallow_drop = True
    else:
        exp.expect_mc_pass_when_filter_off = True

    return exp


# ---------------------------------------------------------------------------
# Raspi BC/MC traffic generator
# ---------------------------------------------------------------------------
class WifiClientBcMcTraffic:
    """Generate IPv4 (and optional IPv6) BC/MC UDP bursts from wifi_client (Raspi)."""

    # Default path for IPv4-only cases.
    TRAFFIC_SCRIPT = textwrap.dedent(
        """\
        import socket, time, sys, struct, subprocess
        SERVER_IF_IP = "{server_if_ip}"
        BC_IP = "{bc_ip}"
        IFACE = "{iface}"
        PORT = {port}
        ALLOW_STREAMS = {allow_streams}
        NONALLOW_STREAMS = {nonallow_streams}
        SEND_BROADCAST = {send_broadcast}
        PACKETS_PER_GROUP = {packets_per_group}
        PPS = {pps}
        GAP_BETWEEN_GROUPS_SEC = {gap_sec}
        PAYLOAD_SIZE = {payload_size}
        NEED_MC = bool(ALLOW_STREAMS or NONALLOW_STREAMS)

        def payload(tag, seq):
            b = ("%s|seq=%d|ts=%.6f" % (tag, seq, time.time())).encode("ascii")
            return b + (b"X" * max(0, PAYLOAD_SIZE - len(b)))

        def send_group_burst(sock, dst_ip, label, count, pps):
            gap = 1.0 / float(pps)
            print("  --> Sending %d packets to %s (%s) @ %d pps" % (count, dst_ip, label, pps))
            for seq in range(1, count + 1):
                sock.sendto(payload(label, seq), (dst_ip, PORT))
                time.sleep(gap)
            print("  --> Done %s: %d packets sent" % (dst_ip, count))
            time.sleep(GAP_BETWEEN_GROUPS_SEC)

        def live_if_ip(iface, fallback):
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show", iface],
                    stderr=subprocess.STDOUT,
                ).decode().strip()
                for line in out.splitlines():
                    parts = line.split()
                    if "inet" in parts:
                        return parts[parts.index("inet") + 1].split("/")[0]
            except Exception as exc:
                print("live_if_ip note: %s" % exc)
            return fallback

        def pin_multicast_if(sock, iface, if_ip):
            try:
                idx = socket.if_nametoindex(iface)
                mreqn = struct.pack("=4s4si", bytes(4), bytes(4), idx)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
                print("IP_MULTICAST_IF pinned via ip_mreqn ifindex=%d" % idx)
                return
            except Exception as exc:
                print("ip_mreqn MULTICAST_IF note: %s" % exc)
            if if_ip:
                try:
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(if_ip)
                    )
                    print("IP_MULTICAST_IF pinned via inet_aton(%s)" % if_ip)
                    return
                except OSError as exc:
                    print("inet_aton MULTICAST_IF note: %s" % exc)
            print("WARNING: IP_MULTICAST_IF skipped — sending MC via routing table")

        SERVER_IF_IP = live_if_ip(IFACE, SERVER_IF_IP)
        if SERVER_IF_IP and BC_IP.endswith(".255"):
            parts = SERVER_IF_IP.split(".")
            if len(parts) == 4:
                BC_IP = ".".join(parts[:3] + ["255"])
        print("SERVER_IF_IP=%s IFACE=%s BC_IP=%s NEED_MC=%s" % (SERVER_IF_IP, IFACE, BC_IP, NEED_MC))

        bc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        bc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        mc_sock = None
        if NEED_MC:
            mc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            mc_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            pin_multicast_if(mc_sock, IFACE, SERVER_IF_IP)

        try:
            if SEND_BROADCAST:
                print("[STEP 1] Broadcast burst -> %s" % BC_IP)
                send_group_burst(bc_sock, BC_IP, "BC", PACKETS_PER_GROUP, PPS)
            if NEED_MC:
                print("[STEP 2] Allowlisted MC groups")
                for ip in ALLOW_STREAMS:
                    send_group_burst(mc_sock, ip, "ALLOW_%s" % ip, PACKETS_PER_GROUP, PPS)
                print("[STEP 3] Non-allowlisted MC groups")
                for ip in NONALLOW_STREAMS:
                    send_group_burst(mc_sock, ip, "BLOCK_%s" % ip, PACKETS_PER_GROUP, PPS)
            print("All traffic generation completed.")
        finally:
            bc_sock.close()
            if mc_sock is not None:
                mc_sock.close()
        """
    )

    # C1726549 only — used when allow/nonallow streams include IPv6 MC.
    TRAFFIC_SCRIPT_V4_V6 = textwrap.dedent(
        """\
        import errno, socket, time, sys, struct, subprocess
        SERVER_IF_IP = "{server_if_ip}"
        BC_IP = "{bc_ip}"
        IFACE = "{iface}"
        PORT = {port}
        ALLOW_STREAMS = {allow_streams}
        NONALLOW_STREAMS = {nonallow_streams}
        SEND_BROADCAST = {send_broadcast}
        PACKETS_PER_GROUP = {packets_per_group}
        PPS = {pps}
        GAP_BETWEEN_GROUPS_SEC = {gap_sec}
        PAYLOAD_SIZE = {payload_size}

        def is_v6(ip):
            return ":" in str(ip)

        ALLOW_V4 = [ip for ip in ALLOW_STREAMS if not is_v6(ip)]
        ALLOW_V6 = [ip for ip in ALLOW_STREAMS if is_v6(ip)]
        BLOCK_V4 = [ip for ip in NONALLOW_STREAMS if not is_v6(ip)]
        BLOCK_V6 = [ip for ip in NONALLOW_STREAMS if is_v6(ip)]
        NEED_MC_V4 = bool(ALLOW_V4 or BLOCK_V4)
        NEED_MC_V6 = bool(ALLOW_V6 or BLOCK_V6)

        def payload(tag, seq):
            b = ("%s|seq=%d|ts=%.6f" % (tag, seq, time.time())).encode("ascii")
            return b + (b"X" * max(0, PAYLOAD_SIZE - len(b)))

        def send_group_burst(sock, dst, label, count, pps):
            gap = 1.0 / float(pps)
            print("  --> Sending %d packets to %s (%s) @ %d pps" % (count, dst, label, pps))
            for seq in range(1, count + 1):
                sock.sendto(payload(label, seq), dst)
                time.sleep(gap)
            print("  --> Done %s: %d packets sent" % (dst, count))
            time.sleep(GAP_BETWEEN_GROUPS_SEC)

        def live_if_ip(iface, fallback):
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show", iface],
                    stderr=subprocess.STDOUT,
                ).decode().strip()
                for line in out.splitlines():
                    parts = line.split()
                    if "inet" in parts:
                        return parts[parts.index("inet") + 1].split("/")[0]
            except Exception as exc:
                print("live_if_ip note: %s" % exc)
            return fallback

        def pin_multicast_if_v4(sock, iface, if_ip):
            try:
                idx = socket.if_nametoindex(iface)
                mreqn = struct.pack("=4s4si", bytes(4), bytes(4), idx)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
                print("IP_MULTICAST_IF pinned via ip_mreqn ifindex=%d" % idx)
                return
            except Exception as exc:
                print("ip_mreqn MULTICAST_IF note: %s" % exc)
            if if_ip:
                try:
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(if_ip)
                    )
                    print("IP_MULTICAST_IF pinned via inet_aton(%s)" % if_ip)
                    return
                except OSError as exc:
                    print("inet_aton MULTICAST_IF note: %s" % exc)
            print("WARNING: IP_MULTICAST_IF skipped — sending MC via routing table")

        def ensure_ipv6_on_iface(iface):
            # errno 99 often means no usable IPv6 source on the iface.
            try:
                subprocess.call(
                    ["sudo", "sysctl", "-w", "net.ipv6.conf.%s.disable_ipv6=0" % iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as exc:
                print("enable ipv6 note: %s" % exc)
            try:
                out = subprocess.check_output(
                    ["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "link"],
                    stderr=subprocess.STDOUT,
                ).decode().strip()
                if "inet6" in out:
                    print("IPv6 link-local OK on %s: %s" % (iface, out.split()[3] if len(out.split()) > 3 else out))
                    return True
            except Exception as exc:
                print("link-local probe note: %s" % exc)
            # Nudge kernel to regenerate link-local (down/up can disrupt WLAN — avoid).
            print("WARNING: no IPv6 link-local on %s yet; continuing" % iface)
            return False

        def make_v6_sock(iface):
            idx = socket.if_nametoindex(iface)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
            # Bind to this iface scope so kernel can pick a valid IPv6 source.
            try:
                sock.bind(("::", 0, 0, idx))
                print("IPv6 sock bound to (::,0,0,%d)" % idx)
            except OSError as exc:
                print("IPv6 bind note: %s" % exc)
            return sock, idx

        def send_v6_group(sock_holder, iface, ip, label, count, pps):
            # sock_holder is a 1-list so we can recreate after errno 99.
            idx = socket.if_nametoindex(iface)
            dst = (ip, PORT, 0, idx)
            for attempt in range(2):
                try:
                    send_group_burst(sock_holder[0], dst, label, count, pps)
                    return
                except OSError as exc:
                    if getattr(exc, "errno", None) != errno.EADDRNOTAVAIL or attempt == 1:
                        raise
                    print(
                        "IPv6 send errno 99 (EADDRNOTAVAIL) on %s — "
                        "recreate socket and retry once" % ip
                    )
                    try:
                        sock_holder[0].close()
                    except Exception:
                        pass
                    time.sleep(1)
                    ensure_ipv6_on_iface(iface)
                    sock_holder[0], _ = make_v6_sock(iface)

        SERVER_IF_IP = live_if_ip(IFACE, SERVER_IF_IP)
        if SERVER_IF_IP and BC_IP.endswith(".255"):
            parts = SERVER_IF_IP.split(".")
            if len(parts) == 4:
                BC_IP = ".".join(parts[:3] + ["255"])
        print(
            "SERVER_IF_IP=%s IFACE=%s BC_IP=%s NEED_MC_V4=%s NEED_MC_V6=%s"
            % (SERVER_IF_IP, IFACE, BC_IP, NEED_MC_V4, NEED_MC_V6)
        )

        bc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        bc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        mc_sock_v4 = None
        mc_sock_v6_holder = [None]
        ifindex = 0
        if NEED_MC_V4:
            mc_sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            mc_sock_v4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            pin_multicast_if_v4(mc_sock_v4, IFACE, SERVER_IF_IP)
        if NEED_MC_V6:
            ensure_ipv6_on_iface(IFACE)
            mc_sock_v6_holder[0], ifindex = make_v6_sock(IFACE)
            print("IPV6_MULTICAST_IF pinned ifindex=%d" % ifindex)

        try:
            if SEND_BROADCAST:
                print("[STEP 1] Broadcast burst -> %s" % BC_IP)
                send_group_burst(bc_sock, (BC_IP, PORT), "BC", PACKETS_PER_GROUP, PPS)
            if NEED_MC_V4 or NEED_MC_V6:
                print("[STEP 2] Allowlisted MC groups (IPv4 + IPv6)")
                for ip in ALLOW_V4:
                    send_group_burst(
                        mc_sock_v4, (ip, PORT), "ALLOW_%s" % ip, PACKETS_PER_GROUP, PPS
                    )
                if ALLOW_V6:
                    # Brief settle after IPv4 bursts — avoids intermittent errno 99 on Pi.
                    time.sleep(2)
                    # Fresh socket before IPv6 groups (more reliable across dual bursts).
                    try:
                        if mc_sock_v6_holder[0] is not None:
                            mc_sock_v6_holder[0].close()
                    except Exception:
                        pass
                    ensure_ipv6_on_iface(IFACE)
                    mc_sock_v6_holder[0], ifindex = make_v6_sock(IFACE)
                for ip in ALLOW_V6:
                    send_v6_group(
                        mc_sock_v6_holder, IFACE, ip, "ALLOW_%s" % ip,
                        PACKETS_PER_GROUP, PPS,
                    )
                print("[STEP 3] Non-allowlisted MC groups (IPv4 + IPv6)")
                for ip in BLOCK_V4:
                    send_group_burst(
                        mc_sock_v4, (ip, PORT), "BLOCK_%s" % ip, PACKETS_PER_GROUP, PPS
                    )
                for ip in BLOCK_V6:
                    send_v6_group(
                        mc_sock_v6_holder, IFACE, ip, "BLOCK_%s" % ip,
                        PACKETS_PER_GROUP, PPS,
                    )
            print("All traffic generation completed.")
        finally:
            bc_sock.close()
            if mc_sock_v4 is not None:
                mc_sock_v4.close()
            if mc_sock_v6_holder[0] is not None:
                mc_sock_v6_holder[0].close()
        """
    )

    def __init__(self, wifi_client=None):
        self.wifi_client = wifi_client

    @staticmethod
    def _normalize_ip(host_ip):
        if host_ip is None:
            return None
        if isinstance(host_ip, bytes):
            host_ip = host_ip.decode()
        return str(host_ip).strip()

    def join_third_party_ap(self, wifi_access_point, interface="wlan0"):
        ssid = wifi_access_point.interfaces.wifi.ssid
        passphrase = wifi_access_point.interfaces.wifi.passphrase
        security = wifi_access_point.interfaces.wifi.security
        if hasattr(security, "name"):
            security = security.name

        wifi_if = self.wifi_client.interfaces.wifi
        if hasattr(wifi_if, "config") and isinstance(wifi_if.config, dict):
            wifi_if.config["interface"] = interface

        logger().info(f"wifi_client joining AP {ssid} on {interface}")
        wifi_if.join(ssid=ssid, passphrase=passphrase, security=security)
        time.sleep(5)
        host_ip = self._normalize_ip(wifi_if.get_ip_address())
        assert host_ip, "wifi_client failed to get IP after joining AP"
        logger().info(f"wifi_client IP: {host_ip}")
        return host_ip

    def leave(self):
        logger().info("wifi_client leaving AP")
        self.wifi_client.interfaces.wifi.leave()

    def _wlan0_ipv4(self, fallback=None, interface="wlan0"):
        wifi_if = self.wifi_client.interfaces.wifi
        py = (
            "python3 -c \""
            "import subprocess;"
            f"o=subprocess.check_output(['ip','-4','-o','addr','show','{interface}']).decode();"
            "ips=[L.split()[L.split().index('inet')+1].split('/')[0] "
            "for L in o.splitlines() if 'inet' in L.split()];"
            "print(ips[0] if ips else '')"
            "\""
        )
        try:
            rc, stdout, stderr = wifi_if.shell.execute(py)
            out = stdout.decode() if isinstance(stdout, bytes) else str(stdout)
            ip = out.strip().splitlines()[-1].strip() if out.strip() else None
            if ip and ip.count(".") == 3:
                return ip
        except Exception as exc:
            logger().info(f"wlan0 IP probe note: {exc}")
        return self._normalize_ip(fallback)

    def generate_traffic(
        self,
        host_ip,
        send_broadcast=True,
        allow_streams=None,
        nonallow_streams=None,
        packets_per_group=SuiteConfig.PACKETS_PER_GROUP,
        pps=SuiteConfig.PPS,
        gap_sec=SuiteConfig.GAP_BETWEEN_GROUPS_SEC,
        payload_size=SuiteConfig.PAYLOAD_SIZE,
        port=SuiteConfig.PORT,
        interface="wlan0",
    ):
        allow_streams = list(allow_streams or [])
        nonallow_streams = list(nonallow_streams or [])
        host_ip = self._wlan0_ipv4(fallback=host_ip, interface=interface)
        assert host_ip, "wifi_client has no IPv4 on wlan0 for BC/MC traffic"
        parts = host_ip.split(".")
        bc_ip = ".".join(parts[:3] + ["255"])

        # IPv4-only cases keep the original script; IPv6 only when streams need it
        # (C1726549). Other tests never hit the v4+v6 path.
        has_v6 = any(":" in str(ip) for ip in (allow_streams + nonallow_streams))
        script_tmpl = self.TRAFFIC_SCRIPT_V4_V6 if has_v6 else self.TRAFFIC_SCRIPT
        remote_path = (
            "/tmp/ipv4_ipv6_bc_mc_traffic_gen.py"
            if has_v6
            else "/tmp/ipv4_bc_mc_traffic_gen.py"
        )

        script = script_tmpl.format(
            server_if_ip=host_ip,
            bc_ip=bc_ip,
            iface=interface,
            port=port,
            allow_streams=repr(allow_streams),
            nonallow_streams=repr(nonallow_streams),
            send_broadcast=str(bool(send_broadcast)),
            packets_per_group=packets_per_group,
            pps=pps,
            gap_sec=gap_sec,
            payload_size=payload_size,
        )
        logger().info(
            f"Generate BC/MC from Raspi (BC={send_broadcast}, v6={has_v6}, "
            f"allow={allow_streams}, block={nonallow_streams})"
        )
        self.wifi_client.interfaces.wifi.shell.create_file(remote_path, script)

        # IPv6 path can hit intermittent errno 99 on Pi; retry whole script once.
        attempts = 2 if has_v6 else 1
        out = err = ""
        rc = 1
        for attempt in range(1, attempts + 1):
            if attempt > 1:
                logger().info(
                    "IPv6 traffic gen retry after prior failure "
                    "(settle 3s, recreate sockets via fresh process)"
                )
                time.sleep(3)
            rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
                f"python3 {remote_path}"
            )
            out = stdout.decode() if isinstance(stdout, bytes) else str(stdout)
            err = stderr.decode() if isinstance(stderr, bytes) else str(stderr)
            logger().info(f"Traffic gen stdout:\n{out}")
            if err:
                logger().info(f"Traffic gen stderr:\n{err}")
            if rc == 0:
                return out
            combined = f"{out}\n{err}"
            transient = (
                "99" in combined
                or "Cannot assign requested address" in combined
                or "EADDRNOTAVAIL" in combined
            )
            if not (has_v6 and transient and attempt < attempts):
                break
        assert rc == 0, f"BC/MC traffic generation failed: {err or out}"
        return out

    def start_concurrent_ping(
        self,
        device_ip,
        dut_mac=None,
        count=40,
        interval_sec=1.0,
        interface="wlan0",
    ):
        """
        Start Raspi->DUT ICMP ping in background (C1726552 only).
        Installs a static neighbor entry (DUT MAC) so ARP does not fail while
        DUT is in TA powersave, and binds ping to wlan0.

        Keep rate moderate (default 40 x 1s): aggressive ping under PS + BC/MC
        can push DUT into rejoin (0x10025) before stats can be read.
        """
        assert device_ip, "DUT IP required for concurrent ping"
        mac = ""
        if dut_mac:
            mac = str(dut_mac).strip().lower().replace("-", ":")
        logger().info(
            f"Start concurrent ping Raspi -> DUT {device_ip} "
            f"(mac={mac or 'n/a'}, iface={interface}, "
            f"count={count}, interval={interval_sec}s)"
        )
        start_script = textwrap.dedent(
            f"""\
            import subprocess, os, time
            device_ip = "{device_ip}"
            dut_mac = "{mac}"
            iface = "{interface}"
            out_path = "/tmp/mc_bc_uc_ping.txt"
            pid_path = "/tmp/mc_bc_uc_ping.pid"
            for p in (out_path, pid_path):
                try:
                    os.remove(p)
                except OSError:
                    pass
            # DUT in PS often does not answer ARP; pin L2 next-hop on wlan0.
            if dut_mac:
                try:
                    subprocess.check_call(
                        [
                            "sudo", "ip", "neigh", "replace", device_ip,
                            "lladdr", dut_mac, "dev", iface, "nud", "permanent",
                        ]
                    )
                    print("neigh replace ok %s -> %s on %s" % (device_ip, dut_mac, iface))
                except Exception as exc:
                    print("neigh replace note: %s" % exc)
            out_f = open(out_path, "w")
            proc = subprocess.Popen(
                [
                    "ping", "-I", iface, "-c", "{count}",
                    "-i", "{interval_sec}", "-W", "3", device_ip,
                ],
                stdout=out_f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            out_f.close()
            with open(pid_path, "w") as pf:
                pf.write(str(proc.pid))
            print(proc.pid)
            time.sleep(0.5)
            """
        )
        remote_path = "/tmp/mc_bc_uc_ping_start.py"
        self.wifi_client.interfaces.wifi.shell.create_file(remote_path, start_script)
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"python3 {remote_path}"
        )
        out = stdout.decode() if isinstance(stdout, bytes) else str(stdout)
        err = stderr.decode() if isinstance(stderr, bytes) else str(stderr)
        pid = ""
        for line in reversed(out.strip().splitlines() if out.strip() else []):
            if line.strip().isdigit():
                pid = line.strip()
                break
        logger().info(f"Concurrent ping pid={pid} rc={rc} out={out} err={err}")
        assert pid.isdigit(), f"Failed to start concurrent ping: out={out} err={err}"
        return pid

    def wait_concurrent_ping(self, min_replies=10, timeout_sec=90):
        """Wait for background ping; assert enough replies (unicast still works)."""
        logger().info(
            f"Wait concurrent ping complete (min_replies={min_replies}, "
            f"timeout={timeout_sec}s)"
        )
        wait_script = textwrap.dedent(
            f"""\
            import os, time, signal
            pid_path = "/tmp/mc_bc_uc_ping.pid"
            out_path = "/tmp/mc_bc_uc_ping.txt"
            pid = None
            try:
                with open(pid_path) as pf:
                    pid = int(pf.read().strip())
            except Exception as exc:
                print("pid read note: %s" % exc)
            deadline = time.time() + {timeout_sec}
            if pid:
                while time.time() < deadline:
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                    time.sleep(1)
                else:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
                    time.sleep(0.5)
            try:
                with open(out_path) as of:
                    print(of.read())
            except Exception as exc:
                print("ping output missing: %s" % exc)
            """
        )
        remote_path = "/tmp/mc_bc_uc_ping_wait.py"
        self.wifi_client.interfaces.wifi.shell.create_file(remote_path, wait_script)
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"python3 {remote_path}"
        )
        out = stdout.decode() if isinstance(stdout, bytes) else str(stdout)
        err = stderr.decode() if isinstance(stderr, bytes) else str(stderr)
        logger().info(f"Concurrent ping output:\n{out}")
        if err:
            logger().info(f"Concurrent ping stderr:\n{err}")

        received = 0
        m = re.search(r"(\d+)\s+received", out, re.I)
        if m:
            received = int(m.group(1))
        else:
            m = re.search(r"(\d+)\s+packets?\s+received", out, re.I)
            if m:
                received = int(m.group(1))
        assert received >= min_replies, (
            f"FAIL: concurrent unicast ping — need >= {min_replies} replies, "
            f"got {received}. Output:\n{out}"
        )
        logger().info(f"Concurrent ping OK: received={received}")
        return received


# ---------------------------------------------------------------------------
# DUT filter CLI + statistics
# ---------------------------------------------------------------------------
def _as_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _stat_get(obj, *keys, default=0):
    cur = obj
    for i, key in enumerate(keys):
        if cur is None:
            return default
        last = i == len(keys) - 1
        if isinstance(cur, dict):
            cur = cur.get(key, default if last else None)
        else:
            cur = getattr(cur, key, default if last else None)
    return default if cur is None else cur


def _parse_allowlist_handle(raw):
    if isinstance(raw, int):
        return raw
    if raw is None:
        return None
    if hasattr(raw, "handle"):
        return int(raw.handle)
    text = str(raw)
    m = re.search(r"handle\s*[:=]\s*(\d+)", text, re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"\b(\d+)\b", text)
    return int(m.group(1)) if m else raw


def _parse_stats_v2_text(text):
    out = {"nwp_filter_stats": {}, "ppe_filter_stats": {}}
    if not text:
        return out
    for m in re.finditer(
        r"(nwp|ppe)_(bc|mc)_(rx|drop|pass)_count\s*[:=]\s*(\d+)", text, re.I
    ):
        which, kind, field, num = m.group(1).lower(), m.group(2).lower(), m.group(3).lower(), int(m.group(4))
        out[f"{which}_filter_stats"][f"{kind}_{field}"] = num
    return out


def _normalize_stats_v2(raw):
    """Normalize host return / text to nwp/ppe_*_filter_stats.{bc,mc}_{rx,drop,pass}."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return _parse_stats_v2_text(raw)

    out = {"nwp_filter_stats": {}, "ppe_filter_stats": {}}
    nwp = _stat_get(raw, "nwp_filter_stats", default=None)
    ppe = _stat_get(raw, "ppe_filter_stats", default=None)
    if nwp is not None or ppe is not None:
        for which, block, fields in (
            ("nwp", nwp or {}, ("rx", "drop", "pass")),
            ("ppe", ppe or {}, ("rx", "drop")),
        ):
            for kind in ("bc", "mc"):
                for field in fields:
                    key = f"{kind}_{field}"
                    val = _stat_get(block, key, default=None)
                    if val is None:
                        val = _stat_get(block, f"{key}_count", default=None)
                    if val is not None:
                        out[f"{which}_filter_stats"][key] = _as_int(val)
        return out

    flat = (
        ("nwp", "bc", "rx"), ("nwp", "bc", "drop"), ("nwp", "bc", "pass"),
        ("nwp", "mc", "rx"), ("nwp", "mc", "drop"), ("nwp", "mc", "pass"),
        ("ppe", "bc", "rx"), ("ppe", "bc", "drop"),
        ("ppe", "mc", "rx"), ("ppe", "mc", "drop"),
    )
    hit = False
    for which, kind, field in flat:
        name = f"{which}_{kind}_{field}_count"
        val = _stat_get(raw, name, default=None)
        if val is None and isinstance(raw, dict):
            val = raw.get(name)
        if val is not None:
            hit = True
            out[f"{which}_filter_stats"][f"{kind}_{field}"] = _as_int(val)
    return out if hit else _parse_stats_v2_text(str(raw))


def _counter(stats, which, field):
    nested = _stat_get(stats, f"{which}_filter_stats", field, default=None)
    if nested is None:
        nested = _stat_get(stats, f"{which}_filter_stats", f"{field}_count", default=None)
    if nested is None:
        nested = _stat_get(stats, f"{which}_{field}_count", default=None)
    return _as_int(nested, 0)


def configure_groupcast_filter(
    wifi_dut,
    enable_bcast_filter=0,
    enable_mcast_filter=0,
    filter_mode=0,
    allowlist_ips=None,
    beacon_drop_threshold=SuiteConfig.BEACON_DROP_THRESHOLD,
):
    wifi = wifi_dut.interfaces.wifi
    allowlist_ips = list(allowlist_ips or [])
    logger().info(
        f"Configure filter: BC={enable_bcast_filter} MC={enable_mcast_filter} "
        f"mode={filter_mode} allowlist={allowlist_ips}"
    )
    wifi.set_beacon_drop_threshold(
        interface="client", beacon_drop_threshold=beacon_drop_threshold
    )
    wifi.set_groupcast_filter_config(
        enable_bcast_filter=enable_bcast_filter,
        enable_mcast_filter=enable_mcast_filter,
        filter_mode=filter_mode,
    )
    wifi.allowlist_mcast_remove_all()
    handles = []
    for ip in allowlist_ips:
        handle = _parse_allowlist_handle(wifi.allowlist_mcast_add_ip(ip))
        handles.append(handle)
        logger().info(f"Allowlist add hdl={handle} ip={ip}")
    return handles


def cleanup_groupcast_filter(wifi_dut, handles=None):
    wifi = wifi_dut.interfaces.wifi
    for handle in handles or []:
        if handle is None:
            continue
        try:
            wifi.allowlist_mcast_remove_ip(handle)
        except Exception as exc:
            logger().info(f"allowlist_mcast_remove_ip({handle}) note: {exc}")
    try:
        wifi.allowlist_mcast_remove_all()
    except Exception as exc:
        logger().info(f"allowlist_mcast_remove_all note: {exc}")


def _log_filter_statistics(stats):
    if stats is None:
        logger().info("Filter stats: <None>")
        return
    bc_rx, bc_drop, bc_pass = _counter(stats, "nwp", "bc_rx"), _counter(stats, "nwp", "bc_drop"), _counter(stats, "nwp", "bc_pass")
    mc_rx, mc_drop, mc_pass = _counter(stats, "nwp", "mc_rx"), _counter(stats, "nwp", "mc_drop"), _counter(stats, "nwp", "mc_pass")
    ppe_bc_rx, ppe_bc_drop = _counter(stats, "ppe", "bc_rx"), _counter(stats, "ppe", "bc_drop")
    ppe_mc_rx, ppe_mc_drop = _counter(stats, "ppe", "mc_rx"), _counter(stats, "ppe", "mc_drop")
    logger().info("--- Wi-Fi statistics (v2) ---")
    logger().info(f"Wireless filter bc rx/drop/pass: {bc_rx} / {bc_drop} / {bc_pass}")
    logger().info(f"Wireless filter mc rx/drop/pass: {mc_rx} / {mc_drop} / {mc_pass}")
    logger().info(f"PPE filter bc rx/drop: {ppe_bc_rx} / {ppe_bc_drop}")
    logger().info(f"PPE filter mc rx/drop: {ppe_mc_rx} / {ppe_mc_drop}")


def read_filter_statistics(wifi_dut, retries=5, retry_delay_sec=5):
    """
    Read FW filter stats. Retries on transient SI91X rejoin/busy (0x10025),
    which can occur after heavy UC+groupcast under TA powersave (C1726552).
    """
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            if attempt == 1:
                logger().info("Reading filter statistics v2")
            else:
                logger().info(
                    f"Reading filter statistics v2 (retry {attempt}/{retries})"
                )
            raw = wifi_dut.interfaces.wifi.get_statistics_v2()
            stats = _normalize_stats_v2(raw)
            _log_filter_statistics(stats)
            return stats
        except Exception as exc:
            last_exc = exc
            msg = str(exc)
            rejoin = (
                "0x10025" in msg
                or "REJOIN" in msg.upper()
                or "COMMAND_ISSUED_IN_REJOIN" in msg.upper()
            )
            if rejoin and attempt < retries:
                logger().info(
                    f"get_statistics_v2 not ready (rejoin/busy): {exc}; "
                    f"wait {retry_delay_sec}s and retry"
                )
                time.sleep(retry_delay_sec)
                continue
            raise
    raise last_exc


def clear_filter_statistics(wifi_dut):
    """Read once to reset FW filter counters (short retry — pre-traffic)."""
    logger().info("Clear FW filter counters (read-to-reset)")
    return read_filter_statistics(wifi_dut, retries=3, retry_delay_sec=3)


def validate_filter_statistics(stats, expected: ExpectedFilterBehavior, path: str):
    logger().info(f"Validate filter stats | {expected.notes} | path={path}")
    assert stats is not None, "get_statistics_v2 returned None"
    _log_filter_statistics(stats)
    min_pkts = expected.min_packets

    nwp_bc_pass = _counter(stats, "nwp", "bc_pass")
    nwp_bc_drop = _counter(stats, "nwp", "bc_drop")
    nwp_bc_rx = _counter(stats, "nwp", "bc_rx")
    ppe_bc_rx = _counter(stats, "ppe", "bc_rx")
    ppe_bc_drop = _counter(stats, "ppe", "bc_drop")
    bc_drop = nwp_bc_drop + ppe_bc_drop
    bc_rx = nwp_bc_rx + ppe_bc_rx

    nwp_mc_pass = _counter(stats, "nwp", "mc_pass")
    nwp_mc_drop = _counter(stats, "nwp", "mc_drop")
    nwp_mc_rx = _counter(stats, "nwp", "mc_rx")
    ppe_mc_rx = _counter(stats, "ppe", "mc_rx")
    ppe_mc_drop = _counter(stats, "ppe", "mc_drop")
    mc_drop = nwp_mc_drop + ppe_mc_drop
    mc_rx = nwp_mc_rx + ppe_mc_rx

    if expected.expect_bc_drop:
        assert bc_drop >= min_pkts, (
            f"FAIL: BC ON — drop >= {min_pkts} required, got {bc_drop}"
        )
        assert nwp_bc_pass == 0, (
            f"FAIL: BC ON — bc_pass must be 0, got {nwp_bc_pass}"
        )
        logger().info(f"BC ON OK: drop={bc_drop}, pass={nwp_bc_pass}")

    if expected.expect_bc_pass:
        allowed = nwp_bc_pass or max(0, bc_rx - bc_drop)
        assert allowed >= min_pkts, (
            f"FAIL: BC OFF — pass/rx >= {min_pkts} required, got {allowed}"
        )
        assert bc_drop == 0, f"FAIL: BC OFF — bc_drop must be 0, got {bc_drop}"
        logger().info(f"BC OFF OK: allowed={allowed}, drop={bc_drop}")

    if expected.expect_mc_allow_pass:
        allowed = nwp_mc_pass
        if allowed == 0 and path == "ppe":
            allowed = max(0, ppe_mc_rx - ppe_mc_drop) if ppe_mc_rx else 0
        assert allowed >= min_pkts, (
            f"FAIL: MC ON + allowlist — pass >= {min_pkts} required, got {allowed}"
        )
        logger().info(f"MC allowlist OK: pass={allowed}")

    if expected.expect_mc_nonallow_drop:
        assert mc_drop >= min_pkts, (
            f"FAIL: MC ON — drop >= {min_pkts} required, got {mc_drop}"
        )
        if not expected.expect_mc_allow_pass:
            assert nwp_mc_pass == 0, (
                f"FAIL: MC ON generic — mc_pass must be 0, got {nwp_mc_pass}"
            )
        logger().info(f"MC drop OK: drop={mc_drop}, pass={nwp_mc_pass}")

    if expected.expect_mc_pass_when_filter_off:
        allowed = nwp_mc_pass or mc_rx
        assert allowed >= min_pkts, (
            f"FAIL: MC OFF — pass/rx >= {min_pkts} required, got {allowed}"
        )
        assert mc_drop == 0, f"FAIL: MC OFF — mc_drop must be 0, got {mc_drop}"
        logger().info(f"MC OFF OK: allowed={allowed}, drop={mc_drop}")

    # PPE>2 fallback / explicit NWP mode: NWP must own the filter counters.
    if expected.expect_nwp_ownership:
        assert path == "nwp", (
            f"FAIL: NWP ownership — expected path=nwp, got {path}"
        )
        if expected.expect_bc_drop:
            assert nwp_bc_drop >= min_pkts, (
                f"FAIL: NWP ownership — nwp_bc_drop >= {min_pkts} required, "
                f"got {nwp_bc_drop} (ppe_bc_drop={ppe_bc_drop})"
            )
        if expected.expect_bc_pass:
            assert nwp_bc_pass >= min_pkts, (
                f"FAIL: NWP ownership — nwp_bc_pass >= {min_pkts} required, "
                f"got {nwp_bc_pass} (must stay on NWP, not PPE)"
            )
        if expected.expect_mc_allow_pass:
            assert nwp_mc_pass >= min_pkts, (
                f"FAIL: NWP ownership — nwp_mc_pass >= {min_pkts} required, "
                f"got {nwp_mc_pass}"
            )
        if expected.expect_mc_nonallow_drop:
            assert nwp_mc_drop >= min_pkts, (
                f"FAIL: NWP ownership — nwp_mc_drop >= {min_pkts} required, "
                f"got {nwp_mc_drop} (ppe_mc_drop={ppe_mc_drop})"
            )
        logger().info(
            f"NWP ownership OK: nwp_bc_pass={nwp_bc_pass}, nwp_bc_drop={nwp_bc_drop}, "
            f"nwp_mc_pass={nwp_mc_pass}, nwp_mc_drop={nwp_mc_drop}"
        )

    logger().info("Filter statistics validation PASSED")


# ---------------------------------------------------------------------------
# Sniffer — powersave PM bit only (not PS-Poll / power meter)
# ---------------------------------------------------------------------------
def _mac_str(addr):
    """Copy MAC to a plain lowercase string (AP bssid props can be live buffers)."""
    if addr is None:
        return ""
    return str(addr).strip().lower()


def _lookup_sniffer_filter(sniffer_filter, filter_name, dut_mac, ap_bssid):
    """
    Load a named filter from sniffer.csv via get_sniffer_filter().

    Returns empty string when lookup/parsing fails (older testline csv/parsers can
    throw IndexError for new entries).
    """
    try:
        pkt_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac,
            da_addr=ap_bssid,
            filter_name=filter_name,
        )
        logger().info(f"{filter_name} filter: {pkt_filter}")
        return pkt_filter
    except Exception as exc:
        logger().info(f"{filter_name} lookup failed: {type(exc).__name__}: {exc}")
        return ""


def assert_dut_powersave_pm_bit(wifi_sniffer, sniffer_filter, dut_mac, ap_bssid):
    """
    Assert DUT entered powersave: frames from DUT to AP with PM bit = 1.

    Primary: sniffer.csv `power_mgmt_bit_null_qos` — Null (0x0024) OR QoS Null
    (0x002c) with PM=1. SOC WLAN+BLE coex often uses QoS Null.
    Fallback: sniffer.csv `power_mgmt_bit` (Null 0x0024 only).
    """
    dut_mac = _mac_str(dut_mac)
    ap_bssid = _mac_str(ap_bssid)
    assert dut_mac, "DUT MAC required for power_mgmt_bit check"
    assert ap_bssid, "AP BSSID required for power_mgmt_bit check"

    logger().info(
        f"Sniffer: assert DUT entered PS (PM bit=1) DUT={dut_mac} AP={ap_bssid}"
    )
    pkt_filter = _lookup_sniffer_filter(
        sniffer_filter, "power_mgmt_bit_null_qos", dut_mac, ap_bssid
    )
    count = _sniffer_packet_count(wifi_sniffer, pkt_filter) if pkt_filter else 0

    if not count:
        pkt_filter = _lookup_sniffer_filter(
            sniffer_filter, "power_mgmt_bit", dut_mac, ap_bssid
        )
        count = _sniffer_packet_count(wifi_sniffer, pkt_filter) if pkt_filter else 0

    if not count:
        # Last-resort inline filter if sniffer.csv entry is missing/broken on line.
        pkt_filter = (
            f"(wlan.sa == {dut_mac}) and (wlan.da == {ap_bssid}) and "
            f"(wlan.fc.pwrmgt == 1) and "
            f"(wlan.fc.type_subtype == 0x0024 or wlan.fc.type_subtype == 0x002c)"
        )
        logger().info(f"Fallback inline PM-bit filter: {pkt_filter}")
        count = _sniffer_packet_count(wifi_sniffer, pkt_filter)

    assert count, (
        f"DUT did not enter powersave — no PM-bit=1 frames "
        f"(DUT={dut_mac}, AP={ap_bssid}, filter={pkt_filter})"
    )
    logger().info(f"DUT in PS confirmed (PM-bit frames={count})")
    return count


def _sniffer_packet_count(wifi_sniffer, pkt_filter, retries=3):
    """
    Run sniffer_validation; return packet count.

    Sniffer SSH can time out during post-filter cleanup (sudo rm) even when the
    count itself is known (often 0). Treat SSH/transport errors as a miss so
    PM-bit Null -> QoS-Null fallback can still run.
    """
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            result = wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=pkt_filter
            )
            count = (
                result.get("packet_count", 0)
                if isinstance(result, dict)
                else (result or 0)
            )
            try:
                return int(count)
            except (TypeError, ValueError):
                return 1 if count else 0
        except FileNotFoundError:
            return 0
        except Exception as exc:
            last_err = exc
            logger().info(
                f"sniffer_validation attempt {attempt}/{retries} failed "
                f"({type(exc).__name__}: {exc})"
            )
            if attempt < retries:
                time.sleep(3)
    logger().info(
        f"sniffer_validation exhausted retries ({last_err}) — treating as count=0"
    )
    return 0


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------
class BcMcFilterFunctional(ThreadBase):
    """
    DUT (WLAN+BLE coex) + Raspi join -> configure filter ->
    TA PS + sniffer PM-bit -> traffic -> filter stats validate.

    Scenarios ap_restart_rejoin / ap_disconnect_reset add radio OFF/ON
    disconnect cleanup (and optional re-apply for C1726553).
    """

    def __init__(
        self,
        dtim=10,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_client=None,
        wifi_sniffer=None,
        sniffer_filter=None,
        sl_collections=None,
        enable_bcast_filter=0,
        enable_mcast_filter=0,
        filter_mode=0,
        allowlist_ips=None,
        send_broadcast=True,
        nonallow_streams=None,
        generate_traffic=True,
        concurrent_ping=False,
        enter_powersave=True,
        validate_ps_pm_bit=True,
        scenario=None,
        test_case_id="mc_bc_filter",
        idle_traffic_wait_sec=SuiteConfig.IDLE_TRAFFIC_WAIT_SEC,
        expected: ExpectedFilterBehavior = None,
    ):
        super().__init__()
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.enable_bcast_filter = enable_bcast_filter
        self.enable_mcast_filter = enable_mcast_filter
        self.filter_mode = filter_mode
        self.allowlist_ips = list(allowlist_ips or [])
        self.send_broadcast = send_broadcast
        self.nonallow_streams = list(
            nonallow_streams
            if nonallow_streams is not None
            else SuiteConfig.MC_NONALLOW_IPS
        )
        self.generate_traffic = generate_traffic
        self.concurrent_ping = concurrent_ping
        self.enter_powersave = enter_powersave
        self.validate_ps_pm_bit = validate_ps_pm_bit
        self.scenario = scenario
        self.test_case_id = test_case_id
        self.idle_traffic_wait_sec = idle_traffic_wait_sec
        self.expected = expected
        self.host_ip = None
        self.device_ip = None
        self.dut_mac = None
        self.filter_handles = []
        self.filter_path = "none"

    def _ensure_expected(self):
        if self.expected is None:
            self.expected = build_expected(
                self.enable_bcast_filter,
                self.enable_mcast_filter,
                self.filter_mode,
                self.allowlist_ips,
                self.send_broadcast,
            )
        self.filter_path = filter_path(
            self.enable_bcast_filter,
            self.enable_mcast_filter,
            self.filter_mode,
            len(self.allowlist_ips),
        )

    def _dut_join(self):
        logger().info(f"AP DTIM={self.dtim}; connecting DUT (WLAN+BLE coex)")
        self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)
        info = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
            retry_count=3,
        )
        self.device_ip = info["device_ip"]
        self.dut_mac = info.get("dut_mac_address")
        logger().info(f"DUT IP={self.device_ip} MAC={self.dut_mac}")

    def _start_ps_sniffer(self, capture_tag="ps"):
        if not (
            self.enter_powersave
            and self.validate_ps_pm_bit
            and self.wifi_sniffer
            and self.sniffer_filter
        ):
            return False
        channel = self.wifi_access_point.interfaces.wifi.channel
        capture = f"{self.test_case_id}_{capture_tag}.pcap"
        logger().info(f"Start sniffer for PS PM-bit on ch={channel} file={capture}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=capture)
        return True

    def _stop_and_assert_ps_pm_bit(self, settle_sec=0):
        if not (
            self.enter_powersave
            and self.validate_ps_pm_bit
            and self.wifi_sniffer
            and self.sniffer_filter
        ):
            return
        if settle_sec > 0:
            time.sleep(settle_sec)
        logger().info("Stop sniffer; validate power-save PM bit")
        # stop_capture is also SSH to the sniffer box — retry on timeout.
        last_exc = None
        for attempt in range(1, 4):
            try:
                self.wifi_sniffer.interfaces.capture.stop_capture()
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                logger().info(
                    f"stop_capture attempt {attempt}/3 failed "
                    f"({type(exc).__name__}: {exc})"
                )
                time.sleep(3)
        if last_exc is not None:
            raise last_exc
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        assert_dut_powersave_pm_bit(
            wifi_sniffer=self.wifi_sniffer,
            sniffer_filter=self.sniffer_filter,
            dut_mac=self.dut_mac,
            ap_bssid=ap_bssid,
        )

    def _apply_filter_and_powersave(self, clear_stats=False, configure_filter=True):
        if clear_stats:
            clear_filter_statistics(self.wifi_dut)
        if configure_filter:
            # Re-applying filter while already in TA PS (C1726553 post-reconfig)
            # can leave DUT in 0x10025 and wipe the next stats window. Exit PS
            # first, configure, then re-enter.
            if self.enter_powersave:
                self._disable_powersave()
            self.filter_handles = configure_groupcast_filter(
                wifi_dut=self.wifi_dut,
                enable_bcast_filter=self.enable_bcast_filter,
                enable_mcast_filter=self.enable_mcast_filter,
                filter_mode=self.filter_mode,
                allowlist_ips=self.allowlist_ips,
            )
            logger().info(f"Expected filter path: {self.filter_path}")

        if self.enter_powersave:
            time.sleep(2)
            logger().info("Enable TA powersave (WLAN + BLE coex)")
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency", dtim_aligned_type=1
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
            # Allow Null/QoS-Null PM-bit frames onto the air before traffic.
            time.sleep(5)

    def _disable_powersave(self):
        """Exit TA PS before AP restart/disconnect cycles (C1726553/54)."""
        try:
            logger().info("Disable TA powersave before AP cycle")
            # Profile 0 disables BT PS (same as end_state bt_powersave_disable).
            bt_off = getattr(Si91xPowerSaveModes, "PowerSaveMode0", 0)
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=bt_off,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="high_performance", dtim_aligned_type=0
            )
            time.sleep(1)
        except Exception as exc:
            logger().info(f"disable powersave note: {exc}")

    def _idle_traffic_and_validate(self, traffic, expected=None, path=None):
        if not self.generate_traffic and not self.concurrent_ping:
            logger().info("Skipping traffic/stats validation (API-only case)")
            return

        exp = expected if expected is not None else self.expected
        fpath = path if path is not None else self.filter_path

        # Wait a couple of DTIM intervals so PS STA is TIM-synced before traffic.
        dtim_wait = max(2.0, (self.dtim or 1) * 0.2)
        logger().info(f"DTIM settle {dtim_wait:.1f}s before traffic/stats window")
        time.sleep(dtim_wait)

        # Read-to-reset immediately before traffic so counters cover only this window.
        clear_filter_statistics(self.wifi_dut)

        wait_sec = self.idle_traffic_wait_sec
        logger().info(f"Idle {wait_sec}s while Raspi generates BC/MC (DUT in PS)")
        t0 = time.time()

        # C1726552 only: ping DUT in parallel with BC/MC (default False elsewhere).
        if self.concurrent_ping:
            traffic.start_concurrent_ping(
                device_ip=self.device_ip,
                dut_mac=self.dut_mac,
            )

        allow_streams = list(self.allowlist_ips) if self.enable_mcast_filter else []
        block_streams = list(self.nonallow_streams) or list(SuiteConfig.MC_NONALLOW_IPS)
        has_v6 = any(":" in str(ip) for ip in (allow_streams + block_streams))
        gap = max(dtim_wait, 5.0 if has_v6 else dtim_wait)

        if self.generate_traffic:
            # Two BC/MC bursts spaced across DTIMs — single short burst can miss
            # delivery to a PS STA (AP only forwards groupcast at DTIM).
            traffic.generate_traffic(
                host_ip=self.host_ip,
                send_broadcast=self.send_broadcast,
                allow_streams=allow_streams,
                nonallow_streams=block_streams,
            )
            # Extra settle between dual bursts when IPv6 MC is used (C1726549):
            # second burst was flaky with errno 99 without this gap.
            logger().info(f"Inter-burst settle {gap:.1f}s (v6={has_v6})")
            time.sleep(gap)
            traffic.generate_traffic(
                host_ip=self.host_ip,
                send_broadcast=self.send_broadcast,
                allow_streams=allow_streams,
                nonallow_streams=block_streams,
            )

        if self.concurrent_ping:
            traffic.wait_concurrent_ping(
                min_replies=SuiteConfig.MIN_FILTER_STAT_PACKETS
            )

        # Heavy UC / post AP-radio rejoin can leave DUT in 0x10025; wait before
        # get_statistics_v2. Normal BC/MC cases rely on stats-read retries +
        # one traffic-window retry below (avoid 20s ping wait every case).
        if self.concurrent_ping or self.scenario in (
            "ap_restart_rejoin",
            "ap_disconnect_reset",
        ):
            self._wait_dut_reachable_after_stress(timeout_sec=45)

        remain = wait_sec - (time.time() - t0)
        if remain > 0:
            time.sleep(remain)

        stats = read_filter_statistics(self.wifi_dut)
        try:
            validate_filter_statistics(stats, exp, fpath)
        except AssertionError as exc:
            # Rejoin during the traffic window can reset counters (seen on
            # C1726553 post re-apply: BC drop=0 after 0x10025). One recovery
            # cycle: wait link, clear, re-send dual burst, validate again.
            if not self.generate_traffic:
                raise
            logger().info(
                f"Stats validation failed after possible rejoin wipe ({exc}) — "
                "retry one clear+traffic+validate cycle"
            )
            self._wait_dut_reachable_after_stress(timeout_sec=45)
            clear_filter_statistics(self.wifi_dut)
            traffic.generate_traffic(
                host_ip=self.host_ip,
                send_broadcast=self.send_broadcast,
                allow_streams=allow_streams,
                nonallow_streams=block_streams,
            )
            time.sleep(gap)
            traffic.generate_traffic(
                host_ip=self.host_ip,
                send_broadcast=self.send_broadcast,
                allow_streams=allow_streams,
                nonallow_streams=block_streams,
            )
            self._wait_dut_reachable_after_stress(timeout_sec=30)
            stats = read_filter_statistics(self.wifi_dut)
            validate_filter_statistics(stats, exp, fpath)

    def _wait_dut_reachable_after_stress(self, timeout_sec=45):
        """After BC/MC (and optional UC) under PS, wait until DUT answers ping."""
        logger().info(
            f"Wait DUT link stable after PS traffic stress "
            f"(timeout={timeout_sec}s, ip={self.device_ip})"
        )
        if not self.device_ip:
            time.sleep(5)
            return
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                if self.sl_collections.ping(
                    device_ip=self.device_ip, ping_count=3, retry_count=1
                ):
                    logger().info(f"DUT reachable again at {self.device_ip}")
                    # Short settle so FW leaves rejoin before stats API.
                    time.sleep(3)
                    return
            except Exception as exc:
                logger().info(f"reachability probe note: {exc}")
            time.sleep(3)
        logger().info(
            "DUT reachability wait timed out — stats read will retry on rejoin"
        )

    def _force_dut_leave(self):
        """
        Asus Wi-Fi radio OFF often makes DUT unreachable while host still reports
        associated=True. Force client leave so FW clears association and
        BC/MC filter state (C1726553 / C1726554).
        """
        logger().info(
            "Force DUT leave — clear association so BC/MC filter resets"
        )
        try:
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as exc:
            logger().info(f"DUT leave note: {exc}")
            try:
                self.wifi_dut.interfaces.wifi.disconnect(interface="client")
            except Exception as exc2:
                logger().info(f"DUT disconnect note: {exc2}")
        time.sleep(2)
        try:
            assoc = bool(self.wifi_dut.interfaces.wifi.associated)
        except Exception:
            assoc = None
        logger().info(f"DUT association after force leave: {assoc}")
        return assoc is False or assoc is None

    def _assert_dut_disconnected(self, timeout_sec=45):
        """After AP Wi-Fi radio OFF: DUT must become unreachable and leave association.
        Returns True if DUT leave was forced (caller should use join API).
        """
        logger().info("Confirm DUT enters disconnected state after AP Wi-Fi radio OFF")
        deadline = time.time() + timeout_sec
        last_assoc = None
        last_reachable = True
        unreachable_since = None
        # Beacon-drop threshold is 5s; allow FW time to mark disassociated.
        assoc_clear_grace_sec = 15

        while time.time() < deadline:
            try:
                last_assoc = bool(self.wifi_dut.interfaces.wifi.associated)
            except Exception as exc:
                logger().info(f"associated query note: {exc}")
                last_assoc = None
            last_reachable = False
            if self.device_ip:
                try:
                    last_reachable = bool(
                        self.sl_collections.ping(
                            device_ip=self.device_ip, ping_count=2, retry_count=1
                        )
                    )
                except Exception:
                    last_reachable = False

            if last_reachable:
                unreachable_since = None
            else:
                if unreachable_since is None:
                    unreachable_since = time.time()
                if last_assoc is False:
                    logger().info(
                        f"DUT disconnected (associated=False, ping_reachable=False)"
                    )
                    return False
                # Unreachable but still associated: wait for beacon-loss, then force.
                if time.time() - unreachable_since >= assoc_clear_grace_sec:
                    logger().info(
                        f"DUT unreachable but associated={last_assoc} after "
                        f"{assoc_clear_grace_sec}s radio-off — force leave to clear filter"
                    )
                    self._force_dut_leave()
                    return True
            time.sleep(2)

        assert not last_reachable, (
            f"FAIL: DUT still reachable after AP Wi-Fi radio OFF "
            f"(associated={last_assoc}, ip={self.device_ip})"
        )
        if last_assoc is not False:
            logger().info(
                f"DUT still associated={last_assoc} after radio-off timeout — force leave"
            )
            self._force_dut_leave()
            return True
        return False

    def _wait_dut_rejoin_no_reboot(self, timeout_sec=30, force_join=False):
        """
        Prefer DUT auto-rejoin after AP Wi-Fi radio returns (same SSID/security, no reboot).
        If leave was forced or auto-rejoin is not observed, use join API (no reboot).
        """
        if force_join:
            logger().info(
                "DUT was force-left during radio OFF; reconnect via join API "
                "(no DUT reboot)"
            )
        else:
            logger().info(
                "Wait for DUT auto-rejoin after Wi-Fi radio ON (no DUT reboot)"
            )
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                try:
                    if self.wifi_dut.interfaces.wifi.associated and self.device_ip:
                        if self.sl_collections.ping(
                            device_ip=self.device_ip, ping_count=3, retry_count=2
                        ):
                            logger().info(
                                f"DUT auto-rejoined; ping OK to {self.device_ip}"
                            )
                            return
                except Exception as exc:
                    logger().info(f"rejoin check note: {exc}")
                if self.device_ip:
                    try:
                        if self.sl_collections.ping(
                            device_ip=self.device_ip, ping_count=3, retry_count=2
                        ):
                            logger().info(
                                f"DUT auto-rejoined; ping OK to {self.device_ip}"
                            )
                            return
                    except Exception as exc:
                        logger().info(f"rejoin ping note: {exc}")
                time.sleep(3)
            logger().info(
                "Auto-rejoin not detected within timeout; "
                "reconnect via join API (no DUT reboot)"
            )

        info = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
            retry_count=3,
        )
        self.device_ip = info["device_ip"]
        self.dut_mac = info.get("dut_mac_address", self.dut_mac)
        logger().info(
            f"DUT rejoined via join API IP={self.device_ip} MAC={self.dut_mac}"
        )

    def _ap_radio_off_on_and_rejoin(self, traffic):
        """
        Shared AP Wi-Fi radio OFF -> DUT disconnect -> radio ON -> rejoin.

        Uses enable_disable_radio (not stop_ap/start_ap) so the controller PC
        that shares this AP over LAN is not disrupted.

        Clears filter_handles (FW drops BC/MC state on disconnect).
        """
        self._disable_powersave()

        # Raspi loses BSS when radio goes down; leave cleanly first.
        try:
            traffic.leave()
        except Exception as exc:
            logger().info(f"wifi_client leave before radio-off note: {exc}")

        radio_off = False
        try:
            logger().info("Turn OFF AP Wi-Fi radio (LAN/controller stays up)")
            self.wifi_access_point.interfaces.wifi.enable_disable_radio(enable=False)
            radio_off = True
            time.sleep(5)

            forced_leave = self._assert_dut_disconnected()
            # FW clears BC/MC filter on disconnect; drop stale allowlist handles.
            self.filter_handles = []

            logger().info("Turn ON AP Wi-Fi radio (same SSID/security)")
            self.wifi_access_point.interfaces.wifi.enable_disable_radio(enable=True)
            radio_off = False
            time.sleep(5)
            self._wait_dut_rejoin_no_reboot(force_join=forced_leave)

            self.host_ip = traffic.join_third_party_ap(self.wifi_access_point)
            assert self.host_ip, "wifi_client failed to rejoin AP after radio ON"
        finally:
            # Never leave the shared AP Wi-Fi radio off if the test aborts mid-cycle.
            if radio_off:
                try:
                    logger().info("Safety: restore AP Wi-Fi radio ON after failure")
                    self.wifi_access_point.interfaces.wifi.enable_disable_radio(
                        enable=True
                    )
                except Exception as exc:
                    logger().info(f"radio restore note: {exc}")

    def _validate_filter_cleared_after_rejoin(self, traffic, capture_tag):
        """After reconnect: PPE/NWP filtering disabled; all BC/MC pass."""
        filter_off_expected = build_expected(
            enable_bcast_filter=0,
            enable_mcast_filter=0,
            filter_mode=0,
            allowlist_ips=[],
            send_broadcast=self.send_broadcast,
        )
        logger().info(
            "Post-rejoin traffic WITHOUT reconfig — expect filter disabled "
            "(all BC/MC received; no residual MAC/IP filters)"
        )
        sniffing = self._start_ps_sniffer(capture_tag=capture_tag)
        self._apply_filter_and_powersave(clear_stats=False, configure_filter=False)
        self._idle_traffic_and_validate(
            traffic, expected=filter_off_expected, path="none"
        )
        return sniffing

    def _run_ap_restart_rejoin(self, traffic):
        """
        C1726553 only:
          AP Wi-Fi radio OFF/ON -> DUT rejoin (no reboot)
          -> traffic BEFORE reconfig (filter default OFF; all MC/BC pass)
          -> re-apply BC/MC + allowlist from app
          -> traffic AFTER reconfig (filtering resumes)
        """
        logger().info(
            "C1726553: AP Wi-Fi radio OFF/ON / DUT rejoin — "
            "validate filter cleared then re-applied"
        )
        self._ap_radio_off_on_and_rejoin(traffic)

        sniffing = self._validate_filter_cleared_after_rejoin(
            traffic, capture_tag="pre_reconfig_ps"
        )
        if sniffing:
            self._stop_and_assert_ps_pm_bit()

        # Application re-applies BC/MC config + allowlist.
        logger().info(
            "Re-apply BC/MC filter + allowlist from application; "
            "expect filtering to resume"
        )
        sniffing = self._start_ps_sniffer(capture_tag="post_reconfig_ps")
        # _apply_filter_and_powersave exits PS, configures, re-enters PS.
        self._apply_filter_and_powersave(clear_stats=False, configure_filter=True)
        # Extra settle so filter+PS are active before the post-reconfig window
        # (ambient BC pass on immediate clear was seen when traffic started too soon).
        time.sleep(max(5.0, (self.dtim or 1) * 0.5))
        self._wait_dut_reachable_after_stress(timeout_sec=30)
        self._idle_traffic_and_validate(traffic)
        return sniffing

    def _run_ap_disconnect_reset(self, traffic):
        """
        C1726554 only:
          AP Wi-Fi radio OFF -> FW clears BC/MC filtering (PPE + NWP disabled)
          -> radio ON -> DUT reconnect
          -> all multicast/broadcast passed; no residual MAC/IP filters

        Confirms disconnect cleanup; does not re-apply filter (unlike C1726553).
        """
        logger().info(
            "C1726554: AP disconnect cleanup — "
            "validate filter cleared after DUT reconnect"
        )
        self._ap_radio_off_on_and_rejoin(traffic)
        return self._validate_filter_cleared_after_rejoin(
            traffic, capture_tag="post_disconnect_ps"
        )

    def run(self):
        self._ensure_expected()
        traffic = WifiClientBcMcTraffic(wifi_client=self.wifi_client)
        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface="client",
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default,
        )

        # 1) DUT (WLAN+BLE coex) + Raspi on same AP
        self._dut_join()
        self.host_ip = traffic.join_third_party_ap(self.wifi_access_point)

        # 2-4) Configure filter, enter PS; sniffer stays up through traffic
        sniffing = self._start_ps_sniffer()
        self._apply_filter_and_powersave(clear_stats=False)

        if self.scenario == "ap_restart_rejoin":
            # C1726553: baseline filter ON -> Wi-Fi radio OFF/ON -> filter OFF -> re-apply ON
            logger().info("Scenario: ap_restart_rejoin (C1726553) — Wi-Fi radio toggle")
            self._idle_traffic_and_validate(traffic)
            if sniffing:
                self._stop_and_assert_ps_pm_bit()
            sniffing = self._run_ap_restart_rejoin(traffic)
            if sniffing:
                self._stop_and_assert_ps_pm_bit()
        elif self.scenario == "ap_disconnect_reset":
            # C1726554: baseline filter ON -> radio OFF/ON -> filter cleared (no re-apply)
            logger().info(
                "Scenario: ap_disconnect_reset (C1726554) — disconnect cleanup"
            )
            self._idle_traffic_and_validate(traffic)
            if sniffing:
                self._stop_and_assert_ps_pm_bit()
            sniffing = self._run_ap_disconnect_reset(traffic)
            if sniffing:
                self._stop_and_assert_ps_pm_bit()
        else:
            # 5) Idle + Raspi traffic (stats cleared at start of this step)
            self._idle_traffic_and_validate(traffic)
            # 6) Assert PM bit from capture spanning PS entry + traffic
            if sniffing:
                # API-only cases need a short settle; traffic cases already waited.
                settle = 5 if not self.generate_traffic else 0
                self._stop_and_assert_ps_pm_bit(settle_sec=settle)

        cleanup_groupcast_filter(self.wifi_dut, self.filter_handles)
        self.wifi_dut.interfaces.wifi.leave()
        traffic.leave()
        time.sleep(5)


def _common_dut_wifi_config():
    return {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
        | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }


pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


# ---------------------------------------------------------------------------
# Test cases (deprecated removed: C1726544, C1726550, C1726551, C1726555)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.parametrize(
    "filter_mode",
    [0, 1],
    ids=["ppe_mode", "nwp_conservative_mode"],
)
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_off_mc_off_with_zero_MC_IP_ppe_and_nwp_C1726541(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
    sniffer_filter, sl_collections, dtim, filter_mode,
):
    """
    C1726541 — BC OFF, MC OFF, empty allowlist (no filter).
    Expect: allow ALL BC and ALL MC.
    Modes: PPE (filter_mode=0) then NWP/conservative (filter_mode=1).
    """

    mode_tag = "ppe" if filter_mode == 0 else "nwp"
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id=f"C1726541_{mode_tag}",
            enable_bcast_filter=0,
            enable_mcast_filter=0,
            filter_mode=filter_mode,
            allowlist_ips=[],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_on_mc_off_with_zero_MC_IP_default_PPE_C1726542(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """C1726542 — BC ON, MC OFF, empty allowlist, PPE mode."""
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726542",
            enable_bcast_filter=1,
            enable_mcast_filter=0,
            filter_mode=0,
            allowlist_ips=[],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_off_mc_on_with_le2_MC_IP_ppe_C1726543(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726543 — BC OFF, MC ON, <=2 allowlisted MC IPs.
    Mode: default PPE only (filter_mode=0); not NWP/conservative.

    Raspi traffic: BC + allowlisted MC IPs + non-allowlisted MC IPs.

    Expect:
      - ALL BC pass (BC filter OFF)
      - allowlisted MC IPs pass
      - non-allowlisted MC IPs drop
    """
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726543",
            enable_bcast_filter=0,
            enable_mcast_filter=1,
            filter_mode=0,
            allowlist_ips=SuiteConfig.MC_ALLOWLIST_IPS[:2],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_on_mc_on_with_le2_MC_IP_ppe_C1726545(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726545 — Same as C1726543 but BC filter also ON.
    BC ON, MC ON, <=2 allowlisted MC IPs.
    Mode: default PPE only (filter_mode=0); not NWP/conservative.

    Raspi traffic: BC + allowlisted MC IPs + non-allowlisted MC IPs.

    Expect:
      - ALL BC drop (BC filter ON)
      - allowlisted MC IPs pass
      - non-allowlisted MC IPs drop
    """
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726545",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=0,
            allowlist_ips=SuiteConfig.MC_ALLOWLIST_IPS[:2],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_on_mc_on_with_gt2_MC_IP_ppe_fallback_nwp_C1726546(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726546 — BC ON, MC ON, 4 allowlisted MC IPs (>2).
    Mode: configure PPE only (filter_mode=0); FW falls back so NWP takes
    ownership of filtering. Assert NWP counters (not PPE) own BC/MC filter.

    Raspi traffic: BC + allowlisted MC IPs + non-allowlisted MC IPs.

    Expect:
      - ALL BC drop on NWP (BC filter ON)
      - allowlisted MC IPs pass on NWP
      - non-allowlisted MC IPs drop on NWP
      - path = nwp (PPE >2 fallback ownership)
    """
    allow_ips = SuiteConfig.MC_ALLOWLIST_IPS[:4]
    expected = build_expected(
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=allow_ips,
        send_broadcast=True,
    )
    expected.expect_nwp_ownership = True
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726546",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=0,
            allowlist_ips=allow_ips,
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            expected=expected,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_off_mc_on_with_1_MC_IP_nwp_C1726547(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726547 — BC OFF, MC ON, 1 allowlisted MC IP.
    Mode: Conservative/NWP software (filter_mode=1). Must stay on NWP
    (do not switch to PPE) even with only 1 allowlist IP.

    Raspi traffic: BC + allowlisted MC IP + non-allowlisted MC IPs.

    Expect:
      - ALL BC pass (BC filter OFF) on NWP
      - allowlisted MC IP pass on NWP
      - non-allowlisted MC IPs drop on NWP
      - path = nwp (NWP ownership, no PPE switch)
    """
    allow_ips = SuiteConfig.MC_ALLOWLIST_IPS[:1]
    expected = build_expected(
        enable_bcast_filter=0,
        enable_mcast_filter=1,
        filter_mode=1,
        allowlist_ips=allow_ips,
        send_broadcast=True,
    )
    expected.expect_nwp_ownership = True
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726547",
            enable_bcast_filter=0,
            enable_mcast_filter=1,
            filter_mode=1,
            allowlist_ips=allow_ips,
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            expected=expected,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_off_mc_on_with_max6_MC_IP_nwp_C1726548(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726548 — Same as C1726547 but with max 6 allowlisted MC IPs.
    BC OFF, MC ON, Conservative/NWP software (filter_mode=1).
    Must stay on NWP (do not switch to PPE).

    Raspi traffic: BC + allowlisted MC IPs + non-allowlisted MC IPs.

    Expect:
      - ALL BC pass (BC filter OFF) on NWP
      - allowlisted MC IPs pass on NWP
      - non-allowlisted MC IPs drop on NWP
      - path = nwp (NWP ownership, no PPE switch)
    """
    allow_ips = SuiteConfig.MC_ALLOWLIST_IPS[:6]
    expected = build_expected(
        enable_bcast_filter=0,
        enable_mcast_filter=1,
        filter_mode=1,
        allowlist_ips=allow_ips,
        send_broadcast=True,
    )
    expected.expect_nwp_ownership = True
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726548",
            enable_bcast_filter=0,
            enable_mcast_filter=1,
            filter_mode=1,
            allowlist_ips=allow_ips,
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            expected=expected,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_on_mc_on_with_3v4_3v6_MC_IP_nwp_C1726549(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726549 — BC ON, MC ON, max 6 allowlist = 3 IPv4 + 3 IPv6 MC IPs.
    Mode: Conservative/NWP software (filter_mode=1). Stay on NWP (no PPE).

    Raspi traffic: BC + 3 IPv4 allow MC + 3 IPv6 allow MC + non-allow MC (v4+v6).

    Expect:
      - ALL BC drop (BC filter ON) on NWP
      - allowlisted IPv4/IPv6 MC pass on NWP
      - non-allowlisted MC drop on NWP
      - path = nwp (NWP ownership)
    """
    allow_ips = SuiteConfig.MC_ALLOWLIST_IPS[:3] + SuiteConfig.MC_ALLOWLIST_IPV6_IPS[:3]
    nonallow_ips = SuiteConfig.MC_NONALLOW_IPS + SuiteConfig.MC_NONALLOW_IPV6_IPS
    expected = build_expected(
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=1,
        allowlist_ips=allow_ips,
        send_broadcast=True,
    )
    expected.expect_nwp_ownership = True
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726549",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=1,
            allowlist_ips=allow_ips,
            send_broadcast=True,
            nonallow_streams=nonallow_ips,
            expected=expected,
            idle_traffic_wait_sec=120,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.parametrize(
    "filter_mode",
    [0, 1],
    ids=["ppe_mode", "nwp_conservative_mode"],
)
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_bc_on_mc_on_with_concurrent_ping_ppe_and_nwp_C1726552(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
    sniffer_filter, sl_collections, dtim, filter_mode,
):
    """
    C1726552 — BC ON, MC ON, <=2 allowlisted MC IPs.
    Modes: Default PPE (filter_mode=0) then NWP/conservative (filter_mode=1).

    Raspi traffic (parallel):
      - Unicast: ping DUT from Raspi
      - Broadcast + allowlisted MC + non-allowlisted MC

    Expect:
      - ALL BC drop (BC filter ON)
      - allowlisted MC pass; non-allowlisted MC drop
      - Unicast ping replies succeed (filter must not block UC)
    """
    allow_ips = SuiteConfig.MC_ALLOWLIST_IPS[:2]
    mode_tag = "ppe" if filter_mode == 0 else "nwp"
    expected = build_expected(
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=filter_mode,
        allowlist_ips=allow_ips,
        send_broadcast=True,
    )
    if filter_mode == 1:
        expected.expect_nwp_ownership = True
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id=f"C1726552_{mode_tag}",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=filter_mode,
            allowlist_ips=allow_ips,
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            concurrent_ping=True,
            expected=expected,
            idle_traffic_wait_sec=90,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_dut_rejoin_after_ap_restart_C1726553(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726553 — BC ON, MC ON, default (PPE) mode, <=2 allowlist IPs.

    1) Configure filter and verify allow PASS / non-allow DROP
    2) Turn OFF AP Wi-Fi radio (not full AP restart — controller LAN stays up);
       confirm DUT disconnects; turn radio ON; DUT rejoins (no reboot)
    3) Before reconfig API: filtering default OFF — all BC/MC received
    4) Re-apply BC/MC + allowlist from app — correct filtering resumes
    """
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726553",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=0,
            allowlist_ips=SuiteConfig.MC_ALLOWLIST_IPS[:2],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            scenario="ap_restart_rejoin",
            idle_traffic_wait_sec=60,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=_common_dut_wifi_config(),
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.MCBC420IFC
def test_mc_bc_filter_reset_on_ap_disconnect_C1726554(
    firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, sl_collections, dtim,
):
    """
    C1726554 — Filter reset on AP disconnect.
    On disconnect: FW clears BC/MC filtering (PPE + NWP disabled).
    After DUT reconnects: all MC/BC pass; no residual MAC/IP filters.
    """
    try:
        wifi_obj = BcMcFilterFunctional(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C1726554",
            enable_bcast_filter=1,
            enable_mcast_filter=1,
            filter_mode=0,
            allowlist_ips=SuiteConfig.MC_ALLOWLIST_IPS[:2],
            send_broadcast=True,
            nonallow_streams=SuiteConfig.MC_NONALLOW_IPS,
            scenario="ap_disconnect_reset",
            idle_traffic_wait_sec=60,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
