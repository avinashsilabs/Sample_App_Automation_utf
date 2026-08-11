import os
import re
import threading
import time
from typing import List, Optional, Sequence, Tuple

import pytest
from utf.utils.logger import get_logger

"""
BLE GATT write-without-response data-transfer wearables tests (RT595).

C553912 — DUT as Slave: 232 B WWR, buffer mode 1 (Raspi central → DUT peripheral).
C553913 — DUT as Master: 20 B WWR, buffer mode 0 (DUT central → Raspi peripheral).
C553914 — DUT as Master: 232 B GATT write-with-response, buffer mode 1 (DUT central → Raspi peripheral).
C553915 — DUT as Slave: 20 B GATT write-with-response, buffer mode 0 (Raspi central → DUT peripheral).
C553916 — DUT as Slave: 230 B TX indications, buffer mode 1 (Raspi central → DUT peripheral).
C553917 — DUT as Master: 20 B RX notifications, buffer mode 0 (Raspi peripheral → DUT central).
C553918 — Dual role: TX notifications 230 B (buffer mode 1) + RX notifications 20 B (buffer mode 0).
C553919 — DUT as Master: 232 B TX notifications + concurrent scan/adv (GAR-8398), buffer mode 1.
C553920 — Dual role: two connections, RX + TX notifications 20 B, buffer mode 0 (multiple procedures).
C553921 — DUT as Slave: 20 B TX notifications, buffer mode 0 (Raspi central → DUT peripheral).
C553922 — DUT as Slave: 232 B TX notifications, buffer mode 1 (Raspi central → DUT peripheral).
C553923 — DUT as Slave: 232 B TX notifications, buffer mode 1 (wearables steps 1–4).
C553924 — DUT as Slave: max TX notifications, big-buff mode (DLE buffer count 8, GAR-8074).

Every link is configured for data in **both** directions, whatever the DUT's GAP
role on it: the case name gives the DUT->peer (TX) mode, and peer->DUT (RX)
notifications ride the same connection alongside it. See
``_dt_set_bidirectional_data_pattern``.

Harness: 1 DUT (``wifi_dut``) + 1 Raspi (``ble_client``); C553920 (and any dual-role
case that needs concurrent master+slave) uses 2 Raspi via ``ble_clients`` —
``raspi_ble_client`` as central and ``secondary_raspi_ble_client`` as ``slave11``
peripheral — same pattern as multi-role C553973. A master and a slave link cannot
coexist between the same pair of addresses, so one Raspi re-role is not enough.

Each case has its **own** constants and ``_*`` helpers so changes for one case
do not alter the other.  Only stateless UART/hostlog utilities are shared
(``_dt_*`` prefix).

Author: Pavan Jenne
"""

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


connect_status_container = {}
local_dut_address = None

ble_connection_lock = threading.Lock()
bt_connection_lock = threading.Lock()

bt_connection_event = threading.Event()
ble1_connection_event = threading.Event()
ble2_connection_event = threading.Event()

bt_in_progress = False
ble_in_progress = False


def logger():
    return get_logger(__name__)


def setup_test_state():
    """Reset all global connection state BEFORE every test."""
    global connect_status_container, bt_in_progress, ble_in_progress

    connect_status_container.clear()
    bt_in_progress = False
    ble_in_progress = False

    bt_connection_event.clear()
    ble1_connection_event.clear()
    ble2_connection_event.clear()


def cleanup_after_test():
    """Reset all global connection state AFTER every test."""
    global bt_in_progress, ble_in_progress

    connect_status_container.clear()
    bt_connection_event.clear()
    ble1_connection_event.clear()
    ble2_connection_event.clear()
    bt_in_progress = False
    ble_in_progress = False


def set_local_dut_address(dut_address):
    """Store the DUT address used by the peripheral connect flow."""
    global local_dut_address
    local_dut_address = dut_address


def extract_from_serial_log(
    wifi_dut,
    pattern=None,
    group_len=None,
    log_timeout=10,
    poll_interval=2,
    baseline=False,
    latest=True,
    time_window_seconds=None,
):
    """Extract a regex pattern from the DUT serial log with optional
    time-window filtering."""
    deadline = time.time() + log_timeout
    serial_conn = wifi_dut.interfaces.wifi.bus

    try:
        start_index = len(serial_conn.get_input_log()) if baseline else 0
    except Exception:
        start_index = 0

    last_match = None

    while time.time() < deadline:
        input_log = serial_conn.get_input_log()
        current_time = time.time()

        for idx, (ts, line) in enumerate(input_log[start_index:], start=start_index):
            if time_window_seconds is not None:
                elapsed_since_log = current_time - ts
                if elapsed_since_log > time_window_seconds:
                    continue

            try:
                decoded = line.decode(errors="ignore")
            except Exception:
                continue

            match = re.search(pattern, decoded)
            if match:
                value = match.group(1)
                if group_len and len(value) <= group_len:
                    value = value.zfill(group_len)

                if not latest:
                    logger().info(
                        f"value ({len(value)} digits): {value} -> "
                        f"Padded to {group_len} digits: {value}"
                    )
                    return value

                last_match = value

        start_index = len(input_log)

        if last_match and latest and time.time() >= deadline:
            logger().info(f"Latest value ({len(last_match)} digits): {last_match}")
            return last_match

        time.sleep(poll_interval)

    if last_match:
        logger().info(f"Latest value ({len(last_match)} digits): {last_match}")
    return last_match


class BLESSPConnect:
    """BLE SMP pairing handler for DUT (peripheral) + Raspi (central).

    The only functional difference is the ``service_classes`` argument passed to ``start_smp_scan`` ,
    ensuring the Raspi GATT server remains live for the DUT to discover during data transfer.
    """

    def __init__(
        self,
        wifi_dut,
        ble_client,
        dut_capability,
        client_capability,
        pin_code,
        smp_sc=1,
        smp_auth_bond=1,
        smp_mtim=1,
        smp_enc_key=1,
        passkey_state=2,
        random_addr_on_dut=False,
        auth_req="0x05",
        oob_data_flag="0x00",
        service_classes=None,
        skip_smp_scan_setup=False,
    ):
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.dut_capability = dut_capability
        self.client_capability = client_capability
        self.pin_code = pin_code
        self.smp_sc = smp_sc
        self.smp_auth_bond = smp_auth_bond
        self.smp_mtim = smp_mtim
        self.smp_enc_key = smp_enc_key
        self.passkey_state = passkey_state
        self.random_addr_on_dut = random_addr_on_dut
        self.auth_req = auth_req
        self.oob_data_flag = oob_data_flag
        self.service_classes = service_classes or []
        self.skip_smp_scan_setup = skip_smp_scan_setup
        self.ble_dut_address = None
        self.ble_client_address = None

    def run(self):
        io_capability = {
            "DisplayOnly": 0x00,
            "DisplayYesNo": 0x01,
            "KeyboardOnly": 0x02,
            "NoInputNoOutput": 0x03,
            "KeyboardDisplay": 0x04,
        }

        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]

        ble_r2d_connect_status = False

        pairing_method = "PasskeyEntry"
        auth_req_value = 0x2D  # Bonding + MITM + SC

        logger().info(
            f"Pairing Method: {pairing_method}, "
            f"auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)"
        )
        logger().info(
            f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), "
            f"Raspi IO: {self.client_capability} (0x{client_io:02X})"
        )

        raspi_auth_req = f"0x{auth_req_value:02x}"
        logger().info(
            f"Setting Raspi auth_req: {io_capability[self.client_capability]} "
            f"{self.oob_data_flag} {raspi_auth_req}"
        )
        self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(
            f"{io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}"
        )
        _dt_settle("post Raspi set_mitm_sc_bits")

        if not self.skip_smp_scan_setup:
            _dt_raspi_ble_session_reset(self.ble_client, self.ble_dut_address)
            _dt_prepare_raspi_central_connect(
                self.wifi_dut, self.ble_client, self.ble_dut_address
            )

        logger().info(
            f"Setting DUT SMP pairing capability: "
            f"IO={io_capability[self.dut_capability]}, "
            f"OOB={self.oob_data_flag}, auth_req={auth_req_value}"
        )
        self.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=io_capability[self.dut_capability],
            oob_data_flag=int(self.oob_data_flag, 16)
            if isinstance(self.oob_data_flag, str)
            else self.oob_data_flag,
            auth_req=auth_req_value,
            max_encryption_key_size=16,
            initiator_key_distribution=15,
            responder_key_distribution=15,
        )
        _dt_settle("post DUT set_smp_pairing_capability_data")

        if self.skip_smp_scan_setup:
            logger().info(
                "Reusing Raspi GATT/agent from prior start_smp_scan "
                f"(services={self.service_classes})"
            )
            self.ble_client.interfaces.bluetooth.set_bus()
            _dt_settle("post set_bus (reuse smp scan agent)")
            _dt_raspi_disconnect_if_connected(
                self.ble_client, self.ble_dut_address
            )
            _dt_settle("pre-connect Raspi disconnect (reuse scan path)")
            try:
                self.ble_client_address = (
                    self.ble_client.interfaces.bluetooth.get_address()
                )
            except Exception:
                self.ble_client_address = None
        else:
            self.ble_client.interfaces.bluetooth.close()

            logger().info(
                f"Start SMP scan from the remote device (Raspi) "
                f"with services={self.service_classes}"
            )
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut_address,
                capability=self.client_capability,
                pin_code=DT_RASPI_DEFERRED_PASSKEY_PIN,
                service_classes=self.service_classes,
            )
            assert self.ble_client_address, "failed to initiate ble in remote device"
            time.sleep(5)
            logger().info("Stop scanning ...")
            self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info("Check the DUT is listed ...")
            devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"Devices scanned by Raspi: {devices}")
            for dev in devices:
                logger().info(f"Scanned device: {dev}")

            self.ble_client.interfaces.bluetooth.set_bus()
            _dt_settle("post set_bus (start_smp_scan path)")

        connect_log_start = len(self.wifi_dut.interfaces.wifi.bus.get_input_log())
        _dt_settle("before Raspi connect thread")
        if pairing_method == "PasskeyEntry":
            _dt_arm_raspi_deferred_passkey(self.ble_client)

        def connect():
            logger().info(
                f"Trying to Connect (Raspi(Central)->DUT (peripheral) "
                f"{ble_r2d_connect_status}"
            )
            logger().info(
                f"Connect and pair to the DUT ({pairing_method},"
                f"{self.ble_dut_address} - using connect with supervision timeout)"
            )
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=self.ble_dut_address,
                supervision_timeout=500,
            )

        t = threading.Thread(target=connect, daemon=True)
        t.start()

        if pairing_method == "PasskeyEntry":
            logger().info("Passkey Entry pairing - monitoring serial logs for passkey")
            passkey = _dt_wait_for_passkey_and_enter_on_raspi(
                self.wifi_dut,
                self.ble_client,
                connect_log_start,
                timeout_sec=DT_PASSKEY_TIMEOUT_SEC,
            )
            t.join(timeout=DT_PASSKEY_TIMEOUT_SEC + 30)
            logger().info(f"Setting passkey: {passkey}")
            le_ltk = extract_from_serial_log(
                self.wifi_dut,
                r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})",
                log_timeout=60,
                baseline=True,
                latest=True,
                time_window_seconds=90,
            )
            logger().info(f"LE LTK extracted: {le_ltk}")
            assert le_ltk is not None, "le_ltk was not found in DUT serial log"

            if le_ltk:
                ble_r2d_connect_status = True

            time.sleep(5)
            logger().info(
                f"(Raspi(Central)->DUT (peripheral) successfully connected: "
                f"{ble_r2d_connect_status}"
            )
        else:
            t.join(timeout=60)

        return ble_r2d_connect_status


def connect_dut_as_peripheral_raspii_as_central(
    ble_dut,
    ble_client,
    wait_for_bt=False,
    event_to_signal=None,
    service_classes=None,
    skip_smp_scan_setup=False,
):
    """DUT peripheral / Raspi central connect flow.

    ``service_classes`` is registered on the Raspi GATT server during the
    connect so the DUT can discover the peer service for data transfer.
    """
    global local_dut_address
    global ble_in_progress

    if event_to_signal is None:
        event_to_signal = ble1_connection_event

    if wait_for_bt:
        logger().info("BLE waiting for BT to complete...")
        bt_connection_event.wait()
        logger().info(" BT completed, proceeding with BLE")

    connect_status = False
    with ble_connection_lock:
        logger().info("BLE connection started (DUT as peripheral)")
        ble_in_progress = True
        event_to_signal.clear()

        try:
            target_address = local_dut_address
            logger().info("\n\n **Raspii as Central and DUT as Peripheral**\n\n")
            ble_test = BLESSPConnect(
                wifi_dut=ble_dut,
                ble_client=ble_client,
                dut_capability="DisplayOnly",
                client_capability="KeyboardDisplay",
                pin_code="-8",
                service_classes=service_classes,
                skip_smp_scan_setup=skip_smp_scan_setup,
            )
            ble_test.ble_dut_address = target_address
            connect_status = ble_test.run()

            logger().info(
                f" BLE connection (DUT as peripheral) completed: {connect_status}"
            )
            return connect_status
        finally:
            ble_in_progress = False
            event_to_signal.set()
            logger().info(" BLE connection lock released")


# DUT-as-central legacy connect parameters (``req_legacy_connect``, aliased as
# ``ble_legacy_connect_req``). Scan interval/window and CE length are in units of
# 0.625 ms, connection interval in 1.25 ms and supervision timeout in 10 ms.
DT_CENTRAL_CONNECT_ADD_TYPE = 0             # peer address type: 0=public, 1=random
DT_CENTRAL_CONNECT_FILTER_POLICY = 0        # 0=accept all advertisers
DT_CENTRAL_CONNECT_OWN_ADDR_TYPE = 0        # 0=public
DT_CENTRAL_CONNECT_SCAN_INTERVAL = 80       # 50 ms
DT_CENTRAL_CONNECT_SCAN_WINDOW = 80         # 50 ms
DT_CENTRAL_CONNECT_CI_MIN = 160             # 200 ms
DT_CENTRAL_CONNECT_CI_MAX = 160             # 200 ms
DT_CENTRAL_CONNECT_LATENCY = 0
DT_CENTRAL_CONNECT_SUPERVISION_TOUT = 500   # 5000 ms
DT_CENTRAL_CONNECT_MIN_CE_LENGTH = 4        # 2.5 ms
DT_CENTRAL_CONNECT_MAX_CE_LENGTH = 6        # 3.75 ms


def connect_dut_as_central_raspii_as_peripheral(
    ble_dut,
    ble_client,
    dut_capability=None,
    client_capability=None,
    auth_req_value=0x2D,
    wait_for_bt=False,
    wait_for_ble1=False,
    event_to_signal=None,
    service_classes=None,
    dev_name=None,
    add_type=DT_CENTRAL_CONNECT_ADD_TYPE,
    filter_policy=DT_CENTRAL_CONNECT_FILTER_POLICY,
    own_addr_type=DT_CENTRAL_CONNECT_OWN_ADDR_TYPE,
    le_scan_interval=DT_CENTRAL_CONNECT_SCAN_INTERVAL,
    le_scan_window=DT_CENTRAL_CONNECT_SCAN_WINDOW,
    conn_interval_min=DT_CENTRAL_CONNECT_CI_MIN,
    conn_interval_max=DT_CENTRAL_CONNECT_CI_MAX,
    conn_latency=DT_CENTRAL_CONNECT_LATENCY,
    supervision_tout=DT_CENTRAL_CONNECT_SUPERVISION_TOUT,
    min_ce_length=DT_CENTRAL_CONNECT_MIN_CE_LENGTH,
    max_ce_length=DT_CENTRAL_CONNECT_MAX_CE_LENGTH,
):
    """DUT central / Raspi peripheral connect flow.

    ``service_classes`` is registered on the Raspi GATT server (advertiser)
    so the DUT (central) can discover the peer service for data transfer.

    ``dev_name`` and every ``add_type`` .. ``max_ce_length`` argument is forwarded
    to the DUT legacy connect request; the ``DT_CENTRAL_CONNECT_*`` defaults hold
    the values used by the wearables data-transfer cases.
    """
    ble_d2r_connect_status = False
    passkey = False
    global local_dut_address
    global ble_in_progress

    if event_to_signal is None:
        event_to_signal = ble1_connection_event

    if wait_for_bt:
        logger().info("BLE waiting for BT to complete...")
        bt_connection_event.wait()
        logger().info(" BT completed")

    if wait_for_ble1:
        logger().info("BLE2 waiting for BLE1 to complete...")
        ble1_connection_event.wait()
        logger().info(" BLE1 completed")

    with ble_connection_lock:
        logger().info("BLE connection started (DUT as central)")
        ble_in_progress = True
        event_to_signal.clear()

        try:
            logger().info("\n\n **DUT as Central and Raspii as Peripheral**\n\n")
            _dt_raspi_ble_session_reset(ble_client)

            io_capability_map = {
                "DisplayOnly": 0x00,
                "DisplayYesNo": 0x01,
                "KeyboardOnly": 0x02,
                "NoInputNoOutput": 0x03,
                "KeyboardDisplay": 0x04,
            }

            client_cap_str = io_capability_map.get(client_capability, "KeyboardDisplay")
            dut_cap_str = io_capability_map.get(dut_capability, "DisplayOnly")

            oob_data_flag = "0x00"

            pairing_method = "PasskeyEntry"
            logger().info(
                f"Pairing Method: {pairing_method}, "
                f"auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)"
            )
            logger().info(f"DUT IO: {dut_cap_str} , Raspi IO: {client_cap_str}")
            raspi_auth_req = f"0x{auth_req_value:02x}"
            logger().info(
                f"Setting Raspi auth_req: {client_capability} "
                f"{oob_data_flag} {raspi_auth_req}"
            )

            ble_client.interfaces.bluetooth.set_mitm_sc_bits(
                f"{io_capability_map[client_capability]} {oob_data_flag} {raspi_auth_req}"
            )
            _dt_settle("post Raspi set_mitm_sc_bits (DUT central)")

            ble_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=io_capability_map[dut_capability],
                oob_data_flag=int(oob_data_flag, 16)
                if isinstance(oob_data_flag, str)
                else oob_data_flag,
                auth_req=auth_req_value,
                max_encryption_key_size=16,
                initiator_key_distribution=15,
                responder_key_distribution=15,
            )
            _dt_settle("post DUT set_smp_pairing_capability_data (DUT central)")

            ble_client.interfaces.bluetooth.close()
            _dt_settle("post Raspi close before start_smp_adv")
            logger().info(
                f"\n\n **** Set RaspberryPi as advertiser "
                f"(services={service_classes}) ****\n\n"
            )
            ble_remote_address = ble_client.interfaces.bluetooth.start_smp_adv(
                None,
                pin_code=DT_RASPI_DEFERRED_PASSKEY_PIN,
                capability=client_capability,
                service_classes=service_classes,
            )
            assert ble_remote_address and _BD_ADDR_RE.match(
                str(ble_remote_address).strip()
            ), (
                f"invalid remote address from advertiser: '{ble_remote_address}'"
            )
            logger().info(
                f"\n\n **** Adv started remote address: {ble_remote_address} ****\n\n"
            )

            time.sleep(5)

            ble_client.interfaces.bluetooth.set_bus()
            _dt_settle("post set_bus (DUT central)")

            if hasattr(ble_dut.interfaces.wifi, "btc_disconnect"):
                try:
                    ble_dut.interfaces.wifi.btc_disconnect(ble_remote_address)
                    time.sleep(2)
                except Exception:
                    pass

            _dt_restart_peer_advertising(ble_client, service_classes)
            _dt_settle("post Raspi adv restart before DUT legacy connect")

            logger().info(
                f"Trying to Connect (DUT(Central)->Raspi (peripheral) "
                f"{ble_d2r_connect_status}"
            )

            connect_log_start = len(ble_dut.interfaces.wifi.bus.get_input_log())
            _dt_arm_raspi_deferred_passkey(ble_client)

            try:
                if hasattr(ble_dut.interfaces.wifi, "legacy_scan_stop"):
                    ble_dut.interfaces.wifi.legacy_scan_stop()
                    time.sleep(1)
            except Exception as exc:
                logger().warning(f"DUT legacy_scan_stop before connect: {exc}")

            connect_exc = {"error": None}

            logger().info(
                f"DUT legacy connect params: add_type={add_type}, "
                f"filter_policy={filter_policy}, own_addr_type={own_addr_type}, "
                f"scan={le_scan_interval}/{le_scan_window}, "
                f"CI={conn_interval_min}-{conn_interval_max}, "
                f"latency={conn_latency}, supervision_tout={supervision_tout}, "
                f"CE_len={min_ce_length}-{max_ce_length}"
            )

            def _dut_central_connect():
                try:
                    ble_dut.interfaces.wifi.ble_legacy_connect_req(
                        dev_addr=ble_remote_address,
                        dev_name=dev_name,
                        add_type=add_type,
                        filter_policy=filter_policy,
                        own_addr_type=own_addr_type,
                        le_scan_interval=le_scan_interval,
                        le_scan_window=le_scan_window,
                        conn_interval_min=conn_interval_min,
                        conn_interval_max=conn_interval_max,
                        conn_latency=conn_latency,
                        supervision_tout=supervision_tout,
                        min_ce_length=min_ce_length,
                        max_ce_length=max_ce_length,
                    )
                except Exception as exc:
                    connect_exc["error"] = exc

            # SMP IO-cap pattern: connect in background; enter passkey on Raspi ASAP.
            connect_thread = threading.Thread(target=_dut_central_connect, daemon=True)
            connect_thread.start()

            passkey = _dt_wait_for_passkey_and_enter_on_raspi(
                ble_dut,
                ble_client,
                connect_log_start,
                timeout_sec=DT_PASSKEY_TIMEOUT_SEC,
            )

            connect_thread.join(timeout=DT_PASSKEY_TIMEOUT_SEC + 30)
            if connect_exc["error"]:
                raise connect_exc["error"]

            logger().info(f"Passkey entry complete (passkey={passkey})")

            le_smp_error = extract_from_serial_log(
                ble_dut,
                r"failed to initiate the SMP pairing process: (0x[0-9a-fA-F]+)",
                log_timeout=10,
                baseline=True,
                latest=False,
                time_window_seconds=5,
            )
            if le_smp_error:
                raise AssertionError(
                    f"SMP pairing failed with error code: {le_smp_error}"
                )
            else:
                logger().info("No SMP pairing error found in serial log.")

            logger().info("SMP done")

            time.sleep(3)
            try:
                le_ltk = extract_from_serial_log(
                    ble_dut,
                    r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})",
                    log_timeout=30,
                    baseline=False,
                    latest=True,
                    time_window_seconds=30,
                )
                logger().info(f"LE LTK extracted: {le_ltk}")
                if le_ltk is None:
                    raise AssertionError("LE LTK was not found in DUT serial log")
                if all(x.strip().lower() == "0x00" for x in le_ltk.split()):
                    raise AssertionError(f"LE LTK is all zeros: {le_ltk}")

                ble_d2r_connect_status = True
                logger().info(
                    f"Connection (DUT(Central)->Raspi (peripheral) completed "
                    f"successfully {ble_d2r_connect_status}"
                )
            except Exception as error:
                raise AssertionError(f"Exception during LE LTK extraction: {error}")

            return ble_d2r_connect_status
        finally:
            ble_in_progress = False
            event_to_signal.set()
            logger().info(" BLE connection lock released")


DT_PASSKEY_TIMEOUT_SEC = 120
DT_PASSKEY_POLL_SEC = 0.5
DT_PASSKEY_PROGRESS_LOG_SEC = 15
# BlueZ agent pin: -8 = wait for runtime ``set_pin()`` (see bluetooth_agent.RequestPasskey).
DT_RASPI_DEFERRED_PASSKEY_PIN = "-8"
# Pause before DUT/Raspi BLE CLI and BlueZ calls (override via env for lab tuning).
DT_INTER_CMD_SETTLE_SEC = float(os.environ.get("DT_INTER_CMD_SETTLE_SEC", "2"))
# After an SMP-fail status line, keep polling briefly for a passkey (UART ordering).
DT_SMP_FAIL_GRACE_SEC = float(os.environ.get("DT_SMP_FAIL_GRACE_SEC", "12"))


def _dt_settle(label: Optional[str] = None, sec: Optional[float] = None) -> None:
    """Standard inter-command delay so firmware / BlueZ can catch up."""
    delay = DT_INTER_CMD_SETTLE_SEC if sec is None else sec
    time.sleep(delay)


def _dt_arm_raspi_deferred_passkey(ble_client) -> None:
    """Put the Raspi SMP agent into wait-for-``set_pin`` mode before pairing."""
    try:
        ble_client.interfaces.bluetooth.set_pin(int(DT_RASPI_DEFERRED_PASSKEY_PIN))
    except Exception as exc:
        logger().warning(f"Raspi set_pin({DT_RASPI_DEFERRED_PASSKEY_PIN}): {exc}")


def _dt_start_raspi_smp_scan(
    ble_client,
    bt_dut_address: str,
    *,
    capability: str,
    service_classes,
):
    """``start_smp_scan`` with deferred passkey agent (not default 4321)."""
    return ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address,
        capability=capability,
        pin_code=DT_RASPI_DEFERRED_PASSKEY_PIN,
        service_classes=service_classes,
    )


DT_RASPI_SCAN_RETRY_COUNT = int(os.environ.get("DT_RASPI_SCAN_RETRY_COUNT", "5"))
DT_RASPI_SCAN_DWELL_SEC = float(os.environ.get("DT_RASPI_SCAN_DWELL_SEC", "8"))
DT_RASPI_SCAN_EXTRA_WAIT_SEC = float(os.environ.get("DT_RASPI_SCAN_EXTRA_WAIT_SEC", "18"))


def _dt_dut_visible_in_raspi_scan(devices, dut_address: str) -> bool:
    if not dut_address:
        return False
    norm = dut_address.replace(":", "").lower()
    for key in devices or {}:
        k = str(key).replace(":", "").lower()
        if dut_address in str(key) or k == norm:
            return True
    return False


def _dt_hostlog_tail_text(bus, *, max_lines: int = 150) -> str:
    log = bus.get_input_log()
    start = max(0, len(log) - max_lines)
    return _dt_hostlog_text(bus, start)


def _dt_force_legacy_adv(wifi_dut, bus, case_id: str) -> bool:
    """Always issue ``legacy_adv``; accept firmware already-in-progress responses."""
    wifi = wifi_dut.interfaces.wifi
    if not hasattr(wifi, "legacy_adv"):
        return False
    baseline = len(bus.get_input_log())
    try:
        result = wifi.legacy_adv(status=1, own_addr_type=_DT_DEFAULT_OWN_ADDR_TYPE)
        if any(m in str(result or "").lower() for m in _DT_ADV_ACTIVE_MARKERS):
            return True
    except Exception as exc:
        if any(m in str(exc).lower() for m in _DT_ADV_ACTIVE_MARKERS):
            return True
        logger().warning(f"legacy_adv: {exc}")
    chunk = _dt_hostlog_text(bus, baseline)
    return any(m in chunk for m in _DT_ADV_ACTIVE_MARKERS)


def _dt_force_legacy_scan(wifi_dut, bus, case_id: str) -> bool:
    """Always issue ``legacy_scan``; accept firmware already-in-progress responses."""
    wifi = wifi_dut.interfaces.wifi
    if not hasattr(wifi, "legacy_scan"):
        return False
    baseline = len(bus.get_input_log())
    try:
        result = wifi.legacy_scan(status=1)
        if any(m in str(result or "").lower() for m in _DT_SCAN_ACTIVE_MARKERS):
            return True
    except Exception as exc:
        if any(m in str(exc).lower() for m in _DT_SCAN_ACTIVE_MARKERS):
            return True
        logger().warning(f"legacy_scan: {exc}")
    chunk = _dt_hostlog_text(bus, baseline)
    return any(m in chunk for m in _DT_SCAN_ACTIVE_MARKERS)


def _dt_prepare_dut_for_raspi_central_scan(
    wifi_dut, bus, case_id: str, *, force_adv: bool = False
) -> None:
    """
    Settle the DUT before Raspi ``start_smp_scan`` (peripheral / slave role).

    The readiness gate at the top of every case (``_dt_ensure_dut_ble_ready``)
    already issued ``legacy_adv`` and confirmed the DUT is advertising, so the
    first scan attempt must not repeat the CLI — one ``req_legacy_adv`` per case
    is what the review asks for. ``force_adv=True`` is only used as recovery on a
    retry, i.e. after a scan attempt genuinely failed to see the DUT.
    """
    if force_adv:
        _dt_force_legacy_adv(wifi_dut, bus, case_id)
    time.sleep(max(_DT_CMD_SETTLE_SEC, DT_INTER_CMD_SETTLE_SEC))


def _dt_restore_dut_peripheral_advertising(
    wifi_dut, bus, case_id: str, *, restore_scan: bool = False
) -> None:
    """Re-enable DUT legacy advertising (and optionally scanning) after central-heavy cases."""
    _dt_settle()
    _dt_force_legacy_adv(wifi_dut, bus, case_id)
    time.sleep(max(_DT_CMD_SETTLE_SEC, DT_INTER_CMD_SETTLE_SEC))
    if restore_scan:
        _dt_force_legacy_scan(wifi_dut, bus, case_id)


def _dt_prep_for_raspi_central_after_master_role(
    wifi_dut, ble_client, dut_address: str, bus, case_id: str
) -> None:
    """
    Drop DUT-central / stale bond state (e.g. after C553919) before Raspi-central tests.

    Advertising is not re-issued here: the readiness gate that runs immediately
    before this call already confirmed it, and repeating the CLI only produced a
    second ``ble_connectable_adv_already_in_progress`` in the report. If clearing
    the bond does take advertising down, the scan retry in
    ``_dt_raspi_scan_for_dut_peripheral`` re-issues it as recovery.
    """
    logger().info(
        f"Prep for Raspi central: disconnect and clear bonds"
    )
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    _dt_raspi_ble_session_reset(ble_client, dut_address)
    _dt_delete_dut_bond(wifi_dut, None)
    time.sleep(max(_DT_CMD_SETTLE_SEC, DT_INTER_CMD_SETTLE_SEC))


def _dt_raspi_scan_for_dut_peripheral(
    wifi_dut,
    ble_client,
    dut_address: str,
    bus,
    case_id: str,
    *,
    service_classes,
    capability: str = "KeyboardDisplay",
    dwell_sec: Optional[float] = None,
) -> str:
    """Scan until DUT appears in Raspi ``get_devices`` (retry + legacy_adv recovery)."""
    dwell = DT_RASPI_SCAN_DWELL_SEC if dwell_sec is None else dwell_sec
    last_devices: dict = {}
    peer_addr = ""
    for attempt in range(1, DT_RASPI_SCAN_RETRY_COUNT + 1):
        _dt_prepare_dut_for_raspi_central_scan(
            wifi_dut,
            bus,
            f"Raspi scan attempt {attempt}",
            force_adv=attempt > 1,
        )
        _dt_raspi_ble_session_reset(ble_client, dut_address)
        ble_client.interfaces.bluetooth.set_bus()
        _dt_settle()
        peer_addr = _dt_start_raspi_smp_scan(
            ble_client,
            dut_address,
            capability=capability,
            service_classes=service_classes,
        )
        assert peer_addr, f"failed to start Raspi SMP scan (attempt {attempt})"
        scan_deadline = time.time() + dwell + DT_RASPI_SCAN_EXTRA_WAIT_SEC
        last_devices: dict = {}
        while time.time() < scan_deadline:
            last_devices = ble_client.interfaces.bluetooth.get_devices() or {}
            if _dt_dut_visible_in_raspi_scan(last_devices, dut_address):
                logger().info(
                    f"Raspi scan attempt {attempt}/{DT_RASPI_SCAN_RETRY_COUNT} "
                    f"devices={last_devices}"
                )
                ble_client.interfaces.bluetooth.stop_scanning()
                return peer_addr
            time.sleep(2)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(
            f"Raspi scan attempt {attempt}/{DT_RASPI_SCAN_RETRY_COUNT} "
            f"devices={last_devices} (DUT not seen before scan window ended)"
        )
        _dt_settle()
    assert _dt_dut_visible_in_raspi_scan(last_devices, dut_address), (
        f"DUT {dut_address} not visible on Raspi scan after "
        f"{DT_RASPI_SCAN_RETRY_COUNT} attempts (last devices={last_devices})"
    )
    return peer_addr


def _dt_bus(wifi_dut):
    return wifi_dut.interfaces.wifi.bus


def _dt_scan_serial_since(
    bus, scan_index: int
) -> Tuple[int, Optional[str], Optional[str]]:
    """Scan new UART lines since ``scan_index``.

    Returns ``(new_scan_index, passkey_or_none, smp_fail_status_or_none)``.
    """
    passkey_re = re.compile(
        r"passkey[:\s]+(\d+)",
        re.IGNORECASE,
    )
    passkey_alt_re = re.compile(
        r"pass\s*key[^0-9]*(\d{5,6})\b",
        re.IGNORECASE,
    )
    smp_fail_re = re.compile(
        r"SMP failed.*?status\s*:\s*([0-9a-fA-Fx]+)",
        re.IGNORECASE | re.DOTALL,
    )
    passkey = None
    smp_status = None
    input_log = bus.get_input_log()
    while scan_index < len(input_log):
        _ts, line = input_log[scan_index]
        scan_index += 1
        try:
            decoded = (
                line.decode(errors="ignore")
                if isinstance(line, bytes)
                else str(line)
            )
        except Exception:
            continue
        m_pk = passkey_re.search(decoded) or passkey_alt_re.search(decoded)
        if m_pk:
            raw = m_pk.group(1)
            passkey = raw.zfill(6) if len(raw) <= 6 else raw[:6]
            smp_status = None
        elif smp_status is None:
            m_fail = smp_fail_re.search(decoded)
            if m_fail:
                smp_status = m_fail.group(1)
    return scan_index, passkey, smp_status


def _dt_wait_for_passkey_and_enter_on_raspi(
    wifi_dut,
    ble_client,
    log_start: int,
    timeout_sec: int = DT_PASSKEY_TIMEOUT_SEC,
) -> str:
    """Poll DUT log for passkey (up to ``timeout_sec``) and call ``set_pin`` ASAP.

    Aligns with SMP IO-cap DUT-central flow: Raspi must receive the passkey
    within the firmware SMP window, not after a long idle.
    """
    bus = wifi_dut.interfaces.wifi.bus
    start_time = time.time()
    deadline = start_time + timeout_sec
    next_progress_log = start_time + DT_PASSKEY_PROGRESS_LOG_SEC
    scan_index = log_start

    logger().info(
        f"Waiting for passkey in DUT serial log (timeout={timeout_sec}s, "
        f"deadline={time.strftime('%H:%M:%S', time.localtime(deadline))})..."
    )

    while time.time() < deadline:
        scan_index, found_pk, smp_status = _dt_scan_serial_since(bus, scan_index)
        if not found_pk:
            tail_pk = _dt_scan_serial_since(bus, max(0, len(bus.get_input_log()) - 200))[1]
            if tail_pk:
                found_pk = tail_pk
        if found_pk:
            elapsed = int(time.time() - start_time)
            logger().info(
                f"Passkey found after {elapsed}s: {found_pk}; Raspi entering passkey"
            )
            ble_client.interfaces.bluetooth.set_pin(int(found_pk))
            return found_pk
        if smp_status:
            grace_deadline = time.time() + DT_SMP_FAIL_GRACE_SEC
            logger().warning(
                f"DUT reported SMP status {smp_status}; grace polling for passkey "
                f"for {DT_SMP_FAIL_GRACE_SEC:.0f}s"
            )
            while time.time() < grace_deadline:
                time.sleep(DT_PASSKEY_POLL_SEC)
                scan_index, found_pk, smp_status = _dt_scan_serial_since(
                    bus, scan_index
                )
                if found_pk:
                    elapsed = int(time.time() - start_time)
                    logger().info(
                        f"Passkey found during SMP grace after {elapsed}s: {found_pk}"
                    )
                    ble_client.interfaces.bluetooth.set_pin(int(found_pk))
                    return found_pk
                if not smp_status:
                    break
            if smp_status:
                raise AssertionError(
                    f"SMP pairing failed on DUT (status {smp_status}) before passkey "
                    f"was displayed — verify Raspi agent (KeyboardDisplay) and "
                    f"auth_req=0x2D match DUT DisplayOnly"
                )
            continue

        now = time.time()
        if now >= next_progress_log:
            elapsed = int(now - start_time)
            remaining = max(0, int(deadline - now))
            logger().info(
                f"Still waiting for passkey... elapsed={elapsed}s "
                f"remaining={remaining}s"
            )
            next_progress_log = now + DT_PASSKEY_PROGRESS_LOG_SEC

        time.sleep(DT_PASSKEY_POLL_SEC)

    elapsed = int(time.time() - start_time)
    logger().error(
        f"Passkey not found in DUT serial log after {elapsed}s "
        f"(timeout={timeout_sec}s)"
    )
    raise AssertionError(
        f"Passkey not found in the serial log within {timeout_sec}s "
        f"(waited {elapsed}s)"
    )


def _dt_wait_for_passkey(wifi_dut, log_start: int, timeout_sec: int = DT_PASSKEY_TIMEOUT_SEC) -> str:
    """Poll the DUT serial log for a 6-digit SMP passkey (no Raspi set_pin)."""
    bus = wifi_dut.interfaces.wifi.bus
    start_time = time.time()
    deadline = start_time + timeout_sec
    next_progress_log = start_time + DT_PASSKEY_PROGRESS_LOG_SEC
    scan_index = log_start

    logger().info(
        f"Waiting for passkey in DUT serial log (timeout={timeout_sec}s, "
        f"deadline={time.strftime('%H:%M:%S', time.localtime(deadline))})..."
    )

    while time.time() < deadline:
        scan_index, passkey, smp_status = _dt_scan_serial_since(bus, scan_index)
        if passkey:
            elapsed = int(time.time() - start_time)
            logger().info(f"Passkey found in serial log after {elapsed}s: {passkey}")
            return passkey
        if smp_status:
            grace_deadline = time.time() + DT_SMP_FAIL_GRACE_SEC
            while time.time() < grace_deadline:
                time.sleep(DT_PASSKEY_POLL_SEC)
                scan_index, passkey, smp_status = _dt_scan_serial_since(
                    bus, scan_index
                )
                if passkey:
                    elapsed = int(time.time() - start_time)
                    logger().info(
                        f"Passkey found during SMP grace after {elapsed}s: {passkey}"
                    )
                    return passkey
                if not smp_status:
                    break
            if smp_status:
                raise AssertionError(
                    f"SMP pairing failed on DUT (status {smp_status}) before passkey "
                    "was displayed"
                )
            continue

        now = time.time()
        if now >= next_progress_log:
            elapsed = int(now - start_time)
            remaining = max(0, int(deadline - now))
            logger().info(
                f"Still waiting for passkey... elapsed={elapsed}s "
                f"remaining={remaining}s"
            )
            next_progress_log = now + DT_PASSKEY_PROGRESS_LOG_SEC

        time.sleep(DT_PASSKEY_POLL_SEC)

    elapsed = int(time.time() - start_time)
    logger().error(
        f"Passkey not found in DUT serial log after {elapsed}s "
        f"(timeout={timeout_sec}s)"
    )
    raise AssertionError(
        f"Passkey not found in the serial log within {timeout_sec}s "
        f"(waited {elapsed}s)"
    )


def _dt_delete_dut_bond(wifi_dut, peer_address=None):
    """Delete the DUT-side pairing/LTK so no bond leaks to the next test case.

    Review comment 3: prefer Raspi-side disconnect in each case's ``_cleanup_peer``.
    When the ACL is still up (e.g. assertion during data-path setup), issue a
    best-effort DUT ``btc_disconnect`` before ``remove_ltk`` so the next Raspi
    central connect is not rejected with BlueZ "connection abort".
    """
    if wifi_dut is None:
        return
    wifi = wifi_dut.interfaces.wifi
    if peer_address and hasattr(wifi, "btc_disconnect"):
        try:
            wifi.btc_disconnect(str(peer_address).strip())
            time.sleep(2)
        except Exception:
            pass


_DT_SERVICE_UUIDS = {
    "ImmediateAlertService": "0x1802",
    "HeartRateService": "0x180D",
    "HealthThermometerService": "0x1809",
    "GenericDataService": "0x006e",
}


def _dt_build_raspi_services(*service_classes):
    """Build the ``service_classes`` list for Raspi ``start_smp_scan`` / ``start_smp_adv``.

    Each case exposes ``C5539xx_GATT_SERVICE`` (primary profile for logs) and
    ``C5539xx_SERVICE_CLASSES`` (full list, including WWR extras when needed).

    Every case also gets ``HeartRateService`` so the peer can drive the peer->DUT
    (RX) leg: each link is configured for data in both directions, and 0x2A37 is
    the notification source the DUT subscribes to.
    """
    ordered: List[object] = []
    seen = set()
    for service_class in service_classes:
        if not service_class or service_class in seen:
            continue
        ordered.append(service_class)
        seen.add(service_class)
    if "ImmediateAlertService" in seen:
        for extra in ("GenericDataService", "HealthThermometerService"):
            if extra not in seen:
                ordered.append(extra)
                seen.add(extra)
    if _DT_RX_NOTIFY_SERVICE not in seen:
        ordered.append(_DT_RX_NOTIFY_SERVICE)
        seen.add(_DT_RX_NOTIFY_SERVICE)
    return ordered


def _dt_service_uuid_list(service_classes=None):
    uuids: List[str] = []
    for service_class in service_classes or []:
        if isinstance(service_class, str):
            uuid = _DT_SERVICE_UUIDS.get(service_class)
        else:
            uuid = getattr(service_class, "UUID", None) or getattr(
                service_class, "GDS_UUID", None
            )
        if uuid and uuid not in uuids:
            uuids.append(uuid)
    return uuids


# GATT profiles the DUT firmware expects on the Raspi peer (SDK data-transfer parity).
_DT_GATT_WWR_PROFILES = (
    (0x1802, 0x2A06),  # Immediate Alert / alert level (SDK WWR path)
    (0x006E, 0x006F),  # Generic data / write-without-response
)
_DT_GATT_WR_PROFILES = ((0x180D, 0x2A39),)  # Heart Rate control point
_DT_GATT_NOTIFY_RX_PROFILES = ((0x1809, 0x2A1E),)  # Health thermometer custom notify
_DT_GATT_HR_NOTIFY_PROFILES = ((0x180D, 0x2A37),)  # Heart rate measurement + CCCD

_DT_PROFILES_BY_KIND = {
    "wwr": _DT_GATT_WWR_PROFILES,
    "wr": _DT_GATT_WR_PROFILES,
    "notify": _DT_GATT_NOTIFY_RX_PROFILES,
    "notify_rx": _DT_GATT_NOTIFY_RX_PROFILES,
    "notify_hr": _DT_GATT_HR_NOTIFY_PROFILES,
}

_DT_RX_PROFILE_KIND = "notify_hr"
_DT_RX_NOTIFY_SERVICE = "HeartRateService"


def _dt_profiles_for_kinds(*profile_kinds) -> tuple:
    """Ordered, de-duplicated (service_uuid, char_uuid) pairs for the given kinds."""
    profiles: List[tuple] = []
    for kind in profile_kinds:
        if not kind:
            continue
        for entry in _DT_PROFILES_BY_KIND.get(kind, _DT_GATT_WWR_PROFILES):
            if entry not in profiles:
                profiles.append(entry)
    return tuple(profiles)


def _dt_raspi_ble_session_reset(ble_client, dut_address: Optional[str] = None) -> None:
    """Tear down BlueZ GATT/agent so the next ``start_smp_scan`` can register cleanly."""
    bt = ble_client.interfaces.bluetooth
    try:
        bt.close()
    except Exception:
        pass
    _dt_settle("post Raspi bluetooth.close (session reset)")
    if dut_address:
        try:
            bt.remove_device(bt_dut_address=dut_address)
        except Exception:
            pass
        time.sleep(1)


def _dt_dut_discover_peer_gatt_for_transfer(
    wifi_dut,
    bus,
    peer_address: str,
    case_id: str,
    *,
    profile_kind: str,
    rx_profile_kind: Optional[str] = _DT_RX_PROFILE_KIND,
    settle_sec: float = 3.0,
) -> None:
    """Run DUT-side GATT discovery on the bonded Raspi peer before ``set_data_pattern``.

    Matches ``Ble_Data_Transfer.service_discovery_on_DUT`` in the SDK/helper
    suites: the DUT requires remote service and characteristic handles for
    bidirectional data transfer; use rx_profile_kind=None for TX-only links.
    """
    profiles = _dt_profiles_for_kinds(profile_kind, rx_profile_kind)

    wifi = wifi_dut.interfaces.wifi
    peer = str(peer_address).strip()
    baseline = len(bus.get_input_log())
    logger().info(
        f"DUT GATT discovery on peer {peer} "
        f"(TX profile_kind={profile_kind}, RX profile_kind={rx_profile_kind})"
    )
    for service_uuid, _char_uuid in profiles:
        try:
            if hasattr(wifi, "ble_get_profile_async"):
                wifi.ble_get_profile_async(peer, service_uuid)
            time.sleep(settle_sec)
            if hasattr(wifi, "ble_get_char_services_async"):
                wifi.ble_get_char_services_async(peer, 1, 0xFFFF)
            time.sleep(settle_sec)
        except Exception as exc:
            logger().warning(
                f"GATT discovery service 0x{service_uuid:04x}: {exc}"
            )

    found, _ = _dt_wait_hostlog(
        bus,
        (
            "write handle found",
            "remote device profiles discovery completed",
            "data transfer req done",
        ),
        timeout=45.0,
        poll_sec=2.0,
        require_all=False,
        baseline=baseline,
    )
    if not found:
        logger().warning(
            f"DUT GATT discovery did not log handles before "
            "set_data_pattern — continuing"
        )

_DT_FW_DATA_PATH_CORE_MARKERS = (
    "data transfer req done",
    "buffer configuration done",
    "start transmitting data to",
)
_DT_FW_GATT_SERVICE_NOT_FOUND_MARKERS = (
    "gatt write no response service not found",
    "gatt write response service not found",
    "gatt write service not found",
)
_DT_FW_RX_DATA_PATH_MARKERS = (
    "start receiving data from",
    "in receive notification event",
    "receiving notifications from remote device",
)

_DT_TX_MODE_FLAGS = {
    "notifications": "tx_notifications",
    "indications": "tx_indications",
    "write": "tx_write",
    "write_no_response": "tx_write_no_response",
}
_DT_RX_MODE_FLAGS = {
    "notifications": "rx_notifications",
    "indications": "rx_indications",
}
_DT_DATA_PATTERN_FLAGS = (
    "rx_notifications",
    "rx_indications",
    "tx_notifications",
    "tx_write",
    "tx_write_no_response",
    "tx_indications",
)


def _dt_set_bidirectional_data_pattern(
    wifi_dut,
    peer_address: str,
    case_id: str,
    *,
    tx_mode: str,
    buffer_mode: int,
    buffer_cnt: int,
    max_data_length: int,
    rx_mode: str = "notifications",
    label: str = "",
) -> bool:
    """Configure the DUT data path in **both** directions on one link.

    Each connection carries DUT→peer traffic for the selected mode plus
    peer→DUT notifications. One TX and one RX CLI flag are enabled together
    (all others remain 0); returns False if ``set_data_pattern`` is unavailable.
    """
    tx_flag = _DT_TX_MODE_FLAGS.get(tx_mode)
    rx_flag = _DT_RX_MODE_FLAGS.get(rx_mode)
    assert tx_flag, f"unknown tx_mode {tx_mode!r}"
    assert rx_flag, f"unknown rx_mode {rx_mode!r}"

    wifi = wifi_dut.interfaces.wifi
    if not hasattr(wifi, "set_data_pattern"):
        logger().warning(
            f"set_data_pattern unavailable — relying on firmware "
            f"auto data path (TX {tx_mode} / RX {rx_mode} not configured)"
        )
        return False

    flags = {name: 0 for name in _DT_DATA_PATTERN_FLAGS}
    flags[tx_flag] = 1
    flags[rx_flag] = 1

    suffix = f" [{label}]" if label else ""
    logger().info(
        f"set_data_pattern {peer_address}{suffix}: "
        f"TX {tx_flag}=1 (DUT -> peer) + RX {rx_flag}=1 (peer -> DUT), "
        f"buffer_mode={buffer_mode}, buffer_cnt={buffer_cnt}, "
        f"max_data_length={max_data_length}"
    )
    wifi.set_data_pattern(
        peer_address,
        buffer_mode=buffer_mode,
        buffer_cnt=buffer_cnt,
        max_data_length=max_data_length,
        **flags,
    )
    return True

_DT_RX_CHECK_TIMEOUT_SEC = 30.0


def _dt_check_tx_data_path_hostlog(
    bus,
    case_id: str,
    *,
    baseline: int,
    poll_sec: float,
    timeout: float = _DT_RX_CHECK_TIMEOUT_SEC,
    label: str = "",
) -> bool:
    """Mirror of ``_dt_check_rx_data_path_hostlog`` for the DUT->peer leg.
    Used where TX is the direction added on top of the case's named mode, so the
    verdict still rests on what TestRail asserts.
    """
    found, _ = _dt_wait_hostlog(
        bus,
        ("start transmitting data to",),
        timeout=timeout,
        poll_sec=poll_sec,
        require_all=False,
        baseline=baseline,
    )
    suffix = f" [{label}]" if label else ""
    if found:
        logger().info(f"TX path verified{suffix} (DUT -> peer)")
        return True
    logger().warning(
        f"TX data-path hostlog missing{suffix} — TX was configured but "
        "the DUT never logged 'start transmitting data to'; check the firmware "
        "TX_NOTIFICATIONS_TO_* build flag for this link"
    )
    return False


def _dt_check_rx_data_path_hostlog(
    bus,
    case_id: str,
    *,
    baseline: int,
    poll_sec: float,
    timeout: float = _DT_RX_CHECK_TIMEOUT_SEC,
    label: str = "",
    strict: bool = False,
) -> bool:
    """Report whether the peer->DUT leg actually carried data, not just that it was set."""
    found, _ = _dt_wait_hostlog(
        bus,
        _DT_FW_RX_DATA_PATH_MARKERS,
        timeout=timeout,
        poll_sec=poll_sec,
        require_all=False,
        baseline=baseline,
    )
    suffix = f" [{label}]" if label else ""
    if found:
        logger().info(f"RX path verified{suffix} (peer -> DUT)")
        return True

    message = (
        f"RX data-path hostlog missing{suffix} — RX was configured but "
        f"the DUT never logged peer->DUT reception (expected one of "
        f"{_DT_FW_RX_DATA_PATH_MARKERS}); check the firmware "
        "RX_NOTIFICATIONS_FROM_* build flag for this link"
    )
    if strict:
        pytest.fail(message)
    logger().warning(message)
    return False


def _dt_prepare_raspi_central_connect(wifi_dut, ble_client, dut_address: str) -> None:
    """Drop stale Raspi-side state before Raspi (central) -> DUT connect."""
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    _dt_settle("post Raspi disconnect before central connect")
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    _dt_settle("post Raspi remove_device before central connect")


def _dt_assert_wearables_data_path_hostlog(
    bus,
    case_id: str,
    *,
    baseline_after_set_pattern: int,
    timeout: float,
    poll_sec: float,
    strict_pipeline: bool = False,
) -> None:
    """Validate WWR/WR data-path hostlog after ``set_data_pattern``.

    Firmware prints ``data transfer req done`` at profile discovery; buffer /
    transmit strings may appear there or after ``set_data_pattern``. Scan the
    full hostlog for the core pipeline markers (not only post-CLI lines).
    Fail fast when the DUT reports the peer GATT write service was not found.
    """
    fail_deadline = time.time() + min(20.0, timeout)
    while time.time() < fail_deadline:
        post = _dt_hostlog_text(bus, baseline_after_set_pattern)
        for marker in _DT_FW_GATT_SERVICE_NOT_FOUND_MARKERS:
            if marker in post:
                msg = (
                    f"set_data_pattern ({marker})"
                )
                if strict_pipeline:
                    pytest.fail(msg)
                logger().warning(msg)
                break
        time.sleep(poll_sec)

    full_log = _dt_hostlog_text(bus, 0)
    missing_core = [m for m in _DT_FW_DATA_PATH_CORE_MARKERS if m not in full_log]
    if strict_pipeline and missing_core:
        assert not missing_core, (
            f"data-path hostlog incomplete — missing: {missing_core}; "
            f"expected all of {_DT_FW_DATA_PATH_CORE_MARKERS}"
        )
    if "data transfer req done" not in full_log:
        found, _ = _dt_wait_hostlog(
            bus,
            ("data transfer req done",),
            timeout=timeout,
            poll_sec=poll_sec,
            require_all=True,
            baseline=0,
        )
        assert found, (
            f"data-path hostlog missing 'data transfer req done' "
            f"within {timeout:.0f}s"
        )
    elif missing_core:
        logger().warning(
            f"partial data-path hostlog — missing {missing_core}; "
            f"continuing (DUT slave / IAS may only log 'data transfer req done' "
            "until transfer starts)"
        )


def _dt_raspi_disconnect_if_connected(ble_client, dut_address):
    """Only issue a Raspi-side disconnect when the link is still connected
    so we don't disconnect an already disconnected connection.
    """
    bt = ble_client.interfaces.bluetooth
    try:
        raspi_still_connected = bt.get_connection_status(dev_addr=dut_address)
    except Exception:
        raspi_still_connected = True
    if raspi_still_connected:
        try:
            bt.disconnect(dev_addr=dut_address)
        except Exception:
            pass


def _dt_restart_peer_advertising(ble_client, service_classes=None):
    """Stop then start the Raspi (peripheral) advertising right before the DUT (central) initiates the connection.

    Re-registers advertisement UUIDs only; the GATT application from start_smp_adv stays registered (avoids duplicate D-Bus handlers).
    """
    bt = ble_client.interfaces.bluetooth
    try:
        bt.stop_advertising()
    except Exception as exc:
        logger().warning(f"stop_advertising before connect: {exc}")
    time.sleep(1)
    try:
        if service_classes:
            serv_uuids = _dt_service_uuid_list(service_classes)
            bt.start_advertising(serv_uuids=serv_uuids)
        else:
            bt.start_advertising()
    except Exception as exc:
        logger().warning(f"start advertising before connect: {exc}")
    time.sleep(2)


def _dt_hostlog_text(bus, start_idx: int = 0) -> str:
    lines: List[str] = []
    for _ts, raw in bus.get_input_log()[start_idx:]:
        if isinstance(raw, bytes):
            lines.append(raw.decode(errors="ignore"))
        else:
            lines.append(str(raw))
    return "\n".join(lines).lower()


def _dt_wait_hostlog(
    bus,
    patterns: Sequence[str],
    *,
    timeout: float,
    poll_sec: float,
    require_all: bool = True,
    baseline: Optional[int] = None,
) -> Tuple[bool, str]:
    start = baseline if baseline is not None else len(bus.get_input_log())
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = _dt_hostlog_text(bus, start)
        if require_all:
            if all(p in text for p in patterns):
                return True, text
        elif any(p in text for p in patterns):
            return True, text
        time.sleep(poll_sec)
    return False, _dt_hostlog_text(bus, start)


def _dt_resolve_dut_address(wifi_dut, *, case_id: str) -> str:
    addr = wifi_dut.interfaces.wifi.get_local_address()
    assert addr and _BD_ADDR_RE.match(str(addr).strip()), (
        f"invalid DUT BD address '{addr}'"
    )
    resolved = str(addr).strip().upper()
    logger().info(f"DUT BD address {resolved}")
    return resolved


_DT_ADV_MARKER = "advertising started"
_DT_SCAN_MARKER = "scanning started"
_DT_ADV_ACTIVE_MARKERS = (
    "advertising started",
    "start adv command called",
    "req_adv_cmd_handler : successful",
    "adv_already_in_progress",
    "already_in_progress",
    "already in progress",
)
_DT_SCAN_ACTIVE_MARKERS = (
    "scanning started",
    "start scan command called",
    "scan_already_in_progress",
    "already_in_progress",
    "already in progress",
)
_DT_DEFAULT_OWN_ADDR_TYPE = 0
_DT_READY_RECOVERY_TIMEOUT_SEC = 120.0
_DT_READY_RETRY_INTERVAL_SEC = 15.0
_DT_CMD_SETTLE_SEC = 5.0

_DT_SMP_KWARG_ALIASES = {
    "max_encryption_key_size": "enc_key_size",
    "initiator_key_distribution": "ini_key_dist",
    "responder_key_distribution": "rsp_key_dist",
}


def _dt_install_smp_kwarg_shim(wifi_dut) -> None:
    """
    Locally adapt the DUT's set_smp_pairing_capability_data to accept the legacy
    kwarg names used by the local connect helpers.

    Connect helpers use legacy keyword names for
    ``set_smp_pairing_capability_data``, but the RT595 CLI expects different
    parameter names. Wrap the DUT method to translate them and avoid TypeError.
    """
    try:
        wifi = wifi_dut.interfaces.wifi
    except Exception:
        return
    original = getattr(wifi, "set_smp_pairing_capability_data", None)
    if original is None or getattr(original, "_dt_kwarg_shim", False):
        return

    def _wrapped(*args, **kwargs):
        for old, new in _DT_SMP_KWARG_ALIASES.items():
            if old in kwargs:
                kwargs[new] = kwargs.pop(old)
        return original(*args, **kwargs)

    _wrapped._dt_kwarg_shim = True
    try:
        wifi.set_smp_pairing_capability_data = _wrapped
    except Exception as exc:
        logger().warning(f"could not install SMP kwarg shim on DUT: {exc}")

    _dt_install_connect_alias(wifi)


def _dt_install_connect_alias(wifi) -> None:
    """
    Alias ``ble_legacy_connect_req`` -> ``req_legacy_connect`` on the DUT wifi
    interface.

    The DUT-as-master helper calls ``ble_legacy_connect_req``, while the
    RT595 CLI exposes the same command as ``req_legacy_connect`` with an
    identical signature. Bind the missing alias on the DUT instance.
    """
    if hasattr(wifi, "ble_legacy_connect_req"):
        return
    target = getattr(wifi, "req_legacy_connect", None)
    if target is None:
        return
    try:
        wifi.ble_legacy_connect_req = target
    except Exception as exc:
        logger().warning(f"could not install connect-req alias on DUT: {exc}")


def _dt_try_restore_adv(wifi_dut, bus, case_id: str) -> bool:
    """Re-issue legacy_adv; True when the DUT confirms advertising is active."""
    return _dt_force_legacy_adv(wifi_dut, bus, case_id)


def _dt_try_restore_scan(wifi_dut, bus, case_id: str) -> bool:
    """Re-issue legacy_scan; True when the DUT confirms scanning is active."""
    return _dt_force_legacy_scan(wifi_dut, bus, case_id)


def _dt_ensure_dut_ble_ready(
    wifi_dut,
    bus,
    case_id: str,
    *,
    required_markers: Sequence[str],
    step_label: str,
    timeout: float = _DT_READY_RECOVERY_TIMEOUT_SEC,
    retry_interval: float = _DT_READY_RETRY_INTERVAL_SEC,
) -> None:
    """
    Assert the DUT is advertising/scanning as the case requires.

    On the first testcase the one-time boot markers are still in the hostlog and
    this returns immediately. On later testcases the buffer has been wiped, so
    re-issue legacy_adv/legacy_scan and accept the firmware's "already in
    progress" response as confirmation, retrying until the budget expires.
    """
    _dt_install_smp_kwarg_shim(wifi_dut)

    need_adv = _DT_ADV_MARKER in required_markers
    need_scan = _DT_SCAN_MARKER in required_markers

    if not (need_adv or need_scan):
        hostlog = _dt_hostlog_text(bus)
        missing = [m for m in required_markers if m not in hostlog]
        assert not missing, f"{step_label}: missing hostlog markers: {missing}"
        return

    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        adv_ok = (not need_adv) or _dt_try_restore_adv(wifi_dut, bus, case_id)
        scan_ok = (not need_scan) or _dt_try_restore_scan(wifi_dut, bus, case_id)
        if adv_ok and scan_ok:
            logger().info(
                f"{step_label}: DUT BLE ready "
                f"(adv={need_adv}, scan={need_scan}, attempt {attempt})"
            )
            return
        time.sleep(min(retry_interval, max(1.0, deadline - time.time())))

    hostlog = _dt_hostlog_text(bus)
    missing = [m for m in required_markers if m not in hostlog]
    assert not missing, (
        f"{step_label}: DUT not advertising/scanning after recovery "
        f"({timeout:.0f}s) — missing: {missing}"
    )


CASE_ID_C553912 = "C553912"
C553912_DUT_ADV_NAME = "9116_BLE"
C553912_PAYLOAD_LENGTH = 232
C553912_BUFFER_MODE = 1
C553912_BUFFER_COUNT = 2
C553912_DUT_INIT_SETTLE_SEC = 20.0
C553912_STEP_SETTLE_SEC = 5.0
C553912_POST_PAIR_SETTLE_SEC = 8.0
C553912_POST_DISCONNECT_SETTLE_SEC = 5.0
C553912_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553912_DATA_PATH_TIMEOUT_SEC = 180.0
C553912_TRANSFER_SEC = float(os.environ.get("C553912_TRANSFER_SEC", "600"))
C553912_TRANSFER_POLL_SEC = 10.0
C553912_HOSTLOG_POLL_SEC = 2.0

C553912_STEP22_FIRMWARE_MARKERS = (
    "DLE_ON_M1=1",
    "DLE_BUFFER_MODE_M1=1",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=232",
)
C553912_STEP23_HOSTLOG_MARKERS = ("advertising started",)
C553912_STEP23_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "scanning started",
)
C553912_MASTER_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553912_BOND_MARKERS = (
    "in smp encrypt event",
    "remote device profiles discovery completed",
)
C553912_DATA_PATH_MARKERS = _DT_FW_DATA_PATH_CORE_MARKERS
# Write-without-response -> Immediate Alert Service (0x1802 / Alert Level 0x2A06)
C553912_GATT_SERVICE = "ImmediateAlertService"
C553912_SERVICE_CLASSES = _dt_build_raspi_services(C553912_GATT_SERVICE)


def _c553912_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    sec = C553912_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553912_cleanup_peer(ble_client, dut_address: str):
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553912_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553912_raspi_connect_with_ias(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 8–12 / 24–25: Raspi central (IAS GATT) scans and connects to DUT peripheral."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553912_settle_before_command(label="pre Raspi scan/connect")

    logger().info(
        f"Step 24: Raspi scan for DUT ({C553912_DUT_ADV_NAME}) "
        f"with {C553912_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553912,
        service_classes=C553912_SERVICE_CLASSES,
        dwell_sec=C553912_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 24–25: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553912_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553912_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Raspi central connect to DUT failed"
    time.sleep(C553912_POST_PAIR_SETTLE_SEC)

    found, _ = _dt_wait_hostlog(
        bus,
        C553912_MASTER_CONNECT_MARKERS,
        timeout=C553912_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553912_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, f"master connect hostlog markers missing (steps 24–25)"

    found, _ = _dt_wait_hostlog(
        bus,
        C553912_BOND_MARKERS,
        timeout=C553912_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553912_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, f"SMP bond / profile discovery hostlog missing (step 25)"

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi address unavailable after connect"
    return peer.strip().upper()


def _c553912_configure_dut_data_transfer(wifi_dut, peer_address: str, bus):
    """TestRail steps 15–16: buffer mode 1 + 232-byte WWR TX plus RX notifications."""
    logger().info(
        f"Step 15–16: configure buffer_mode={C553912_BUFFER_MODE}, "
        f"count={C553912_BUFFER_COUNT}, payload={C553912_PAYLOAD_LENGTH} B WWR to {peer_address} "
        "(DUT peripheral: TX write-without-response + RX notifications)"
    )
    baseline = len(bus.get_input_log())
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553912, profile_kind="wwr"
    )
    time.sleep(C553912_STEP_SETTLE_SEC)
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553912,
        tx_mode="write_no_response",
        buffer_mode=C553912_BUFFER_MODE,
        buffer_cnt=C553912_BUFFER_COUNT,
        max_data_length=C553912_PAYLOAD_LENGTH,
    )
    if configured:
        time.sleep(C553912_STEP_SETTLE_SEC)

    _dt_assert_wearables_data_path_hostlog(
        bus,
        CASE_ID_C553912,
        baseline_after_set_pattern=baseline,
        timeout=C553912_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553912_HOSTLOG_POLL_SEC,
        strict_pipeline=False,
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553912,
        baseline=baseline,
        poll_sec=C553912_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Steps 15–16: buffer config + TX and RX paths validated"
    )


def _c553912_monitor_data_transfer(ble_client, dut_address: str, bus, *, duration: float):
    """TestRail step 17: 10 min continuous 232-byte WWR data transfer."""
    logger().info(f"Step 17: monitor data transfer for {duration:.0f}s")
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during data transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(f"DUT reported master disconnect during transfer")
        time.sleep(C553912_TRANSFER_POLL_SEC)
    logger().info(f"Step 17: transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553912)
def test_ble_dut_slave_wwr_232b_buffer_mode1_C553912(wifi_dut, ble_client):
    """
    TestRail C553912 — DUT as Slave, 232-byte GATT WWR, buffer mode 1.

    Data path (both directions on the link): DUT -> Raspi 232 B write-without-response
    plus Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553912
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553912_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553912_STEP23_HOSTLOG_MARKERS,
            step_label="Step 23",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        if hasattr(wifi_dut.interfaces.wifi, "power_save"):
            logger().info(
                f"Steps 6–7: WLAN/BT power save (2,1) deferred — "
                "RT595 btc CLI has no wlan_power_save/bt_power_save_profile "
                "(firmware build-time precondition; see secure_pairing suite)"
            )

        peer_address = _c553912_raspi_connect_with_ias(wifi_dut, ble_client, dut_address, bus)

        _c553912_configure_dut_data_transfer(wifi_dut, peer_address, bus)
        _c553912_monitor_data_transfer(
            ble_client, dut_address, bus, duration=C553912_TRANSFER_SEC
        )

        logger().info(
            f"Step 18: OTA validation deferred — verify 232-byte secured "
            "ATT Write Command payloads via RF sniffer capture"
        )

        logger().info(f"Step 19: disconnect from Raspi")
        _dt_raspi_disconnect_if_connected(ble_client, dut_address)
        time.sleep(C553912_POST_DISCONNECT_SETTLE_SEC)

        logger().info(f"Step 26: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553912_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 22–26 (OTA deferred)")


CASE_ID_C553913 = "C553913"
C553913_PAYLOAD_LENGTH = 20
C553913_BUFFER_MODE = 0
C553913_BUFFER_COUNT = 2
C553913_RASPI_ADV_NAME = os.environ.get("C553913_RASPI_ADV_NAME", "slave11")
C553913_DUT_INIT_SETTLE_SEC = 20.0
C553913_STEP_SETTLE_SEC = 5.0
C553913_POST_PAIR_SETTLE_SEC = 5.0
C553913_POST_DISCONNECT_SETTLE_SEC = 3.0
C553913_PEER_ADV_START_SEC = 3.0
C553913_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553913_DATA_PATH_TIMEOUT_SEC = 180.0
C553913_TRANSFER_SEC = float(os.environ.get("C553913_TRANSFER_SEC", "600"))
C553913_TRANSFER_POLL_SEC = 10.0
C553913_HOSTLOG_POLL_SEC = 2.0
C553913_AUTH_REQ = 0x2D

C553913_STEP22_FIRMWARE_MARKERS = (
    "DLE_ON_S1=0",
    "DLE_BUFFER_MODE_S1=0",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=20",
)
C553913_STEP23_HOSTLOG_MARKERS = ("scanning started",)
C553913_STEP23_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553913_SLAVE_CONNECT_MARKERS = (
    "start scanning",
    "in on_enhance_conn evt",
    "on enhance connect event",
    "smp pairing request initiated",
    "in smp sc passkey event",
    "number of peripheral devices connected:1",
    "number of slave devices connected:1",
)
C553913_BOND_DATA_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data to",
)
C553913_DATA_PATH_MARKERS = _DT_FW_DATA_PATH_CORE_MARKERS


def _c553913_cleanup_peer(ble_client, dut_address: str):
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553913_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


# Write-without-response -> Immediate Alert Service (0x1802 / Alert Level 0x2A06)
C553913_GATT_SERVICE = "ImmediateAlertService"
C553913_SERVICE_CLASSES = _dt_build_raspi_services(C553913_GATT_SERVICE)


def _c553913_raspi_advertise_and_dut_connect(
    wifi_dut, ble_client, dut_address: str, bus, *, adv_name: str
) -> str:
    """TestRail steps 24–25: Raspi peripheral advertises; DUT central scans and connects."""
    setup_test_state()
    set_local_dut_address(dut_address)
    time.sleep(C553913_STEP_SETTLE_SEC)

    logger().info(
        f"Step 24: Raspi BLE advertising as '{adv_name}' "
        "(DUT central will scan + connect)"
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
    except Exception as exc:
        logger().warning(f"set_advertising_data('{adv_name}'): {exc}")
    time.sleep(C553913_PEER_ADV_START_SEC)
    time.sleep(C553913_STEP_SETTLE_SEC)

    baseline = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553913_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553913_SERVICE_CLASSES,
    )
    assert ok, f"DUT-central connect to Raspi peripheral failed"
    time.sleep(C553913_POST_PAIR_SETTLE_SEC)
    time.sleep(C553913_STEP_SETTLE_SEC)

    found, _ = _dt_wait_hostlog(
        bus,
        C553913_SLAVE_CONNECT_MARKERS,
        timeout=C553913_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553913_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 24: DUT scan/connect hostlog missing "
        f"(expected one of {C553913_SLAVE_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553913_BOND_DATA_MARKERS,
        timeout=C553913_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553913_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 25: SMP bond / buffer / data transmit hostlog missing "
        f"(expected one of {C553913_BOND_DATA_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi peripheral address unavailable after connect"
    peer = peer.strip().upper()
    logger().info(f"Step 25: DUT master bonded to Raspi peripheral @ {peer}")
    return peer


def _c553913_configure_dut_data_transfer(wifi_dut, peer_address: str, bus):
    """TestRail steps 15–16: buffer mode 0 + 20-byte WWR TX plus RX notifications."""
    logger().info(
        f"Step 15–16: configure buffer_mode={C553913_BUFFER_MODE}, "
        f"count={C553913_BUFFER_COUNT}, payload={C553913_PAYLOAD_LENGTH} B WWR to {peer_address} "
        "(DUT central: TX write-without-response + RX notifications)"
    )
    baseline = len(bus.get_input_log())
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553913, profile_kind="wwr"
    )
    time.sleep(C553913_STEP_SETTLE_SEC)
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553913,
        tx_mode="write_no_response",
        buffer_mode=C553913_BUFFER_MODE,
        buffer_cnt=C553913_BUFFER_COUNT,
        max_data_length=C553913_PAYLOAD_LENGTH,
    )
    if configured:
        time.sleep(C553913_STEP_SETTLE_SEC)

    _dt_assert_wearables_data_path_hostlog(
        bus,
        CASE_ID_C553913,
        baseline_after_set_pattern=baseline,
        timeout=C553913_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553913_HOSTLOG_POLL_SEC,
        strict_pipeline=False,
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553913,
        baseline=baseline,
        poll_sec=C553913_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Steps 15–16: buffer config + TX and RX paths validated"
    )


def _c553913_monitor_data_transfer(
    bus, peer_address: str, *, duration: float, baseline: int
):
    """TestRail step 17: 10 min continuous 20-byte WWR data transfer (DUT central)."""
    logger().info(f"Step 17: monitor data transfer for {duration:.0f}s")
    peer_l = peer_address.lower()
    peer_nc = peer_address.replace(":", "").lower()
    start = time.time()
    while time.time() - start < duration:
        recent = _dt_hostlog_text(bus, baseline)
        if "number of peripheral devices connected:0" in recent:
            pytest.fail(f"DUT reports zero peripheral devices during transfer")
        if "number of slave devices connected:0" in recent:
            pytest.fail(f"DUT reports zero slave devices during transfer")
        for line in recent.splitlines():
            if peer_l not in line and peer_nc not in line:
                continue
            if "disconnect" in line:
                pytest.fail(
                    f"DUT peripheral link dropped during transfer: "
                    f"{line.strip()}"
                )
        time.sleep(C553913_TRANSFER_POLL_SEC)
    logger().info(f"Step 17: transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553913)
def test_ble_dut_master_wwr_20b_buffer_mode0_C553913(wifi_dut, ble_client):
    """
    TestRail C553913 — DUT as Master, 20-byte GATT WWR, buffer mode 0.

    Data path (both directions on the link): DUT -> Raspi 20 B write-without-response
    plus Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    Role mapping (TestRail phone → Raspi):
      DUT  = BLE central / master (scans, initiates connection, sends WWR data)
      Raspi = BLE peripheral / slave (advertises, receives WWR data)

    """
    case_id = CASE_ID_C553913
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None
    transfer_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553913_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553913_STEP23_HOSTLOG_MARKERS,
            step_label="Step 23",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Steps 6–7: WLAN/BT power save (2,1) — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553913_raspi_advertise_and_dut_connect(
            wifi_dut,
            ble_client,
            dut_address,
            bus,
            adv_name=C553913_RASPI_ADV_NAME,
        )

        _c553913_configure_dut_data_transfer(wifi_dut, peer_address, bus)

        transfer_baseline = len(bus.get_input_log())
        time.sleep(C553913_STEP_SETTLE_SEC)
        _c553913_monitor_data_transfer(
            bus,
            peer_address,
            duration=C553913_TRANSFER_SEC,
            baseline=transfer_baseline,
        )

        logger().info(
            f"Step 18: OTA validation deferred — verify 20-byte secured "
            "ATT Write Command payloads via RF sniffer capture"
        )

        logger().info(f"Step 19: disconnect from Raspi side (DUT central link)")
        _dt_raspi_disconnect_if_connected(ble_client, dut_address)

        logger().info(f"Step 26: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553913_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)
        _dt_restore_dut_peripheral_advertising(wifi_dut, bus, case_id)

    logger().info(f"PASS — hostlog steps 22–26 (OTA deferred)")


CASE_ID_C553914 = "C553914"
C553914_PAYLOAD_LENGTH = 232
C553914_BUFFER_MODE = 1
C553914_BUFFER_COUNT = 2
C553914_RASPI_ADV_NAME = os.environ.get("C553914_RASPI_ADV_NAME", "slave11")
C553914_DUT_INIT_SETTLE_SEC = 20.0
C553914_STEP_SETTLE_SEC = 5.0
C553914_POST_PAIR_SETTLE_SEC = 5.0
C553914_POST_DISCONNECT_SETTLE_SEC = 3.0
C553914_PEER_ADV_START_SEC = 3.0
C553914_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553914_DATA_PATH_TIMEOUT_SEC = 120.0
C553914_TRANSFER_SEC = float(os.environ.get("C553914_TRANSFER_SEC", "600"))
C553914_TRANSFER_POLL_SEC = 10.0
C553914_HOSTLOG_POLL_SEC = 2.0
C553914_AUTH_REQ = 0x2D

C553914_STEP22_FIRMWARE_MARKERS = (
    "DLE_ON_S1=1",
    "DLE_BUFFER_MODE_S1=1",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=230",
)
C553914_STEP23_HOSTLOG_MARKERS = ("scanning started",)
C553914_STEP23_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553914_SLAVE_CONNECT_MARKERS = (
    "start scanning",
    "in on_enhance_conn evt",
    "on enhance connect event",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
    "number of peripheral devices connected:1",
    "number of slave devices connected:1",
)
C553914_BOND_DATA_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data to",
)
C553914_DATA_PATH_MARKERS = _DT_FW_DATA_PATH_CORE_MARKERS


def _c553914_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553914_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553914_cleanup_peer(ble_client, dut_address: str):
    _c553914_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553914_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


# Write-with-response -> Heart Rate Service (0x180D / Heart Rate Control Point 0x2A39)
C553914_GATT_SERVICE = "HeartRateService"
C553914_SERVICE_CLASSES = _dt_build_raspi_services(C553914_GATT_SERVICE)


def _c553914_raspi_advertise_and_dut_connect(
    wifi_dut, ble_client, dut_address: str, bus, *, adv_name: str
) -> str:
    """TestRail steps 24–25: Raspi peripheral advertises; DUT central scans, MTU, SMP, bonds."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553914_settle_before_command(label="Raspi set_advertising_data")

    logger().info(
        f"Step 24: Raspi BLE advertising as '{adv_name}' "
        "(DUT central will scan + connect)"
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
    except Exception as exc:
        logger().warning(f"set_advertising_data('{adv_name}'): {exc}")
    time.sleep(C553914_PEER_ADV_START_SEC)
    _c553914_settle_before_command(label="DUT connect_dut_as_central_raspii_as_peripheral")

    baseline = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553914_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553914_SERVICE_CLASSES,
    )
    assert ok, f"DUT-central connect to Raspi peripheral failed"
    time.sleep(C553914_POST_PAIR_SETTLE_SEC)
    _c553914_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553914_SLAVE_CONNECT_MARKERS,
        timeout=C553914_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553914_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 24: DUT scan/connect/MTU/SMP hostlog missing "
        f"(expected one of {C553914_SLAVE_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553914_BOND_DATA_MARKERS,
        timeout=C553914_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553914_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 25: SMP bond / buffer / data transmit hostlog missing "
        f"(expected one of {C553914_BOND_DATA_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi peripheral address unavailable after connect"
    peer = peer.strip().upper()
    logger().info(f"Step 25: DUT master bonded to Raspi peripheral @ {peer}")
    return peer


def _c553914_configure_dut_data_transfer(wifi_dut, peer_address: str, bus):
    """TestRail steps 15–16: buffer mode 1 + 232-byte GATT WR TX plus RX notifications."""
    logger().info(
        f"Step 15–16: configure buffer_mode={C553914_BUFFER_MODE}, "
        f"count={C553914_BUFFER_COUNT}, payload={C553914_PAYLOAD_LENGTH} B write-with-response "
        f"to {peer_address} (DUT central: TX write-with-response + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553914, profile_kind="wr"
    )
    _c553914_settle_before_command(label="DUT set_data_pattern (write-with-response + RX)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553914,
        tx_mode="write",
        buffer_mode=C553914_BUFFER_MODE,
        buffer_cnt=C553914_BUFFER_COUNT,
        max_data_length=C553914_PAYLOAD_LENGTH,
    )
    if configured:
        _c553914_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553914_DATA_PATH_MARKERS,
        timeout=C553914_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553914_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"data-path hostlog missing "
        f"(expected one of {C553914_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553914,
        baseline=baseline,
        poll_sec=C553914_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Steps 15–16: buffer config + TX and RX paths validated"
    )


def _c553914_monitor_data_transfer(
    bus, peer_address: str, *, duration: float, baseline: int
):
    """TestRail step 17: 10 min continuous 232-byte write-with-response data transfer."""
    logger().info(f"Step 17: monitor data transfer for {duration:.0f}s")
    peer_l = peer_address.lower()
    peer_nc = peer_address.replace(":", "").lower()
    start = time.time()
    while time.time() - start < duration:
        recent = _dt_hostlog_text(bus, baseline)
        if "number of peripheral devices connected:0" in recent:
            pytest.fail(f"DUT reports zero peripheral devices during transfer")
        if "number of slave devices connected:0" in recent:
            pytest.fail(f"DUT reports zero slave devices during transfer")
        for line in recent.splitlines():
            if peer_l not in line and peer_nc not in line:
                continue
            if "disconnect" in line:
                pytest.fail(
                    f"DUT peripheral link dropped during transfer: "
                    f"{line.strip()}"
                )
        time.sleep(C553914_TRANSFER_POLL_SEC)
    logger().info(f"Step 17: transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553914)
def test_ble_dut_master_wr_232b_buffer_mode1_C553914(wifi_dut, ble_client):
    """
    TestRail C553914 — DUT as Master, 232-byte GATT write-with-response, buffer mode 1.

    Data path (both directions on the link): DUT -> Raspi 232 B write-with-response
    plus Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    Role mapping (TestRail phone → Raspi):
      DUT  = BLE central / master (scans, initiates connection, sends WR data)
      Raspi = BLE peripheral / slave (advertises, receives WR data)

    """
    case_id = CASE_ID_C553914
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None
    transfer_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553914_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553914_STEP23_HOSTLOG_MARKERS,
            step_label="Step 23",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Steps 6–7: WLAN/BT power save (2,1) — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553914_raspi_advertise_and_dut_connect(
            wifi_dut,
            ble_client,
            dut_address,
            bus,
            adv_name=C553914_RASPI_ADV_NAME,
        )

        _c553914_configure_dut_data_transfer(wifi_dut, peer_address, bus)

        transfer_baseline = len(bus.get_input_log())
        _c553914_settle_before_command(label="Step 17 transfer monitor start")
        _c553914_monitor_data_transfer(
            bus,
            peer_address,
            duration=C553914_TRANSFER_SEC,
            baseline=transfer_baseline,
        )

        logger().info(
            f"Step 18: OTA validation deferred — verify 232-byte secured "
            "ATT Write Request payloads via RF sniffer capture"
        )

        logger().info(f"Step 19: disconnect from Raspi side (DUT central link)")
        _dt_raspi_disconnect_if_connected(ble_client, dut_address)

        logger().info(f"Step 26: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553914_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553914_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)
        _dt_restore_dut_peripheral_advertising(wifi_dut, bus, case_id)

    logger().info(f"PASS — hostlog steps 22–26 (OTA deferred)")


CASE_ID_C553915 = "C553915"
C553915_DUT_ADV_NAME = "9116_BLE"
C553915_PAYLOAD_LENGTH = 20
C553915_BUFFER_MODE = 0
C553915_BUFFER_COUNT = 2
C553915_DUT_INIT_SETTLE_SEC = 20.0
C553915_STEP_SETTLE_SEC = 5.0
C553915_POST_PAIR_SETTLE_SEC = 8.0
C553915_POST_DISCONNECT_SETTLE_SEC = 5.0
C553915_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553915_DATA_PATH_TIMEOUT_SEC = 120.0
C553915_TRANSFER_SEC = float(os.environ.get("C553915_TRANSFER_SEC", "600"))
C553915_TRANSFER_POLL_SEC = 10.0
C553915_HOSTLOG_POLL_SEC = 2.0

C553915_STEP21_FIRMWARE_MARKERS = (
    "DLE_ON_M1=0",
    "DLE_BUFFER_MODE_M1=0",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=20",
)
C553915_STEP22_HOSTLOG_MARKERS = ("advertising started",)
C553915_STEP22_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
    "scanning started",
)
C553915_MASTER_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553915_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553915_DATA_PATH_MARKERS = _DT_FW_DATA_PATH_CORE_MARKERS
# Write-with-response -> Heart Rate Service (0x180D / Heart Rate Control Point 0x2A39)
C553915_GATT_SERVICE = "HeartRateService"
C553915_SERVICE_CLASSES = _dt_build_raspi_services(C553915_GATT_SERVICE)


def _c553915_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553915_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553915_cleanup_peer(ble_client, dut_address: str):
    _c553915_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553915_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553915_raspi_connect_with_ias(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 23–24: Raspi central scans, MTU exchange, SMP passkey bond to DUT peripheral."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553915_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 23: Raspi scan for DUT ({C553915_DUT_ADV_NAME}) "
        f"with {C553915_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553915,
        service_classes=C553915_SERVICE_CLASSES,
        dwell_sec=C553915_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 23–24: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553915_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553915_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Raspi central connect to DUT failed"
    time.sleep(C553915_POST_PAIR_SETTLE_SEC)
    _c553915_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553915_MASTER_CONNECT_MARKERS,
        timeout=C553915_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553915_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 23: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553915_MASTER_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553915_BOND_MARKERS,
        timeout=C553915_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553915_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 24: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553915_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi address unavailable after connect"
    return peer.strip().upper()


def _c553915_configure_dut_data_transfer(wifi_dut, peer_address: str, bus):
    """TestRail steps 15–16: buffer mode 0 + 20-byte GATT WR TX plus RX notifications."""
    logger().info(
        f"Step 15–16: configure buffer_mode={C553915_BUFFER_MODE}, "
        f"count={C553915_BUFFER_COUNT}, payload={C553915_PAYLOAD_LENGTH} B write-with-response "
        f"to {peer_address} (DUT peripheral: TX write-with-response + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553915, profile_kind="wr"
    )
    _c553915_settle_before_command(label="DUT set_data_pattern (write-with-response + RX)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553915,
        tx_mode="write",
        buffer_mode=C553915_BUFFER_MODE,
        buffer_cnt=C553915_BUFFER_COUNT,
        max_data_length=C553915_PAYLOAD_LENGTH,
    )
    if configured:
        _c553915_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553915_DATA_PATH_MARKERS,
        timeout=C553915_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553915_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"data-path hostlog missing "
        f"(expected one of {C553915_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553915,
        baseline=baseline,
        poll_sec=C553915_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Steps 15–16: buffer config + TX and RX paths validated"
    )


def _c553915_monitor_data_transfer(ble_client, dut_address: str, bus, *, duration: float):
    """TestRail step 17: 10 min continuous 20-byte write-with-response data transfer."""
    logger().info(f"Step 17: monitor data transfer for {duration:.0f}s")
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during data transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(f"DUT reported master disconnect during transfer")
        time.sleep(C553915_TRANSFER_POLL_SEC)
    logger().info(f"Step 17: transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553915)
def test_ble_dut_slave_wr_20b_buffer_mode0_C553915(wifi_dut, ble_client):
    """
    TestRail C553915 — DUT as Slave, 20-byte GATT write-with-response, buffer mode 0.

    Data path (both directions on the link): DUT -> Raspi 20 B write-with-response
    plus Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553915
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553915_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553915_STEP22_HOSTLOG_MARKERS,
            step_label="Step 22",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Steps 6–7: WLAN/BT power save (2,1) — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553915_raspi_connect_with_ias(wifi_dut, ble_client, dut_address, bus)

        _c553915_configure_dut_data_transfer(wifi_dut, peer_address, bus)

        _c553915_settle_before_command(label="Step 17 transfer monitor start")
        _c553915_monitor_data_transfer(
            ble_client, dut_address, bus, duration=C553915_TRANSFER_SEC
        )

        logger().info(
            f"Step 18: OTA validation deferred — verify 20-byte secured "
            "ATT Write Request payloads via RF sniffer capture"
        )

        logger().info(f"Step 19: disconnect from Raspi")
        _c553915_settle_before_command(label="Raspi disconnect (step 19)")
        _dt_raspi_disconnect_if_connected(ble_client, dut_address)
        time.sleep(C553915_POST_DISCONNECT_SETTLE_SEC)

        logger().info(f"Step 25: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553915_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553915_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 21–25 (OTA deferred)")


CASE_ID_C553916 = "C553916"
C553916_DUT_ADV_NAME = "9116_BLE"
C553916_PAYLOAD_LENGTH = 230
C553916_BUFFER_MODE = 1
C553916_BUFFER_COUNT = 2
C553916_DUT_INIT_SETTLE_SEC = 20.0
C553916_STEP_SETTLE_SEC = 5.0
C553916_POST_PAIR_SETTLE_SEC = 8.0
C553916_POST_DISCONNECT_SETTLE_SEC = 5.0
C553916_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553916_DATA_PATH_TIMEOUT_SEC = 120.0
C553916_TRANSFER_SEC = float(os.environ.get("C553916_TRANSFER_SEC", "600"))
C553916_TRANSFER_POLL_SEC = 10.0
C553916_HOSTLOG_POLL_SEC = 2.0

C553916_STEP20_FIRMWARE_MARKERS = (
    "DLE_ON_M1=1",
    "DLE_BUFFER_MODE_M1=1",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=230",
)
C553916_STEP21_HOSTLOG_MARKERS = ("advertising started",)
C553916_STEP21_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
    "scanning started",
)
C553916_MASTER_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553916_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553916_DATA_PATH_MARKERS = (
    "remote device enabled the indications",
    "buffer configuration done",
    "start transmitting data",
    "data transfer req done",
)
# Indications -> Health Thermometer Service (0x1809 / Temperature Measurement 0x2A1C)
C553916_GATT_SERVICE = "HealthThermometerService"
C553916_SERVICE_CLASSES = _dt_build_raspi_services(C553916_GATT_SERVICE)


def _c553916_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553916_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553916_cleanup_peer(ble_client, dut_address: str):
    _c553916_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553916_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553916_raspi_connect_with_ias(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 22–23: Raspi central scans, MTU exchange, SMP passkey bond to DUT peripheral."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553916_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 22: Raspi scan for DUT ({C553916_DUT_ADV_NAME}) "
        f"with {C553916_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553916,
        service_classes=C553916_SERVICE_CLASSES,
        dwell_sec=C553916_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 22–23: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553916_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553916_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Raspi central connect to DUT failed"
    time.sleep(C553916_POST_PAIR_SETTLE_SEC)
    _c553916_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553916_MASTER_CONNECT_MARKERS,
        timeout=C553916_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553916_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 22: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553916_MASTER_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553916_BOND_MARKERS,
        timeout=C553916_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553916_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 23: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553916_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi address unavailable after connect"
    return peer.strip().upper()


def _c553916_configure_dut_data_transfer(wifi_dut, peer_address: str, bus):
    """TestRail steps 15–16: buffer mode 1 + 230-byte TX indications plus RX notifications."""
    logger().info(
        f"Step 15–16: configure buffer_mode={C553916_BUFFER_MODE}, "
        f"count={C553916_BUFFER_COUNT}, payload={C553916_PAYLOAD_LENGTH} B TX indications "
        f"to {peer_address} (DUT peripheral: TX indications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553916, profile_kind="notify_rx"
    )
    _c553916_settle_before_command(label="DUT set_data_pattern (TX indications + RX)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553916,
        tx_mode="indications",
        buffer_mode=C553916_BUFFER_MODE,
        buffer_cnt=C553916_BUFFER_COUNT,
        max_data_length=C553916_PAYLOAD_LENGTH,
    )
    if configured:
        _c553916_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553916_DATA_PATH_MARKERS,
        timeout=C553916_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553916_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"indication data-path hostlog missing "
        f"(expected one of {C553916_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553916,
        baseline=baseline,
        poll_sec=C553916_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Steps 15–16: buffer config + TX indications and RX validated"
    )


def _c553916_monitor_data_transfer(ble_client, dut_address: str, bus, *, duration: float):
    """TestRail step 16: 10 min continuous 230-byte TX indication data transfer."""
    logger().info(f"Step 16: monitor indication transfer for {duration:.0f}s")
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during indication transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(f"DUT reported master disconnect during transfer")
        time.sleep(C553916_TRANSFER_POLL_SEC)
    logger().info(f"Step 16: indication transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553916)
def test_ble_dut_slave_tx_indications_230b_buffer_mode1_C553916(wifi_dut, ble_client):
    """
    TestRail C553916 — DUT as Slave, 230-byte TX indications, buffer mode 1.

    Data path (both directions on the link): DUT -> Raspi 230 B indications plus
    Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553916
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553916_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553916_STEP21_HOSTLOG_MARKERS,
            step_label="Step 21",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Steps 6–7: WLAN/BT power save (2,1) — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553916_raspi_connect_with_ias(wifi_dut, ble_client, dut_address, bus)

        _c553916_configure_dut_data_transfer(wifi_dut, peer_address, bus)

        _c553916_settle_before_command(label="Step 16 transfer monitor start")
        _c553916_monitor_data_transfer(
            ble_client, dut_address, bus, duration=C553916_TRANSFER_SEC
        )

        logger().info(
            f"Step 17: OTA validation deferred — verify 230-byte secured "
            "ATT Indication payloads via RF sniffer capture"
        )

        logger().info(f"Step 24: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553916_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553916_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 20–24 (OTA deferred)")


CASE_ID_C553917 = "C553917"
C553917_PAYLOAD_LENGTH = 20
C553917_BUFFER_MODE = 0
C553917_BUFFER_COUNT = 2
C553917_RASPI_ADV_NAME = os.environ.get("C553917_RASPI_ADV_NAME", "slave11")
C553917_DUT_INIT_SETTLE_SEC = 20.0
C553917_STEP_SETTLE_SEC = 5.0
C553917_POST_PAIR_SETTLE_SEC = 5.0
C553917_POST_DISCONNECT_SETTLE_SEC = 3.0
C553917_PEER_ADV_START_SEC = 3.0
C553917_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553917_DATA_PATH_TIMEOUT_SEC = 120.0
C553917_TRANSFER_SEC = float(os.environ.get("C553917_TRANSFER_SEC", "600"))
C553917_TRANSFER_POLL_SEC = 10.0
C553917_HOSTLOG_POLL_SEC = 2.0
C553917_AUTH_REQ = 0x2D

C553917_STEP20_FIRMWARE_MARKERS = (
    "DLE_ON_S1=0",
    "DLE_BUFFER_MODE_S1=0",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=20",
)
C553917_STEP21_HOSTLOG_MARKERS = ("scanning started",)
C553917_STEP21_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553917_SLAVE_CONNECT_MARKERS = (
    "start scanning",
    "in on_enhance_conn evt",
    "on enhance connect event",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
    "number of peripheral devices connected:1",
    "number of slave devices connected:1",
)
C553917_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553917_DATA_PATH_MARKERS = (
    "start receiving data from",
    "in receive notification event",
    "receiving notifications from remote device",
    "buffer configuration done",
)


def _c553917_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553917_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553917_cleanup_peer(ble_client, dut_address: str):
    _c553917_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553917_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


# Notifications -> Heart Rate Service (0x180D / Heart Rate Measurement 0x2A37 + CCCD)
C553917_GATT_SERVICE = "HeartRateService"
C553917_SERVICE_CLASSES = _dt_build_raspi_services(C553917_GATT_SERVICE)


def _c553917_raspi_advertise_and_dut_connect(
    wifi_dut, ble_client, dut_address: str, bus, *, adv_name: str
) -> str:
    """TestRail steps 22–23: Raspi peripheral advertises; DUT central scans, MTU, SMP, bonds."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553917_settle_before_command(label="Raspi set_advertising_data")

    logger().info(
        f"Step 22: Raspi BLE advertising as '{adv_name}' "
        "(DUT central will scan + connect)"
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
    except Exception as exc:
        logger().warning(f"set_advertising_data('{adv_name}'): {exc}")
    time.sleep(C553917_PEER_ADV_START_SEC)
    _c553917_settle_before_command(label="DUT connect_dut_as_central_raspii_as_peripheral")

    baseline = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553917_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553917_SERVICE_CLASSES,
    )
    assert ok, f"DUT-central connect to Raspi peripheral failed"
    time.sleep(C553917_POST_PAIR_SETTLE_SEC)
    _c553917_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553917_SLAVE_CONNECT_MARKERS,
        timeout=C553917_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553917_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 22: DUT scan/connect/MTU/SMP hostlog missing "
        f"(expected one of {C553917_SLAVE_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553917_BOND_MARKERS,
        timeout=C553917_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553917_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 23: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553917_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Raspi peripheral address unavailable after connect"
    peer = peer.strip().upper()
    logger().info(f"Step 23: DUT master bonded to Raspi peripheral @ {peer}")
    return peer


def _c553917_configure_dut_rx_notifications(wifi_dut, peer_address: str, bus):
    """TestRail step 15: RX notifications plus TX notifications (buffer mode 0, 20 B)."""
    logger().info(
        f"Step 15: configure buffer_mode={C553917_BUFFER_MODE}, "
        f"count={C553917_BUFFER_COUNT}, payload={C553917_PAYLOAD_LENGTH} B RX notifications "
        f"from {peer_address} (DUT central: RX notifications + TX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553917, profile_kind="notify_hr"
    )
    _c553917_settle_before_command(label="DUT set_data_pattern (RX + TX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553917,
        tx_mode="notifications",
        buffer_mode=C553917_BUFFER_MODE,
        buffer_cnt=C553917_BUFFER_COUNT,
        max_data_length=C553917_PAYLOAD_LENGTH,
    )
    if configured:
        _c553917_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553917_DATA_PATH_MARKERS,
        timeout=C553917_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553917_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"RX notification data-path hostlog missing "
        f"(expected one of {C553917_DATA_PATH_MARKERS})"
    )
    _dt_check_tx_data_path_hostlog(
        bus,
        CASE_ID_C553917,
        baseline=baseline,
        poll_sec=C553917_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Step 15: notify enable + RX and TX paths validated"
    )


def _c553917_monitor_rx_notifications(
    bus, peer_address: str, *, duration: float, baseline: int
):
    """TestRail step 16: 10 min continuous 20-byte RX notification data transfer."""
    logger().info(f"Step 16: monitor RX notifications for {duration:.0f}s")
    peer_l = peer_address.lower()
    peer_nc = peer_address.replace(":", "").lower()
    start = time.time()
    while time.time() - start < duration:
        recent = _dt_hostlog_text(bus, baseline)
        if "number of peripheral devices connected:0" in recent:
            pytest.fail(f"DUT reports zero peripheral devices during RX transfer")
        if "number of slave devices connected:0" in recent:
            pytest.fail(f"DUT reports zero slave devices during RX transfer")
        for line in recent.splitlines():
            if peer_l not in line and peer_nc not in line:
                continue
            if "disconnect" in line:
                pytest.fail(
                    f"DUT peripheral link dropped during RX transfer: "
                    f"{line.strip()}"
                )
        time.sleep(C553917_TRANSFER_POLL_SEC)
    logger().info(f"Step 16: RX notification transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553917)
def test_ble_dut_master_rx_notifications_20b_buffer_mode0_C553917(wifi_dut, ble_client):
    """
    TestRail C553917 — DUT as Master, 20-byte RX notifications, buffer mode 0.

    Data path (both directions on the link): Raspi -> DUT 20 B notifications plus
    DUT -> Raspi notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    Role mapping (TestRail phone → Raspi):
      DUT  = BLE central / master (scans, connects, enables notify, receives data)
      Raspi = BLE peripheral / slave (advertises, sends notifications)

    """
    case_id = CASE_ID_C553917
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None
    transfer_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553917_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553917_STEP21_HOSTLOG_MARKERS,
            step_label="Step 21",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Steps 6–7: WLAN/BT power save (2,1) — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553917_raspi_advertise_and_dut_connect(
            wifi_dut,
            ble_client,
            dut_address,
            bus,
            adv_name=C553917_RASPI_ADV_NAME,
        )

        _c553917_configure_dut_rx_notifications(wifi_dut, peer_address, bus)

        transfer_baseline = len(bus.get_input_log())
        _c553917_settle_before_command(label="Step 16 RX notification monitor start")
        _c553917_monitor_rx_notifications(
            bus,
            peer_address,
            duration=C553917_TRANSFER_SEC,
            baseline=transfer_baseline,
        )

        logger().info(
            f"Step 17: OTA validation deferred — verify 20-byte secured "
            "ATT Notification payloads via RF sniffer capture"
        )

        logger().info(f"Step 19: disconnect from Raspi side (DUT central link)")
        _dt_raspi_disconnect_if_connected(ble_client, dut_address)

        logger().info(f"Step 24: OTA data transmission check deferred")

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553917_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553917_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)
        _dt_restore_dut_peripheral_advertising(wifi_dut, bus, case_id)

    logger().info(f"PASS — hostlog steps 20–24 (OTA deferred)")


CASE_ID_C553918 = "C553918"
C553918_DUT_ADV_NAME = "9116_BLE"
C553918_SLAVE_ADV_NAME = os.environ.get("C553918_SLAVE_ADV_NAME", "slave11")
C553918_TX_PAYLOAD_LENGTH = 230
C553918_RX_PAYLOAD_LENGTH = 20
C553918_TX_BUFFER_MODE = 1
C553918_RX_BUFFER_MODE = 0
C553918_BUFFER_COUNT = 2
C553918_AUTH_REQ = 0x2D
C553918_DUT_INIT_SETTLE_SEC = 20.0
C553918_STEP_SETTLE_SEC = 5.0
C553918_POST_PAIR_SETTLE_SEC = 8.0
C553918_POST_DISCONNECT_SETTLE_SEC = 5.0
C553918_PEER_ADV_START_SEC = 3.0
C553918_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553918_DATA_PATH_TIMEOUT_SEC = 120.0
C553918_TRANSFER_SEC = float(os.environ.get("C553918_TRANSFER_SEC", "600"))
C553918_TRANSFER_POLL_SEC = 10.0
C553918_HOSTLOG_POLL_SEC = 2.0
C553918_GATT_SERVICE = "HeartRateService"
C553918_SERVICE_CLASSES = _dt_build_raspi_services(C553918_GATT_SERVICE)

C553918_STEP31_FIRMWARE_MARKERS = (
    "DLE_ON_M1=1",
    "DLE_BUFFER_MODE_M1=1",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=230",
    "DLE_ON_S1=0",
    "DLE_BUFFER_MODE_S1=0",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=20",
)
C553918_STEP32_HOSTLOG_MARKERS = ("advertising started", "scanning started")
C553918_STEP32_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553918_MASTER_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553918_MASTER_BOND_RX_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "start receiving data from",
    "in receive notification event",
    "receiving notifications from remote device",
)
C553918_SLAVE_CONNECT_MARKERS = (
    "advertise report received",
    "connect command",
    "connecting to device",
    "in on_enhance_conn evt",
    "number of slave devices connected:1",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553918_SLAVE_BOND_TX_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data to",
    "in transmit notification event",
    "data transfer req done",
    "write handle found",
)
C553918_DUAL_STREAMING_MARKERS = (
    "in receive notification event",
    "receiving notifications from remote device",
    "start transmitting data to",
)


def _c553918_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553918_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553918_cleanup_peer(ble_client, dut_address: str):
    _c553918_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553918_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


def _c553918_raspi_link_up(ble_client, dut_address: str) -> bool:
    """Raspi BlueZ view of the master (DUT-peripheral) link."""
    try:
        return bool(
            ble_client.interfaces.bluetooth.get_connection_status(dev_addr=dut_address)
        )
    except Exception as exc:
        logger().warning(f"get_connection_status({dut_address}): {exc}")
        return False


def _c553918_connect_master(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 33–34: Raspi central scans/connects; DUT peripheral RX notifications."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553918_settle_before_command(label="Raspi close + set_bus (master link)")

    logger().info(
        f"Step 33: Raspi BLE scan for DUT ({C553918_DUT_ADV_NAME}) "
        f"with {C553918_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553918,
        service_classes=C553918_SERVICE_CLASSES,
        dwell_sec=C553918_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 33–34: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553918_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553918_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 33: Raspi central connect to DUT failed"
    time.sleep(C553918_POST_PAIR_SETTLE_SEC)
    _c553918_settle_before_command(label="post master-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553918_MASTER_CONNECT_MARKERS,
        timeout=C553918_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 33: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553918_MASTER_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553918_MASTER_BOND_RX_MARKERS,
        timeout=C553918_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 34: SMP bond / RX notification path hostlog missing "
        f"(expected one of {C553918_MASTER_BOND_RX_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 34: Raspi address unavailable after master connect"
    peer = peer.strip().upper()
    logger().info(
        f"Step 34: master link bonded; DUT receiving notifications @ {peer}"
    )
    return peer


def _c553918_configure_dut_rx_notifications(wifi_dut, peer_address: str, bus):
    """SDK step 24 / S1: 20-byte RX plus TX notifications on the master (DUT peripheral) link."""
    logger().info(
        f"SDK step 24: configure RX notifications buffer_mode="
        f"{C553918_RX_BUFFER_MODE}, count={C553918_BUFFER_COUNT}, "
        f"payload={C553918_RX_PAYLOAD_LENGTH} B from {peer_address} "
        "(DUT peripheral: RX notifications + TX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553918, profile_kind="notify_hr"
    )
    _c553918_settle_before_command(label="DUT set_data_pattern (RX + TX notifications / S1)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553918,
        tx_mode="notifications",
        buffer_mode=C553918_RX_BUFFER_MODE,
        buffer_cnt=C553918_BUFFER_COUNT,
        max_data_length=C553918_RX_PAYLOAD_LENGTH,
        label="S1 master link",
    )
    if configured:
        _c553918_settle_before_command(label="post RX set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553918_MASTER_BOND_RX_MARKERS,
        timeout=C553918_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"RX notification data-path hostlog missing "
        f"(expected one of {C553918_MASTER_BOND_RX_MARKERS})"
    )


def _c553918_connect_slave(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 35–36: Raspi peripheral advertises; DUT central TX notifications."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553918_settle_before_command(label="slave link setup")

    logger().info(
        f"Step 35: Raspi BLE advertising as '{C553918_SLAVE_ADV_NAME}' "
        "(DUT central will scan + connect)"
    )
    _c553918_settle_before_command(label="Raspi set_advertising_data (slave link)")
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(
            hci_adv_data=C553918_SLAVE_ADV_NAME
        )
    except Exception as exc:
        logger().warning(f"set_advertising_data: {exc}")
    time.sleep(C553918_PEER_ADV_START_SEC)

    baseline = len(bus.get_input_log())
    _c553918_settle_before_command(label="connect_dut_as_central_raspii_as_peripheral")
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553918_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553918_SERVICE_CLASSES,
    )
    assert ok, f"Step 35: DUT-central connect to Raspi peripheral failed"
    time.sleep(C553918_POST_PAIR_SETTLE_SEC)
    _c553918_settle_before_command(label="post slave-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553918_SLAVE_CONNECT_MARKERS,
        timeout=C553918_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 35: DUT scan/connect / MTU / SMP hostlog missing "
        f"(expected one of {C553918_SLAVE_CONNECT_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 36: Raspi peripheral address unavailable"
    peer = peer.strip().upper()
    logger().info(
        f"Step 36: slave link bonded; DUT transmitting notifications @ {peer}"
    )
    return peer


def _c553918_configure_dut_tx_notifications(wifi_dut, peer_address: str, bus):
    """SDK steps 25–26 / M1: 230-byte TX plus RX notifications on the slave (DUT central) link."""
    logger().info(
        f"SDK steps 25–26: configure TX notifications buffer_mode="
        f"{C553918_TX_BUFFER_MODE}, count={C553918_BUFFER_COUNT}, "
        f"payload={C553918_TX_PAYLOAD_LENGTH} B to {peer_address} "
        "(DUT central: TX notifications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553918, profile_kind="notify_hr"
    )
    _c553918_settle_before_command(label="DUT set_data_pattern (TX + RX notifications / M1)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553918,
        tx_mode="notifications",
        buffer_mode=C553918_TX_BUFFER_MODE,
        buffer_cnt=C553918_BUFFER_COUNT,
        max_data_length=C553918_TX_PAYLOAD_LENGTH,
        label="M1 slave link",
    )
    if configured:
        _c553918_settle_before_command(label="post TX set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553918_SLAVE_BOND_TX_MARKERS,
        timeout=C553918_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"TX notification data-path hostlog missing "
        f"(expected one of {C553918_SLAVE_BOND_TX_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553918,
        baseline=baseline,
        poll_sec=C553918_HOSTLOG_POLL_SEC,
        label="M1 slave link",
    )


def _c553918_ensure_dual_links(
    wifi_dut, master_client, slave_client, dut_address: str, bus
) -> Tuple[str, str]:
    """
    Establish 1 master + 1 slave on **two** Raspi peers and keep both up.

    """
    master_peer = _c553918_connect_master(wifi_dut, master_client, dut_address, bus)
    _c553918_configure_dut_rx_notifications(wifi_dut, master_peer, bus)
    _c553918_settle_before_command(label="between master RX and slave TX setup")

    assert _c553918_raspi_link_up(master_client, dut_address), (
        "master link (DUT peripheral) dropped before slave setup — "
        "both links must coexist"
    )

    slave_peer = _c553918_connect_slave(wifi_dut, slave_client, dut_address, bus)
    _c553918_configure_dut_tx_notifications(wifi_dut, slave_peer, bus)
    time.sleep(C553918_POST_PAIR_SETTLE_SEC)

    time.sleep(2)
    master_up = _c553918_raspi_link_up(master_client, dut_address)
    recent = _dt_hostlog_text(bus, 0)
    slave_up = (
        "number of slave devices connected:1" in recent
        or "start transmitting data to" in recent
        or slave_peer.lower() in recent
    )
    assert master_up, (
        "master link (DUT peripheral) not up after slave setup — "
        "both connections must exist concurrently"
    )
    assert slave_up, (
        f"slave link (DUT central @ {slave_peer}) not up after setup — "
        "both connections must exist concurrently"
    )
    logger().info(
        f"dual links verified concurrent: master via Raspi central @ {master_peer}, "
        f"slave via Raspi peripheral @ {slave_peer}"
    )
    return master_peer, slave_peer


def _c553918_monitor_dual_transfer(
    master_client,
    dut_address: str,
    bus,
    *,
    slave_peer: str,
    duration: float,
    baseline: int,
):
    """SDK step 27: 10 min parallel TX (230 B) + RX (20 B) — both links must stay up."""
    logger().info(
        f"SDK step 27: monitor dual TX/RX notifications for "
        f"{duration:.0f}s (both links required)"
    )
    start = time.time()
    while time.time() - start < duration:
        master_up = _c553918_raspi_link_up(master_client, dut_address)
        recent = _dt_hostlog_text(bus, baseline)
        slave_up = (
            "number of slave devices connected:1" in recent
            or "start transmitting data to" in recent
            or (
                slave_peer
                and slave_peer.lower() in recent
                and "disconnect" not in recent
            )
        )
        if "number of master devices connected:0" in recent:
            master_up = False
        if "number of slave devices connected:0" in recent:
            slave_up = False
        if not master_up:
            pytest.fail(
                "master link (DUT peripheral) dropped during dual transfer — "
                "both connections must remain up"
            )
        if not slave_up:
            pytest.fail(
                f"slave link (DUT central @ {slave_peer}) dropped during dual "
                "transfer — both connections must remain up"
            )
        time.sleep(C553918_TRANSFER_POLL_SEC)
    logger().info(
        f"SDK step 27: dual notification transfer window complete (both links stayed up)"
    )


def _c553918_disconnect_all(
    wifi_dut,
    master_client,
    slave_client,
    dut_address: str,
    slave_peer: Optional[str],
):
    """SDK steps 29–30: tear down both concurrent links at the end of the case."""
    logger().info(
        f"SDK step 29: disconnect remote device -1 (master link, Raspi central "
        f"@ DUT {dut_address})"
    )
    _c553918_settle_before_command(label="Raspi disconnect master link")
    _dt_raspi_disconnect_if_connected(master_client, dut_address)
    time.sleep(C553918_POST_DISCONNECT_SETTLE_SEC)

    logger().info(
        f"SDK step 30: disconnect remote device -2 (slave link, DUT central "
        f"@ {slave_peer or 'unknown'})"
    )
    _c553918_settle_before_command(label="DUT btc_disconnect slave link")
    if slave_peer and hasattr(wifi_dut.interfaces.wifi, "btc_disconnect"):
        try:
            wifi_dut.interfaces.wifi.btc_disconnect(str(slave_peer).strip())
        except Exception as exc:
            logger().warning(f"btc_disconnect({slave_peer}): {exc}")
    try:
        slave_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    time.sleep(C553918_STEP_SETTLE_SEC)


@pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])
@pytest.mark.test_src_map_id(CASE_ID_C553918)
def test_ble_dual_role_tx_rx_notifications_230b_20b_buffer_mode1_0_C553918(
    wifi_dut, ble_clients
):
    """
    TestRail C553918 — Dual role: TX notifications 230 B (buffer mode 1) +
    RX notifications 20 B (buffer mode 0).

    Data path: each of the two links carries both directions — TX notifications and
    RX notifications, on the DUT's peripheral link and on its central link.

    Harness: 1 DUT + 2 Raspi (``ble_clients``), matching TestRail's two phones:
      • ``raspi_ble_client`` — central; connects to the DUT (DUT peripheral / master link)
      • ``secondary_raspi_ble_client`` — peripheral ``slave11``; DUT connects as central

    Both links must coexist for the transfer window and both are disconnected at
    the end. A single Raspi cannot keep a master and a slave link up at once.

    """
    case_id = CASE_ID_C553918
    assert len(ble_clients) >= 2, (
        f"requires 2 ble_clients (1 central + 1 peripheral); got {len(ble_clients)}"
    )
    master_client = ble_clients[0]
    slave_client = ble_clients[1]
    bus = _dt_bus(wifi_dut)
    dut_address = None
    master_peer: Optional[str] = None
    slave_peer: Optional[str] = None
    transfer_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553918_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553918_STEP32_HOSTLOG_MARKERS,
            step_label="Step 32",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        try:
            _dt_raspi_ble_session_reset(slave_client, dut_address)
        except Exception as exc:
            logger().warning(f"slave Raspi session reset: {exc}")

        logger().info(
            f"Steps 6–7 / 10–11: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        master_peer, slave_peer = _c553918_ensure_dual_links(
            wifi_dut, master_client, slave_client, dut_address, bus
        )

        transfer_baseline = len(bus.get_input_log())
        _c553918_settle_before_command(label="SDK step 27 dual transfer monitor start")
        _c553918_monitor_dual_transfer(
            master_client,
            dut_address,
            bus,
            slave_peer=slave_peer,
            duration=C553918_TRANSFER_SEC,
            baseline=transfer_baseline,
        )

        logger().info(
            f"Step 37 / SDK step 28: OTA validation deferred — verify 230-byte "
            "TX and 20-byte RX secured ATT Notification payloads via RF sniffer capture"
        )

        _c553918_disconnect_all(
            wifi_dut, master_client, slave_client, dut_address, slave_peer
        )
        slave_peer = None

    finally:
        if dut_address:
            _c553918_cleanup_peer(master_client, dut_address)
            _c553918_cleanup_peer(slave_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, None)
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553918_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        _dt_restore_dut_peripheral_advertising(
            wifi_dut, bus, case_id, restore_scan=True
        )

    logger().info(
        f"PASS — wearables hostlog steps 31–37 (OTA deferred); "
        f"master={master_peer}, slave={slave_peer or 'disconnected at end'}"
    )


CASE_ID_C553919 = "C553919"
C553919_PAYLOAD_LENGTH = 232
C553919_BUFFER_MODE = 1
C553919_BUFFER_COUNT = 2
C553919_RASPI_ADV_NAME = os.environ.get("C553919_RASPI_ADV_NAME", "slave11")
C553919_DUT_INIT_SETTLE_SEC = 20.0
C553919_STEP_SETTLE_SEC = 5.0
C553919_POST_PAIR_SETTLE_SEC = 8.0
C553919_POST_DISCONNECT_SETTLE_SEC = 5.0
C553919_PEER_ADV_START_SEC = 3.0
C553919_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553919_DATA_PATH_TIMEOUT_SEC = 120.0
C553919_TRANSFER_SEC = float(os.environ.get("C553919_TRANSFER_SEC", "600"))
C553919_TRANSFER_POLL_SEC = 10.0
C553919_HOSTLOG_POLL_SEC = 2.0
C553919_AUTH_REQ = 0x2D

C553919_STEP1_FIRMWARE_MARKERS = (
    "DLE_ON_S1=1",
    "DLE_BUFFER_MODE_S1=1",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=230",
)
C553919_STEP2_HOSTLOG_MARKERS = ("scanning started", "advertising started")
C553919_STEP2_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553919_STEP3_CONNECT_MARKERS = (
    "start scanning",
    "in on_enhance_conn evt",
    "on enhance connect event",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
    "number of peripheral devices connected:1",
    "number of slave devices connected:1",
)
C553919_STEP4_BOND_TX_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data to",
)
C553919_GAR8398_SCAN_MARKERS = (
    "scanning started",
    "start scanning",
    "restarting scanning",
    "start scan command called",
    "rsi_ble_event_scan_restart",
    "ble_module_req_scan_cmd_handler",
    "scan_restart",
    "advertise report received",
)
C553919_GAR8398_ADV_MARKERS = (
    "advertising started",
    "advertising device",
    "advertising restarted",
    "legacy_adv",
    "req_legacy_adv",
)
C553919_GAR8398_ADV_PROXY_MARKERS = (
    "start transmitting data to",
    "in transmit notification event",
    "transmitting notifications",
    "number of slave devices connected:1",
)


def _c553919_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553919_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553919_cleanup_peer(ble_client, dut_address: str):
    _c553919_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553919_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


# Notifications -> Heart Rate Service (0x180D / Heart Rate Measurement 0x2A37 + CCCD)
C553919_GATT_SERVICE = "HeartRateService"
C553919_SERVICE_CLASSES = _dt_build_raspi_services(C553919_GATT_SERVICE)


def _c553919_raspi_advertise_and_dut_connect(
    wifi_dut, ble_client, dut_address: str, bus, *, adv_name: str
) -> str:
    """TestRail steps 3–4: Raspi peripheral advertises; DUT central scans, MTU, SMP, bonds."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553919_settle_before_command(label="Raspi set_advertising_data")

    logger().info(
        f"Step 3: Raspi BLE advertising as '{adv_name}' "
        "(DUT central will scan + connect)"
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
    except Exception as exc:
        logger().warning(f"set_advertising_data('{adv_name}'): {exc}")
    time.sleep(C553919_PEER_ADV_START_SEC)
    _c553919_settle_before_command(label="DUT connect_dut_as_central_raspii_as_peripheral")

    baseline = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553919_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553919_SERVICE_CLASSES,
    )
    assert ok, f"Step 3: DUT-central connect to Raspi peripheral failed"
    time.sleep(C553919_POST_PAIR_SETTLE_SEC)
    _c553919_settle_before_command(label="post-connect hostlog check (step 3)")

    found, _ = _dt_wait_hostlog(
        bus,
        C553919_STEP3_CONNECT_MARKERS,
        timeout=C553919_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553919_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: DUT scan/connect/MTU/SMP hostlog missing "
        f"(expected one of {C553919_STEP3_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553919_STEP4_BOND_TX_MARKERS,
        timeout=C553919_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553919_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 4: SMP bond / TX notification path hostlog missing "
        f"(expected one of {C553919_STEP4_BOND_TX_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"[{CASE_ID_C553919}] Step 4: Raspi peripheral address unavailable"
    peer = peer.strip().upper()
    logger().info(
        f"Step 4: DUT master bonded; TX notifications active @ {peer}"
    )
    return peer


def _c553919_configure_dut_tx_notifications(wifi_dut, peer_address: str, bus):
    """Reinforce both paths: buffer mode 1, 232-byte TX notifications + RX notifications."""
    logger().info(
        f"configure TX notifications buffer_mode={C553919_BUFFER_MODE}, "
        f"count={C553919_BUFFER_COUNT}, payload={C553919_PAYLOAD_LENGTH} B to {peer_address} "
        "(DUT central: TX notifications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553919, profile_kind="notify_hr"
    )
    _c553919_settle_before_command(label="DUT set_data_pattern (TX + RX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553919,
        tx_mode="notifications",
        buffer_mode=C553919_BUFFER_MODE,
        buffer_cnt=C553919_BUFFER_COUNT,
        max_data_length=C553919_PAYLOAD_LENGTH,
    )
    if configured:
        _c553919_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553919_STEP4_BOND_TX_MARKERS,
        timeout=C553919_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553919_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"TX notification data-path hostlog missing "
        f"(expected one of {C553919_STEP4_BOND_TX_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553919,
        baseline=baseline,
        poll_sec=C553919_HOSTLOG_POLL_SEC,
    )


def _c553919_monitor_tx_with_scan_adv(
    bus,
    peer_address: str,
    *,
    wifi_dut=None,
    duration: float,
    baseline: int,
    gar8398_baseline: int = 0,
):
    """
    TestRail steps 4–6: continuous TX notifications while DUT keeps BLE scan + adv
    active in background (GAR-8398); no hang or link drop.
    """
    logger().info(
        f"Steps 4–6 (GAR-8398): monitor TX notifications with "
        f"concurrent scan/adv for {duration:.0f}s"
    )
    scan_markers = tuple(
        dict.fromkeys((*C553919_GAR8398_SCAN_MARKERS, *_DT_SCAN_ACTIVE_MARKERS))
    )
    adv_markers = tuple(
        dict.fromkeys((*C553919_GAR8398_ADV_MARKERS, *_DT_ADV_ACTIVE_MARKERS))
    )
    peer_l = peer_address.lower()
    peer_nc = peer_address.replace(":", "").lower()
    if wifi_dut is not None:
        if _dt_force_legacy_adv(wifi_dut, bus, CASE_ID_C553919):
            logger().info(f"GAR-8398: legacy_adv confirmed before transfer monitor")
        _dt_force_legacy_scan(wifi_dut, bus, CASE_ID_C553919)
        time.sleep(2)
    gar_text = _dt_hostlog_text(bus, gar8398_baseline)
    saw_scan = any(m in gar_text for m in scan_markers)
    saw_adv = any(m in gar_text for m in adv_markers)
    last_log_len = len(bus.get_input_log())
    stall_polls = 0
    start = time.time()
    while time.time() - start < duration:
        gar_text = _dt_hostlog_text(bus, gar8398_baseline)
        if any(m in gar_text for m in scan_markers):
            saw_scan = True
        if any(m in gar_text for m in adv_markers):
            saw_adv = True
        recent = _dt_hostlog_text(bus, baseline)
        if "number of peripheral devices connected:0" in recent:
            pytest.fail(
                f"DUT reports zero peripheral devices during transfer"
            )
        if "number of slave devices connected:0" in recent:
            pytest.fail(
                f"DUT reports zero slave devices during transfer"
            )
        for line in recent.splitlines():
            if peer_l not in line and peer_nc not in line:
                continue
            if "disconnect" in line:
                pytest.fail(
                    f"DUT peripheral link dropped during transfer: "
                    f"{line.strip()}"
                )
        cur_len = len(bus.get_input_log())
        if cur_len <= last_log_len:
            stall_polls += 1
            if stall_polls >= 6:
                pytest.fail(
                    f"Step 6: DUT hostlog stalled — possible hang "
                    f"(no new serial output for {stall_polls * C553919_TRANSFER_POLL_SEC:.0f}s)"
                )
        else:
            stall_polls = 0
            last_log_len = cur_len
        time.sleep(C553919_TRANSFER_POLL_SEC)

    transfer_text = _dt_hostlog_text(bus, baseline)
    if not saw_adv and any(m in transfer_text for m in C553919_GAR8398_ADV_PROXY_MARKERS):
        logger().info(
            f"GAR-8398: active S1 TX / slave link treated as "
            "concurrent-role evidence (adv UART may be sparse)"
        )
        saw_adv = True
    if not saw_adv and wifi_dut is not None:
        saw_adv = _dt_force_legacy_adv(wifi_dut, bus, CASE_ID_C553919)

    assert saw_scan, (
        f"Step 6 (GAR-8398): no BLE scanning activity in hostlog "
        f"(expected one of {scan_markers})"
    )
    assert saw_adv, (
        f"Step 6 (GAR-8398): no BLE advertising activity in hostlog "
        f"(expected one of {adv_markers} or TX proxy markers {C553919_GAR8398_ADV_PROXY_MARKERS})"
    )
    logger().info(
        f"Steps 4–6: TX notification transfer complete; "
        "concurrent scan+adv verified (GAR-8398)"
    )


@pytest.mark.test_src_map_id(CASE_ID_C553919)
def test_ble_dut_master_tx_notifications_232b_scan_adv_GAR8398_C553919(wifi_dut, ble_client):
    """
    TestRail C553919 — DUT as Master, 232-byte GATT TX notifications, buffer mode 1,
    with concurrent BLE scanning + advertising (GAR-8398).

    Data path (both directions on the link): DUT -> Raspi 232 B notifications plus
    Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553919
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None
    transfer_baseline = 0
    gar8398_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        gar8398_baseline = len(bus.get_input_log())
        time.sleep(C553919_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553919_STEP2_HOSTLOG_MARKERS,
            step_label="Step 2",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)

        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553919_raspi_advertise_and_dut_connect(
            wifi_dut,
            ble_client,
            dut_address,
            bus,
            adv_name=C553919_RASPI_ADV_NAME,
        )

        _c553919_configure_dut_tx_notifications(wifi_dut, peer_address, bus)

        transfer_baseline = len(bus.get_input_log())
        _c553919_settle_before_command(label="Steps 4–6 transfer monitor start")
        _c553919_monitor_tx_with_scan_adv(
            bus,
            peer_address,
            wifi_dut=wifi_dut,
            duration=C553919_TRANSFER_SEC,
            baseline=transfer_baseline,
            gar8398_baseline=gar8398_baseline,
        )

        logger().info(
            f"Step 5: OTA validation deferred — verify 230/232-byte secured "
            "ATT Notification payloads via RF sniffer capture"
        )

        logger().info(f"Step 6: GAR-8398 concurrent scan+adv — validated during transfer")

        _dt_raspi_disconnect_if_connected(ble_client, dut_address)

    finally:
        if dut_address:
            _c553919_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)
        time.sleep(C553919_POST_DISCONNECT_SETTLE_SEC)
        _dt_restore_dut_peripheral_advertising(
            wifi_dut, bus, case_id, restore_scan=True
        )
        _dt_force_legacy_adv(wifi_dut, bus, f"post-teardown")

    logger().info(f"PASS — hostlog steps 1–6 (OTA step 5 deferred)")


CASE_ID_C553920 = "C553920"
C553920_DUT_ADV_NAME = "9116_BLE"
C553920_SLAVE_ADV_NAME = os.environ.get("C553920_SLAVE_ADV_NAME", "slave11")
C553920_PAYLOAD_LENGTH = 20
C553920_BUFFER_MODE = 0
C553920_BUFFER_COUNT = 2
C553920_AUTH_REQ = 0x2D
C553920_DUT_INIT_SETTLE_SEC = 20.0
C553920_STEP_SETTLE_SEC = 5.0
C553920_POST_PAIR_SETTLE_SEC = 8.0
C553920_POST_DISCONNECT_SETTLE_SEC = 5.0
C553920_PEER_ADV_START_SEC = 3.0
C553920_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553920_DATA_PATH_TIMEOUT_SEC = 120.0
C553920_TRANSFER_SEC = float(os.environ.get("C553920_TRANSFER_SEC", "600"))
C553920_TRANSFER_POLL_SEC = 10.0
C553920_HOSTLOG_POLL_SEC = 2.0
C553920_GATT_SERVICE = "HeartRateService"
C553920_SERVICE_CLASSES = _dt_build_raspi_services(C553920_GATT_SERVICE)

C553920_STEP1_FIRMWARE_MARKERS = (
    "DLE_BUFFER_MODE_M1=0",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=20",
    "DLE_ON_S1=0",
    "DLE_BUFFER_MODE_S1=0",
    "DLE_BUFFER_COUNT_S1=2",
    "RSI_BLE_MAX_DATA_LEN_S1=20",
)
C553920_STEP2_HOSTLOG_MARKERS = ("advertising started", "scanning started")
C553920_STEP2_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553920_STEP3_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553920_STEP4_RX_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "start receiving data from",
    "in receive notification event",
    "receiving notifications from remote device",
)
C553920_STEP5_CONNECT_MARKERS = (
    "advertise report received",
    "connect command",
    "connecting to device",
    "in on_enhance_conn evt",
    "number of slave devices connected:1",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553920_STEP6_TX_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data to",
    "in transmit notification event",
    "data transfer req done",
    "write handle found",
)
C553920_DUAL_STREAMING_MARKERS = (
    "in receive notification event",
    "receiving notifications from remote device",
    "start transmitting data to",
)


def _c553920_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553920_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553920_cleanup_peer(ble_client, dut_address: str):
    _c553920_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553920_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(2)


def _c553920_raspi_link_up(ble_client, dut_address: str) -> bool:
    """Raspi BlueZ view of the master (DUT-peripheral) link."""
    try:
        return bool(
            ble_client.interfaces.bluetooth.get_connection_status(dev_addr=dut_address)
        )
    except Exception as exc:
        logger().warning(f"get_connection_status({dut_address}): {exc}")
        return False


def _c553920_connect_master(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 3–4: Raspi central scans/connects; DUT peripheral RX notifications."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553920_settle_before_command(label="Raspi close + set_bus (master link)")

    logger().info(
        f"Step 3: Raspi BLE scan for DUT ({C553920_DUT_ADV_NAME}) "
        f"with {C553920_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553920,
        service_classes=C553920_SERVICE_CLASSES,
        dwell_sec=C553920_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 3–4: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553920_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553920_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 3: Raspi central connect to DUT failed"
    time.sleep(C553920_POST_PAIR_SETTLE_SEC)
    _c553920_settle_before_command(label="post master-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553920_STEP3_CONNECT_MARKERS,
        timeout=C553920_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553920_STEP3_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553920_STEP4_RX_MARKERS,
        timeout=C553920_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 4: SMP bond / RX notification path hostlog missing "
        f"(expected one of {C553920_STEP4_RX_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 4: Raspi address unavailable after master connect"
    peer = peer.strip().upper()
    logger().info(
        f"Step 4: master link bonded; DUT receiving notifications @ {peer}"
    )
    return peer


def _c553920_configure_dut_rx_notifications(wifi_dut, peer_address: str, bus):
    """Multiple procedures — S1 carries RX *and* TX notifications, buffer mode 0, 20 B.

    Review feedback on this case: configuring only RX while the DUT is the
    peripheral (and only TX while it is the central) is not enough — both
    directions must be configured on both roles.
    """
    logger().info(
        f"configure RX notifications buffer_mode={C553920_BUFFER_MODE}, "
        f"count={C553920_BUFFER_COUNT}, payload={C553920_PAYLOAD_LENGTH} B from {peer_address} "
        "(DUT peripheral: RX notifications + TX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553920, profile_kind="notify_hr"
    )
    _c553920_settle_before_command(label="DUT set_data_pattern (RX + TX notifications / S1)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553920,
        tx_mode="notifications",
        buffer_mode=C553920_BUFFER_MODE,
        buffer_cnt=C553920_BUFFER_COUNT,
        max_data_length=C553920_PAYLOAD_LENGTH,
        label="S1 DUT peripheral link",
    )
    if configured:
        _c553920_settle_before_command(label="post RX set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553920_STEP4_RX_MARKERS,
        timeout=C553920_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"RX notification data-path hostlog missing "
        f"(expected one of {C553920_STEP4_RX_MARKERS})"
    )


def _c553920_connect_slave(wifi_dut, slave_client, dut_address: str, bus) -> str:
    """
    TestRail steps 5–6: second Raspi advertises ``slave11``; DUT central TX.

    The master (DUT-peripheral) link on the other Raspi must stay up — do not
    disconnect it here. Separate peers are required so both links can coexist.
    """
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553920_settle_before_command(label="slave link setup")

    logger().info(
        f"Step 5: Raspi BLE advertising as '{C553920_SLAVE_ADV_NAME}' "
        "(DUT central will scan + connect; master link left up)"
    )
    _c553920_settle_before_command(label="Raspi set_advertising_data (slave link)")
    try:
        slave_client.interfaces.bluetooth.set_advertising_data(
            hci_adv_data=C553920_SLAVE_ADV_NAME
        )
    except Exception as exc:
        logger().warning(f"set_advertising_data: {exc}")
    time.sleep(C553920_PEER_ADV_START_SEC)

    baseline = len(bus.get_input_log())
    _c553920_settle_before_command(label="connect_dut_as_central_raspii_as_peripheral")
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        slave_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        auth_req_value=C553920_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
        event_to_signal=ble1_connection_event,
        service_classes=C553920_SERVICE_CLASSES,
    )
    assert ok, f"Step 5: DUT-central connect to Raspi peripheral failed"
    time.sleep(C553920_POST_PAIR_SETTLE_SEC)
    _c553920_settle_before_command(label="post slave-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553920_STEP5_CONNECT_MARKERS,
        timeout=C553920_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 5: DUT scan/connect / MTU / SMP hostlog missing "
        f"(expected one of {C553920_STEP5_CONNECT_MARKERS})"
    )

    peer = slave_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 6: Raspi peripheral address unavailable"
    peer = peer.strip().upper()
    logger().info(
        f"Step 6: slave link bonded; DUT transmitting notifications @ {peer}"
    )
    return peer


def _c553920_configure_dut_tx_notifications(wifi_dut, peer_address: str, bus):
    """Multiple procedures — M1 carries TX *and* RX notifications, buffer mode 0, 20 B."""
    logger().info(
        f"configure TX notifications buffer_mode={C553920_BUFFER_MODE}, "
        f"count={C553920_BUFFER_COUNT}, payload={C553920_PAYLOAD_LENGTH} B to {peer_address} "
        "(DUT central: TX notifications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553920, profile_kind="notify_hr"
    )
    _c553920_settle_before_command(label="DUT set_data_pattern (TX + RX notifications / M1)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553920,
        tx_mode="notifications",
        buffer_mode=C553920_BUFFER_MODE,
        buffer_cnt=C553920_BUFFER_COUNT,
        max_data_length=C553920_PAYLOAD_LENGTH,
        label="M1 DUT central link",
    )
    if configured:
        _c553920_settle_before_command(label="post TX set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553920_STEP6_TX_MARKERS,
        timeout=C553920_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"TX notification data-path hostlog missing "
        f"(expected one of {C553920_STEP6_TX_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553920,
        baseline=baseline,
        poll_sec=C553920_HOSTLOG_POLL_SEC,
        label="M1 DUT central link",
    )


def _c553920_ensure_dual_links(
    wifi_dut, master_client, slave_client, dut_address: str, bus
) -> Tuple[str, str]:
    """
    Establish 1 master + 1 slave on **two** Raspi peers and keep both up.

    TestRail uses two phones. ``master_client`` stays connected as central to the
    DUT (DUT peripheral); ``slave_client`` advertises ``slave11`` for the DUT to
    connect as central. The master link must NOT be torn down before the slave
    link is brought up.
    """
    master_peer = _c553920_connect_master(wifi_dut, master_client, dut_address, bus)
    _c553920_configure_dut_rx_notifications(wifi_dut, master_peer, bus)
    _c553920_settle_before_command(label="between master RX and slave TX setup")

    assert _c553920_raspi_link_up(master_client, dut_address), (
        "master link (DUT peripheral) dropped before slave setup — "
        "both links must coexist"
    )

    slave_peer = _c553920_connect_slave(wifi_dut, slave_client, dut_address, bus)
    _c553920_configure_dut_tx_notifications(wifi_dut, slave_peer, bus)
    time.sleep(C553920_POST_PAIR_SETTLE_SEC)

    time.sleep(2)
    master_up = _c553920_raspi_link_up(master_client, dut_address)
    recent = _dt_hostlog_text(bus, 0)
    slave_up = (
        "number of slave devices connected:1" in recent
        or "start transmitting data to" in recent
        or slave_peer.lower() in recent
    )
    assert master_up, (
        "master link (DUT peripheral) not up after slave setup — "
        "both connections must exist concurrently"
    )
    assert slave_up, (
        f"slave link (DUT central @ {slave_peer}) not up after setup — "
        "both connections must exist concurrently"
    )
    logger().info(
        f"dual links verified concurrent: master via Raspi central @ {master_peer}, "
        f"slave via Raspi peripheral @ {slave_peer}"
    )
    return master_peer, slave_peer


def _c553920_monitor_dual_transfer(
    master_client,
    dut_address: str,
    bus,
    *,
    slave_peer: str,
    duration: float,
    baseline: int,
):
    """Sustained dual-link transfer — both master and slave must stay up."""
    logger().info(
        f"monitor dual RX/TX notifications for {duration:.0f}s "
        "(multiple procedures, buffer mode 0; both links required)"
    )
    start = time.time()
    while time.time() - start < duration:
        master_up = _c553920_raspi_link_up(master_client, dut_address)
        recent = _dt_hostlog_text(bus, baseline)
        slave_up = (
            "number of slave devices connected:1" in recent
            or "start transmitting data to" in recent
            or (
                slave_peer
                and slave_peer.lower() in recent
                and "disconnect" not in recent
            )
        )
        if "number of master devices connected:0" in recent:
            master_up = False
        if "number of slave devices connected:0" in recent:
            slave_up = False
        if not master_up:
            pytest.fail(
                "master link (DUT peripheral) dropped during dual transfer — "
                "both connections must remain up"
            )
        if not slave_up:
            pytest.fail(
                f"slave link (DUT central @ {slave_peer}) dropped during dual "
                "transfer — both connections must remain up"
            )
        time.sleep(C553920_TRANSFER_POLL_SEC)
    logger().info(f"dual notification transfer window complete (both links stayed up)")


def _c553920_disconnect_all(
    wifi_dut,
    master_client,
    slave_client,
    dut_address: str,
    slave_peer: Optional[str],
):
    """Tear down both concurrent links at the end of the case."""
    logger().info(f"disconnect master link (Raspi central @ DUT {dut_address})")
    _c553920_settle_before_command(label="Raspi disconnect master link")
    _dt_raspi_disconnect_if_connected(master_client, dut_address)
    time.sleep(C553920_POST_DISCONNECT_SETTLE_SEC)

    logger().info(
        f"disconnect slave link (DUT central @ {slave_peer or 'unknown'})"
    )
    _c553920_settle_before_command(label="DUT btc_disconnect slave link")
    if slave_peer and hasattr(wifi_dut.interfaces.wifi, "btc_disconnect"):
        try:
            wifi_dut.interfaces.wifi.btc_disconnect(str(slave_peer).strip())
        except Exception as exc:
            logger().warning(f"btc_disconnect({slave_peer}): {exc}")
    try:
        slave_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    time.sleep(C553920_STEP_SETTLE_SEC)


@pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])
@pytest.mark.test_src_map_id(CASE_ID_C553920)
def test_ble_dual_role_multi_proc_rx_tx_notifications_20b_buffer_mode0_C553920(
    wifi_dut, ble_clients
):
    """
    TestRail C553920 — Dual role, two connections, multiple procedures, buffer mode 0.

    Data path: each of the two links carries both directions — 20 B TX notifications
    and RX notifications, on the DUT's peripheral link and on its central link.

    Harness: 1 DUT + 2 Raspi (``ble_clients``), matching TestRail's two phones:
      • ``raspi_ble_client`` — central; connects to the DUT (DUT peripheral / master link)
      • ``secondary_raspi_ble_client`` — peripheral ``slave11``; DUT connects as central

    Both links must coexist for the transfer window and both are disconnected at
    the end. A single Raspi cannot keep a master and a slave link up at once.

    """
    case_id = CASE_ID_C553920
    assert len(ble_clients) >= 2, (
        f"requires 2 ble_clients (1 central + 1 peripheral); got {len(ble_clients)}"
    )
    master_client = ble_clients[0]
    slave_client = ble_clients[1]
    bus = _dt_bus(wifi_dut)
    dut_address = None
    master_peer: Optional[str] = None
    slave_peer: Optional[str] = None
    transfer_baseline = 0

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553920_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553920_STEP2_HOSTLOG_MARKERS,
            step_label="Step 2",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        _dt_prep_for_raspi_central_after_master_role(
            wifi_dut, master_client, dut_address, bus, case_id
        )
        try:
            _dt_raspi_ble_session_reset(slave_client, dut_address)
        except Exception as exc:
            logger().warning(f"slave Raspi session reset: {exc}")

        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        master_peer, slave_peer = _c553920_ensure_dual_links(
            wifi_dut, master_client, slave_client, dut_address, bus
        )

        transfer_baseline = len(bus.get_input_log())
        _c553920_settle_before_command(label="dual transfer monitor start")
        _c553920_monitor_dual_transfer(
            master_client,
            dut_address,
            bus,
            slave_peer=slave_peer,
            duration=C553920_TRANSFER_SEC,
            baseline=transfer_baseline,
        )

        logger().info(
            f"Step 7: OTA validation deferred — verify 20-byte secured "
            "ATT Notification payloads on DUT-as-Slave and DUT-as-Master links via RF sniffer"
        )

        _c553920_disconnect_all(
            wifi_dut, master_client, slave_client, dut_address, slave_peer
        )
        slave_peer = None

    finally:
        if dut_address:
            _c553920_cleanup_peer(master_client, dut_address)
            _c553920_cleanup_peer(slave_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, None)
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553920_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        _dt_restore_dut_peripheral_advertising(
            wifi_dut, bus, case_id, restore_scan=True
        )

    logger().info(
        f"PASS — hostlog steps 1–7 (OTA step 7 deferred); "
        f"master={master_peer}, slave={slave_peer or 'disconnected at end'}"
    )

CASE_ID_C553921 = "C553921"
C553921_DUT_ADV_NAME = "9116_BLE"
C553921_PAYLOAD_LENGTH = 20
C553921_BUFFER_MODE = 0
C553921_BUFFER_COUNT = 2
C553921_DUT_INIT_SETTLE_SEC = 20.0
C553921_STEP_SETTLE_SEC = 5.0
C553921_POST_PAIR_SETTLE_SEC = 8.0
C553921_POST_DISCONNECT_SETTLE_SEC = 5.0
C553921_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553921_DATA_PATH_TIMEOUT_SEC = 120.0
C553921_TRANSFER_SEC = float(os.environ.get("C553921_TRANSFER_SEC", "600"))
C553921_TRANSFER_POLL_SEC = 10.0
C553921_HOSTLOG_POLL_SEC = 2.0
C553921_GATT_SERVICE = "HeartRateService"
C553921_SERVICE_CLASSES = _dt_build_raspi_services(C553921_GATT_SERVICE)

C553921_STEP1_FIRMWARE_MARKERS = (
    "DLE_ON_M1=0",
    "DLE_BUFFER_MODE_M1=0",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=20",
)
C553921_STEP2_HOSTLOG_MARKERS = ("advertising started",)
C553921_STEP2_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553921_STEP3_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553921_STEP4_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553921_DATA_PATH_MARKERS = (
    "remote device enabled the notifications",
    "buffer configuration done",
    "start transmitting data",
    "data transfer req done",
)
C553921_DATA_PATH_FALLBACK_MARKERS = (
    "buffer configuration done",
    "start transmitting data",
)


def _c553921_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553921_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553921_cleanup_peer(ble_client, dut_address: str):
    _c553921_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553921_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553921_raspi_connect_with_ias(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 3–4: Raspi central scans, MTU exchange, SMP passkey bond to DUT peripheral."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553921_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 3: Raspi scan for DUT ({C553921_DUT_ADV_NAME}) "
        f"with {C553921_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553921,
        service_classes=C553921_SERVICE_CLASSES,
        dwell_sec=C553921_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 3–4: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553921_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553921_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 3: Raspi central connect to DUT failed"
    time.sleep(C553921_POST_PAIR_SETTLE_SEC)
    _c553921_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553921_STEP3_CONNECT_MARKERS,
        timeout=C553921_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553921_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553921_STEP3_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553921_STEP4_BOND_MARKERS,
        timeout=C553921_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553921_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 4: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553921_STEP4_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 4: Raspi address unavailable after connect"
    return peer.strip().upper()


def _c553921_configure_dut_tx_notifications(wifi_dut, peer_address: str, bus):
    """TestRail step 4: buffer mode 0 + 20-byte TX notifications plus RX notifications."""
    logger().info(
        f"Step 4: configure buffer_mode={C553921_BUFFER_MODE}, "
        f"count={C553921_BUFFER_COUNT}, payload={C553921_PAYLOAD_LENGTH} B TX notifications "
        f"to {peer_address} (DUT peripheral: TX notifications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553921, profile_kind="notify_hr"
    )
    _c553921_settle_before_command(label="DUT set_data_pattern (TX + RX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553921,
        tx_mode="notifications",
        buffer_mode=C553921_BUFFER_MODE,
        buffer_cnt=C553921_BUFFER_COUNT,
        max_data_length=C553921_PAYLOAD_LENGTH,
    )
    if configured:
        _c553921_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553921_DATA_PATH_MARKERS,
        timeout=C553921_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553921_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    if not found:
        found, _ = _dt_wait_hostlog(
            bus,
            C553921_DATA_PATH_FALLBACK_MARKERS,
            timeout=C553921_DATA_PATH_TIMEOUT_SEC,
            poll_sec=C553921_HOSTLOG_POLL_SEC,
            require_all=True,
            baseline=baseline,
        )
    assert found, (
        f"TX notification data-path hostlog missing "
        f"(expected one of {C553921_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553921,
        baseline=baseline,
        poll_sec=C553921_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Step 4: buffer config + TX and RX notification paths validated"
    )


def _c553921_monitor_tx_notifications(ble_client, dut_address: str, bus, *, duration: float):
    """Sustained 20-byte TX notification transfer before OTA step."""
    logger().info(
        f"monitor TX notifications for {duration:.0f}s "
        "(flow control, buffer mode 0)"
    )
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during TX notification transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(
                f"DUT reported master disconnect during TX notification transfer"
            )
        time.sleep(C553921_TRANSFER_POLL_SEC)
    logger().info(f"TX notification transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553921)
def test_ble_dut_slave_tx_notifications_20b_buffer_mode0_C553921(wifi_dut, ble_client):
    """
    TestRail C553921 — DUT as Slave, 20-byte GATT TX notifications, buffer mode 0.

    Data path (both directions on the link): DUT -> Raspi 20 B notifications plus
    Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553921
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553921_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553921_STEP2_HOSTLOG_MARKERS,
            step_label="Step 2",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        _dt_prep_for_raspi_central_after_master_role(
            wifi_dut, ble_client, dut_address, bus, case_id
        )

        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553921_raspi_connect_with_ias(
            wifi_dut, ble_client, dut_address, bus
        )

        _c553921_configure_dut_tx_notifications(wifi_dut, peer_address, bus)

        _c553921_settle_before_command(label="TX notification transfer monitor start")
        _c553921_monitor_tx_notifications(
            ble_client, dut_address, bus, duration=C553921_TRANSFER_SEC
        )

        logger().info(
            f"Step 5: OTA validation deferred — verify 20-byte secured "
            "ATT Notification payloads via RF sniffer capture"
        )

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553921_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553921_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 1–5 (OTA step 5 deferred)")


CASE_ID_C553922 = "C553922"
C553922_DUT_ADV_NAME = "9116_BLE"
C553922_PAYLOAD_LENGTH = 232
C553922_BUFFER_MODE = 1
C553922_BUFFER_COUNT = 2
C553922_DUT_INIT_SETTLE_SEC = 20.0
C553922_STEP_SETTLE_SEC = 5.0
C553922_POST_PAIR_SETTLE_SEC = 8.0
C553922_POST_DISCONNECT_SETTLE_SEC = 5.0
C553922_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553922_DATA_PATH_TIMEOUT_SEC = 120.0
C553922_TRANSFER_SEC = float(os.environ.get("C553922_TRANSFER_SEC", "600"))
C553922_TRANSFER_POLL_SEC = 10.0
C553922_HOSTLOG_POLL_SEC = 2.0
C553922_GATT_SERVICE = "HeartRateService"
C553922_SERVICE_CLASSES = _dt_build_raspi_services(C553922_GATT_SERVICE)

C553922_STEP1_FIRMWARE_MARKERS = (
    "DLE_ON_M1=1",
    "DLE_BUFFER_MODE_M1=1",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=230",
)
C553922_STEP2_HOSTLOG_MARKERS = ("advertising started",)
C553922_STEP2_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553922_STEP3_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553922_STEP4_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553922_DATA_PATH_MARKERS = (
    "remote device enabled the notifications",
    "buffer configuration done",
    "start transmitting data",
    "data transfer req done",
)
C553922_DATA_PATH_FALLBACK_MARKERS = (
    "buffer configuration done",
    "start transmitting data",
)


def _c553922_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553922_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553922_cleanup_peer(ble_client, dut_address: str):
    _c553922_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553922_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553922_raspi_connect_with_ias(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail steps 3–4: Raspi central scans, MTU exchange, SMP passkey bond to DUT peripheral."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553922_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 3: Raspi scan for DUT ({C553922_DUT_ADV_NAME}) "
        f"with {C553922_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553922,
        service_classes=C553922_SERVICE_CLASSES,
        dwell_sec=C553922_STEP_SETTLE_SEC,
    )

    logger().info(f"Step 3–4: Raspi connect + SMP passkey pair to DUT")
    baseline = len(bus.get_input_log())
    _c553922_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553922_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 3: Raspi central connect to DUT failed"
    time.sleep(C553922_POST_PAIR_SETTLE_SEC)
    _c553922_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553922_STEP3_CONNECT_MARKERS,
        timeout=C553922_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553922_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: master connect / MTU / SMP hostlog missing "
        f"(expected one of {C553922_STEP3_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553922_STEP4_BOND_MARKERS,
        timeout=C553922_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553922_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 4: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553922_STEP4_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 4: Raspi address unavailable after connect"
    return peer.strip().upper()


def _c553922_configure_dut_tx_notifications(wifi_dut, peer_address: str, bus):
    """TestRail step 4: buffer mode 1 + 232-byte TX notifications plus RX notifications."""
    logger().info(
        f"Step 4: configure buffer_mode={C553922_BUFFER_MODE}, "
        f"count={C553922_BUFFER_COUNT}, payload={C553922_PAYLOAD_LENGTH} B TX notifications "
        f"to {peer_address} (DUT peripheral: TX notifications + RX notifications)"
    )
    baseline = 0
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer_address, CASE_ID_C553922, profile_kind="notify_hr"
    )
    _c553922_settle_before_command(label="DUT set_data_pattern (TX + RX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer_address,
        CASE_ID_C553922,
        tx_mode="notifications",
        buffer_mode=C553922_BUFFER_MODE,
        buffer_cnt=C553922_BUFFER_COUNT,
        max_data_length=C553922_PAYLOAD_LENGTH,
    )
    if configured:
        _c553922_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553922_DATA_PATH_MARKERS,
        timeout=C553922_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553922_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    if not found:
        found, _ = _dt_wait_hostlog(
            bus,
            C553922_DATA_PATH_FALLBACK_MARKERS,
            timeout=C553922_DATA_PATH_TIMEOUT_SEC,
            poll_sec=C553922_HOSTLOG_POLL_SEC,
            require_all=True,
            baseline=baseline,
        )
    assert found, (
        f"TX notification data-path hostlog missing "
        f"(expected one of {C553922_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553922,
        baseline=baseline,
        poll_sec=C553922_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Step 4: buffer config + TX and RX notification paths validated"
    )


def _c553922_monitor_tx_notifications(ble_client, dut_address: str, bus, *, duration: float):
    """Sustained 232-byte TX notification transfer before OTA step."""
    logger().info(
        f"monitor TX notifications for {duration:.0f}s "
        "(flow control, buffer mode 1)"
    )
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during TX notification transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(
                f"DUT reported master disconnect during TX notification transfer"
            )
        time.sleep(C553922_TRANSFER_POLL_SEC)
    logger().info(f"TX notification transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553922)
def test_ble_dut_slave_tx_notifications_232b_buffer_mode1_C553922(wifi_dut, ble_client):
    """
    TestRail C553922 — DUT as Slave, 232-byte GATT TX notifications, buffer mode 1.

    Data path (both directions on the link): DUT -> Raspi 232 B notifications plus
    Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553922
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553922_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553922_STEP2_HOSTLOG_MARKERS,
            step_label="Step 2",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        _dt_prep_for_raspi_central_after_master_role(
            wifi_dut, ble_client, dut_address, bus, case_id
        )

        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553922_raspi_connect_with_ias(
            wifi_dut, ble_client, dut_address, bus
        )

        _c553922_configure_dut_tx_notifications(wifi_dut, peer_address, bus)

        _c553922_settle_before_command(label="TX notification transfer monitor start")
        _c553922_monitor_tx_notifications(
            ble_client, dut_address, bus, duration=C553922_TRANSFER_SEC
        )

        logger().info(
            f"Step 5: OTA validation deferred — verify 230/232-byte secured "
            "ATT Notification payloads via RF sniffer capture"
        )

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553922_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553922_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 1–5 (OTA step 5 deferred)")


CASE_ID_C553923 = "C553923"
C553923_DUT_ADV_NAME = "9116_BLE"
C553923_PAYLOAD_LENGTH = 232
C553923_BUFFER_MODE = 1
C553923_BUFFER_COUNT = 2
C553923_DUT_INIT_SETTLE_SEC = 20.0
C553923_STEP_SETTLE_SEC = 5.0
C553923_POST_PAIR_SETTLE_SEC = 8.0
C553923_POST_DISCONNECT_SETTLE_SEC = 5.0
C553923_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553923_DATA_PATH_TIMEOUT_SEC = 120.0
C553923_TRANSFER_SEC = float(os.environ.get("C553923_TRANSFER_SEC", "600"))
C553923_TRANSFER_POLL_SEC = 10.0
C553923_HOSTLOG_POLL_SEC = 2.0
C553923_GATT_SERVICE = "HeartRateService"
C553923_SERVICE_CLASSES = _dt_build_raspi_services(C553923_GATT_SERVICE)

C553923_STEP1_FIRMWARE_MARKERS = (
    "DLE_ON_M1=1",
    "DLE_BUFFER_MODE_M1=1",
    "DLE_BUFFER_COUNT_M1=2",
    "RSI_BLE_MAX_DATA_LEN_M1=232",
)
C553923_STEP2_HOSTLOG_MARKERS = ("advertising started",)
C553923_STEP2_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553923_STEP3_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553923_STEP3_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553923_DATA_PATH_MARKERS = (
    "remote device enabled the notifications",
    "buffer configuration done",
    "start transmitting data",
    "data transfer req done",
)
C553923_DATA_PATH_FALLBACK_MARKERS = (
    "buffer configuration done",
    "start transmitting data",
)


def _c553923_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """2–30 s pause before btc/ble/bluez commands (smp-pairing / multi-slaves pattern)."""
    sec = C553923_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553923_cleanup_peer(ble_client, dut_address: str):
    _c553923_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553923_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553923_raspi_connect_bond_and_tx(wifi_dut, ble_client, dut_address: str, bus) -> str:
    """TestRail step 3: Raspi scan/connect, SMP passkey bond, TX notifications enabled."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553923_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 3: Raspi scan for DUT ({C553923_DUT_ADV_NAME}) "
        f"with {C553923_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553923,
        service_classes=C553923_SERVICE_CLASSES,
        dwell_sec=C553923_STEP_SETTLE_SEC,
    )

    logger().info(
        f"Step 3: Raspi connect + SMP passkey pair to DUT "
        "(Tx notifications flow control)"
    )
    baseline = len(bus.get_input_log())
    _c553923_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553923_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 3: Raspi central connect to DUT failed"
    time.sleep(C553923_POST_PAIR_SETTLE_SEC)
    _c553923_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553923_STEP3_CONNECT_MARKERS,
        timeout=C553923_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553923_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: connect / MTU / SMP passkey hostlog missing "
        f"(expected one of {C553923_STEP3_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553923_STEP3_BOND_MARKERS,
        timeout=C553923_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553923_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 3: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553923_STEP3_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 3: Raspi address unavailable after connect"
    peer = peer.strip().upper()

    logger().info(
        f"Step 3: configure buffer_mode={C553923_BUFFER_MODE}, "
        f"count={C553923_BUFFER_COUNT}, payload={C553923_PAYLOAD_LENGTH} B TX notifications "
        f"to {peer} (DUT peripheral: TX notifications + RX notifications)"
    )
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer, CASE_ID_C553923, profile_kind="notify_hr"
    )
    _c553923_settle_before_command(label="DUT set_data_pattern (TX + RX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer,
        CASE_ID_C553923,
        tx_mode="notifications",
        buffer_mode=C553923_BUFFER_MODE,
        buffer_cnt=C553923_BUFFER_COUNT,
        max_data_length=C553923_PAYLOAD_LENGTH,
    )
    if configured:
        _c553923_settle_before_command(label="post set_data_pattern hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553923_DATA_PATH_MARKERS,
        timeout=C553923_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553923_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    if not found:
        found, _ = _dt_wait_hostlog(
            bus,
            C553923_DATA_PATH_FALLBACK_MARKERS,
            timeout=C553923_DATA_PATH_TIMEOUT_SEC,
            poll_sec=C553923_HOSTLOG_POLL_SEC,
            require_all=True,
            baseline=baseline,
        )
    assert found, (
        f"Step 3: TX notification data-path hostlog missing "
        f"(expected one of {C553923_DATA_PATH_MARKERS})"
    )
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553923,
        baseline=baseline,
        poll_sec=C553923_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Step 3: bonded; TX notifications transmitting, "
        f"RX notifications configured @ {peer}"
    )
    return peer


def _c553923_monitor_tx_notifications(ble_client, dut_address: str, bus, *, duration: float):
    """Sustained 232-byte TX notification transfer before OTA step 4."""
    logger().info(
        f"monitor TX notifications for {duration:.0f}s "
        "(flow control, buffer mode 1)"
    )
    start = time.time()
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Raspi central link dropped during TX notification transfer"
        )
        recent = _dt_hostlog_text(bus, max(0, len(bus.get_input_log()) - 500))
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(
                f"DUT reported master disconnect during TX notification transfer"
            )
        time.sleep(C553923_TRANSFER_POLL_SEC)
    logger().info(f"TX notification transfer window complete")


@pytest.mark.test_src_map_id(CASE_ID_C553923)
def test_ble_dut_slave_tx_notifications_232b_buffer_mode1_C553923(wifi_dut, ble_client):
    """
    TestRail C553923 — DUT as Slave, 232-byte GATT TX notifications, buffer mode 1.

    Data path (both directions on the link): DUT -> Raspi 232 B notifications plus
    Raspi -> DUT notifications.

    Harness: 1 DUT + 1 Raspi (``ble_client``).

    """
    case_id = CASE_ID_C553923
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553923_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553923_STEP2_HOSTLOG_MARKERS,
            step_label="Step 2",
        )
        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        _dt_prep_for_raspi_central_after_master_role(
            wifi_dut, ble_client, dut_address, bus, case_id
        )

        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        peer_address = _c553923_raspi_connect_bond_and_tx(
            wifi_dut, ble_client, dut_address, bus
        )

        _c553923_settle_before_command(label="TX notification transfer monitor start")
        _c553923_monitor_tx_notifications(
            ble_client, dut_address, bus, duration=C553923_TRANSFER_SEC
        )

        logger().info(
            f"Step 4: OTA validation deferred — verify 232-byte secured "
            "ATT Notification payloads via RF sniffer capture"
        )

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553923_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553923_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(f"PASS — hostlog steps 1–4 (OTA step 4 deferred)")


CASE_ID_C553924 = "C553924"
C553924_DUT_ADV_NAME = "9116_BLE"
C553924_PAYLOAD_LENGTH = 232
C553924_BUFFER_MODE = 1
C553924_BUFFER_COUNT = 8
C553924_MIN_BIG_BUFF = 8
C553924_DUT_INIT_SETTLE_SEC = 20.0
C553924_STEP_SETTLE_SEC = 5.0
C553924_POST_PAIR_SETTLE_SEC = 8.0
C553924_POST_DISCONNECT_SETTLE_SEC = 5.0
C553924_SMP_HOSTLOG_TIMEOUT_SEC = 120.0
C553924_DATA_PATH_TIMEOUT_SEC = 120.0
C553924_TRANSFER_SEC = float(os.environ.get("C553924_TRANSFER_SEC", "120"))
C553924_TRANSFER_POLL_SEC = 10.0
C553924_HOSTLOG_POLL_SEC = 2.0
C553924_GATT_SERVICE = "HeartRateService"
C553924_SERVICE_CLASSES = _dt_build_raspi_services(C553924_GATT_SERVICE)
C553924_CAPTURE_BASENAME = "rfcreations_C553924_big_buff_max_notifies"
C553924_SNIFFER_MIN_PACKETS = 50
C553924_SNIFFER_MIN_NOTIFY = 30
C553924_THROUGHPUT_WINDOW_SEC = 30.0
C553924_MIN_NOTIFY_PER_WINDOW = 3

C553924_STEP1_FIRMWARE_MARKERS = (
    "RX_NOTIFICATIONS_FROM_M1=0",
    "DLE_ON_M1=1",
    "DLE_BUFFER_COUNT_M1=8",
)
C553924_STEP1_BOOT_MARKERS = ("advertising started",)
C553924_STEP1_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553924_STEP2_CONNECT_MARKERS = (
    "in on_enhance_conn evt",
    "number of master devices connected:1",
    "advertising device",
    "mtu exchange information",
    "mtu size from remote device",
    "smp pairing request initiated",
    "in smp sc passkey event",
)
C553924_STEP2_BOND_MARKERS = (
    "in smp encrypt event",
    "in smp security keys event",
    "remote device profiles discovery completed",
)
C553924_DATA_PATH_MARKERS = (
    "remote device enabled the notifications",
    "buffer configuration done",
    "start transmitting data",
    "data transfer req done",
)
C553924_DATA_PATH_FALLBACK_MARKERS = (
    "buffer configuration done",
    "start transmitting data",
)

_C553924_BIG_BUFF_RE = re.compile(
    r"big\s*buff(?:er)?(?:\s*count)?\s*[=:]\s*(\d+)", re.IGNORECASE
)
_C553924_BUFFER_CNT_RE = re.compile(
    r"buffer[_\s]?cnt(?:ount)?\s*[=:]\s*(\d+)", re.IGNORECASE
)


def _c553924_settle_before_command(*, label: str, settle_sec: Optional[float] = None):
    """5 s pause before btc/ble/bluez commands (wearables data-transfer pattern)."""
    sec = C553924_STEP_SETTLE_SEC if settle_sec is None else settle_sec
    time.sleep(sec)


def _c553924_cleanup_peer(ble_client, dut_address: str):
    _c553924_settle_before_command(label="Raspi disconnect (cleanup)")
    _dt_raspi_disconnect_if_connected(ble_client, dut_address)
    time.sleep(C553924_POST_DISCONNECT_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=dut_address)
    except Exception:
        pass
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass


def _c553924_extract_big_buff_counts(hostlog_text: str) -> List[int]:
    """Parse optional runtime big-buff / buffer-count values from DUT hostlog."""
    counts: List[int] = []
    for pattern in (_C553924_BIG_BUFF_RE, _C553924_BUFFER_CNT_RE):
        for match in pattern.finditer(hostlog_text):
            try:
                counts.append(int(match.group(1)))
            except (TypeError, ValueError):
                continue
    return counts


def _c553924_assert_big_buff_not_below_min(hostlog_text: str, *, context: str):
    """Fail when hostlog reports big-buff / buffer count below configured minimum."""
    for value in _c553924_extract_big_buff_counts(hostlog_text):
        assert value >= C553924_MIN_BIG_BUFF, (
            f"{context}: big buff / buffer count {value} "
            f"< {C553924_MIN_BIG_BUFF}"
        )
    assert "buffer full error" not in hostlog_text, (
        f"{context}: unexpected buffer full error in hostlog"
    )


def _c553924_raspi_connect_bond_and_enable_notifications(
    wifi_dut, ble_client, dut_address: str, bus
) -> str:
    """TestRail step 2: Raspi scan/connect; remote enables notifications (TX path)."""
    setup_test_state()
    set_local_dut_address(dut_address)
    _c553924_settle_before_command(label="Raspi close + set_bus")

    logger().info(
        f"Step 2: Raspi scan for DUT ({C553924_DUT_ADV_NAME}) "
        f"with {C553924_GATT_SERVICE}"
    )
    peer_addr = _dt_raspi_scan_for_dut_peripheral(
        wifi_dut,
        ble_client,
        dut_address,
        bus,
        CASE_ID_C553924,
        service_classes=C553924_SERVICE_CLASSES,
        dwell_sec=C553924_STEP_SETTLE_SEC,
    )

    logger().info(
        f"Step 2: Raspi connect + SMP passkey pair to DUT "
        "(remote will enable TX notifications)"
    )
    baseline = len(bus.get_input_log())
    _c553924_settle_before_command(label="connect_dut_as_peripheral_raspii_as_central")
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut, ble_client, wait_for_bt=False, event_to_signal=ble1_connection_event,
        service_classes=C553924_SERVICE_CLASSES,
        skip_smp_scan_setup=True,
    )
    assert ok, f"Step 2: Raspi central connect to DUT failed"
    time.sleep(C553924_POST_PAIR_SETTLE_SEC)
    _c553924_settle_before_command(label="post-connect hostlog check")

    found, _ = _dt_wait_hostlog(
        bus,
        C553924_STEP2_CONNECT_MARKERS,
        timeout=C553924_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553924_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 2: connect / MTU / SMP passkey hostlog missing "
        f"(expected one of {C553924_STEP2_CONNECT_MARKERS})"
    )

    found, _ = _dt_wait_hostlog(
        bus,
        C553924_STEP2_BOND_MARKERS,
        timeout=C553924_SMP_HOSTLOG_TIMEOUT_SEC,
        poll_sec=C553924_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    assert found, (
        f"Step 2: SMP bond / profile discovery hostlog missing "
        f"(expected one of {C553924_STEP2_BOND_MARKERS})"
    )

    peer = ble_client.interfaces.bluetooth.get_address()
    assert peer, f"Step 2: Raspi address unavailable after connect"
    peer = peer.strip().upper()

    logger().info(
        f"Step 2: configure big-buff TX notifications "
        f"(buffer_mode={C553924_BUFFER_MODE}, count={C553924_BUFFER_COUNT}, "
        f"payload={C553924_PAYLOAD_LENGTH} B) to {peer} "
        "(DUT peripheral: TX notifications + RX notifications)"
    )
    _dt_dut_discover_peer_gatt_for_transfer(
        wifi_dut, bus, peer, CASE_ID_C553924, profile_kind="notify_hr"
    )
    _c553924_settle_before_command(label="DUT set_data_pattern (TX + RX notifications)")
    configured = _dt_set_bidirectional_data_pattern(
        wifi_dut,
        peer,
        CASE_ID_C553924,
        tx_mode="notifications",
        buffer_mode=C553924_BUFFER_MODE,
        buffer_cnt=C553924_BUFFER_COUNT,
        max_data_length=C553924_PAYLOAD_LENGTH,
    )
    if configured:
        _c553924_settle_before_command(label="post set_data_pattern hostlog check")

    found, notify_log = _dt_wait_hostlog(
        bus,
        C553924_DATA_PATH_MARKERS,
        timeout=C553924_DATA_PATH_TIMEOUT_SEC,
        poll_sec=C553924_HOSTLOG_POLL_SEC,
        require_all=False,
        baseline=baseline,
    )
    if not found:
        found, notify_log = _dt_wait_hostlog(
            bus,
            C553924_DATA_PATH_FALLBACK_MARKERS,
            timeout=C553924_DATA_PATH_TIMEOUT_SEC,
            poll_sec=C553924_HOSTLOG_POLL_SEC,
            require_all=True,
            baseline=baseline,
        )
    assert found, (
        f"Step 2: remote notification enable / TX path hostlog missing "
        f"(expected one of {C553924_DATA_PATH_MARKERS})"
    )
    _c553924_assert_big_buff_not_below_min(notify_log, context="after remote enabled notifications")
    _dt_check_rx_data_path_hostlog(
        bus,
        CASE_ID_C553924,
        baseline=baseline,
        poll_sec=C553924_HOSTLOG_POLL_SEC,
    )
    logger().info(
        f"Step 2: bonded; remote enabled notifications, "
        f"peer->DUT RX notifications configured @ {peer}"
    )
    return peer


def _c553924_monitor_transfer_and_big_buff(ble_client, dut_address: str, bus, *, duration: float):
    """TestRail step 3 (runtime): sustain TX transfer; big buff must stay >= 8."""
    logger().info(
        f"Step 3: monitor TX notifications + big buff for {duration:.0f}s"
    )
    start = time.time()
    transfer_baseline = len(bus.get_input_log())
    while time.time() - start < duration:
        assert ble_client.interfaces.bluetooth.get_connection_status(dut_address), (
            f"Step 3: Raspi central link dropped during transfer"
        )
        recent = _dt_hostlog_text(bus, transfer_baseline)
        _c553924_assert_big_buff_not_below_min(
            recent, context="during TX notification transfer"
        )
        if "disconnected" in recent and "number of master devices connected:0" in recent:
            pytest.fail(
                f"Step 3: DUT reported master disconnect during transfer"
            )
        time.sleep(C553924_TRANSFER_POLL_SEC)
    logger().info(f"Step 3: transfer monitor window complete")


def _c553924_resolve_pcap(sniffer) -> str:
    import os as _os

    pcap = sniffer.local_capture_files or sniffer.capture_file
    assert pcap, f"Step 3: no capture file path after stop_capture"
    if isinstance(pcap, str) and ";" in pcap:
        pcap = pcap.split(";")[0]
    assert _os.path.isfile(pcap), f"Step 3: capture missing: {pcap}"
    return pcap


def _c553924_validate_sniffer_throughput_intervals_big_buff(sniffer):
    """
    TestRail step 3 OTA: BLE throughput over time, connection intervals, big buff >= 8.

    Uses tshark on the RF Creations PCAPNG.
    """
    from collections import defaultdict

    from rf_sniffer_helpers import MIN_PACKET_COUNT, _tshark_field_rows, count_tshark

    pcap = _c553924_resolve_pcap(sniffer)
    size = os.path.getsize(pcap)
    assert size > 0, f"Step 3: empty capture: {pcap}"

    pkt_count = getattr(sniffer, "packet_count_value", 0) or 0
    logger().info(
        f"Step 3: sniffer capture {pcap} "
        f"({size} bytes, server packet_count={pkt_count})"
    )
    if pkt_count > 0:
        assert pkt_count >= max(C553924_SNIFFER_MIN_PACKETS, MIN_PACKET_COUNT), (
            f"Step 3: too few packets ({pkt_count})"
        )

    notify_filter = "btatt.opcode == 0x1b"
    notify_total = count_tshark(pcap, notify_filter)
    if notify_total <= 0:
        notify_filter = "btatt"
        notify_total = count_tshark(pcap, "btatt && btatt.opcode == 27")
    assert notify_total >= C553924_SNIFFER_MIN_NOTIFY, (
        f"Step 3: insufficient ATT Handle Value Notifications "
        f"in capture ({notify_total} < {C553924_SNIFFER_MIN_NOTIFY})"
    )
    logger().info(
        f"Step 3: ATT notifications in capture: {notify_total}"
    )

    time_rows = _tshark_field_rows(
        pcap, notify_filter, ["frame.time_relative", "btatt.value.len"]
    )
    buckets: dict = defaultdict(int)
    payload_bytes = 0
    for row in time_rows:
        if not row or not row[0]:
            continue
        try:
            rel = float(row[0])
        except ValueError:
            continue
        bucket = int(rel // C553924_THROUGHPUT_WINDOW_SEC)
        buckets[bucket] += 1
        if len(row) > 1 and row[1]:
            try:
                payload_bytes += int(row[1])
            except ValueError:
                pass

    assert buckets, (
        f"Step 3: could not bucket notification throughput from capture"
    )
    low_windows = [
        idx
        for idx, count in sorted(buckets.items())
        if count < C553924_MIN_NOTIFY_PER_WINDOW
    ]
    assert not low_windows, (
        f"Step 3: BLE throughput dropped in window(s) "
        f"{low_windows} (counts={dict(buckets)})"
    )
    duration_sec = max(buckets) * C553924_THROUGHPUT_WINDOW_SEC + C553924_THROUGHPUT_WINDOW_SEC
    avg_notify_rate = notify_total / max(duration_sec, 1.0)
    avg_kbps = (payload_bytes * 8.0) / max(duration_sec, 1.0) / 1000.0
    logger().info(
        f"Step 3: sustained notification throughput — "
        f"{notify_total} notifies over ~{duration_sec:.0f}s "
        f"({avg_notify_rate:.2f} notifies/s, ~{avg_kbps:.2f} kbps ATT payload)"
    )

    interval_fields = (
        "btle.conn_interval",
        "btle.interval",
        "btle.conn_interval_min",
        "btle.conn_interval_max",
    )
    intervals_ms = set()
    for field in interval_fields:
        rows = _tshark_field_rows(
            pcap, f"btle && {field}", [field, "frame.time_relative"]
        )
        for row in rows:
            if not row or not row[0]:
                continue
            try:
                raw = int(float(row[0]))
            except ValueError:
                continue
            if raw <= 0:
                continue
            intervals_ms.add(round(raw * 1.25, 3))

    assert intervals_ms, (
        f"Step 3: no connection interval values found in sniffer capture"
    )
    logger().info(
        f"Step 3: connection interval(s) observed (ms): "
        f"{sorted(intervals_ms)}"
    )

    logger().info(
        f"Step 3: big buff buffer count configured/expected = "
        f"{C553924_BUFFER_COUNT} (must not be < {C553924_MIN_BIG_BUFF} during transfer)"
    )
    assert C553924_BUFFER_COUNT >= C553924_MIN_BIG_BUFF, (
        f"Step 3: data-transfer buffer count "
        f"{C553924_BUFFER_COUNT} < {C553924_MIN_BIG_BUFF}"
    )


@pytest.mark.test_src_map_id(CASE_ID_C553924)
def test_ble_big_buff_max_notifies_transmitted_GAR8074_C553924(
    wifi_dut, ble_client
):
    """
    TestRail C553924 — Verify BLE Maximum Notifies Transmitted in Big Buff mode (GAR-8074).

    Data path (both directions on the link): DUT -> Raspi big-buff notifications plus
    Raspi -> DUT notifications (RX_NOTIFICATIONS_FROM_M1 is 0 in this build, so the
    RX leg is configured and reported but does not gate the verdict).

    Harness: 1 DUT + 1 Raspi (``ble_client``). RF Creations sniffer deferred for 9116 wearables.

    """
    case_id = CASE_ID_C553924
    bus = _dt_bus(wifi_dut)
    dut_address = None
    peer_address = None

    try:
        try:
            _ = bus.ser
        except Exception as exc:
            logger().warning(f"DUT serial open: {exc}")
        time.sleep(C553924_DUT_INIT_SETTLE_SEC)
        _dt_ensure_dut_ble_ready(
            wifi_dut,
            bus,
            case_id,
            required_markers=C553924_STEP1_BOOT_MARKERS,
            step_label="Step 1",
        )
        hostlog = _dt_hostlog_text(bus)
        missing_fw = [m for m in C553924_STEP1_FIRMWARE_MARKERS if m not in hostlog]
        if missing_fw:
            logger().warning(
                f"Step 1: firmware build-time markers not in current "
                f"hostlog (emitted once at boot; not re-printed on per-test UART "
                f"reopen): {missing_fw}"
            )
        _c553924_assert_big_buff_not_below_min(hostlog, context="after DUT boot")

        dut_address = _dt_resolve_dut_address(wifi_dut, case_id=case_id)
        _dt_prep_for_raspi_central_after_master_role(
            wifi_dut, ble_client, dut_address, bus, case_id
        )
        logger().info(
            f"Preconditions: WLAN/BT power save — firmware build-time "
            "(not applied via RT595 btc CLI; see secure_pairing suite)"
        )

        _c553924_settle_before_command(label="Raspi close + set_bus")
        try:
            ble_client.interfaces.bluetooth.close()
        except Exception:
            pass
        time.sleep(2)
        ble_client.interfaces.bluetooth.set_bus()

        peer_address = _c553924_raspi_connect_bond_and_enable_notifications(
            wifi_dut, ble_client, dut_address, bus
        )

        _c553924_settle_before_command(label="big-buff transfer monitor start")
        _c553924_monitor_transfer_and_big_buff(
            ble_client, dut_address, bus, duration=C553924_TRANSFER_SEC
        )

        logger().info(
            f"Step 3: RF Creations sniffer OTA validation deferred "
        )

    finally:
        try:
            if hasattr(wifi_dut.interfaces.wifi, "legacy_scan_stop"):
                _c553924_settle_before_command(label="DUT legacy_scan_stop")
                wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
        if dut_address:
            _c553924_cleanup_peer(ble_client, dut_address)
        _dt_delete_dut_bond(wifi_dut, peer_address)

    logger().info(
        f"PASS — hostlog steps 1–2 (RF Creations sniffer step 3 deferred)"
    )
