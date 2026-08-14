import time
import pytest
import threading
import re
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xBLEFeatureBitMap
)
from utf.utils import print_dict
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez import Bluez
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth import BLEDeviceState
"""
    setup requirement:
        1. DUT(917-SDK) -- 10 devices (8 peripherals + 2 centrals)
        2. Raspberry PI4

        Test Steps:
        1. Initiates the DUT Coex wlan and BLE
        2. Connect slave-1, start notify thread for slave-1
        3. Pause all notifs, connect slave-2, resume notifs on slave-1 & slave-2 in parallel
        4. Repeat until all 10 connections are up with parallel notifications
        5. Run all notifications for 20 minutes
        6. Disconnect all

    Author: Harsha / Ravi Nemali
"""


def logger():
    return get_logger(__name__)

def _start_ble_sniffer_capture(ble_sniffer, capture_file):
    logger().info("Connecting to BLE sniffer...")
    ble_sniffer.interfaces.sniffer.connect()
    time.sleep(5)  # Capture for 5 seconds
    logger().info("Starting BLE sniffer capture...")
    ble_sniffer.interfaces.sniffer.start_capture()


def _stop_ble_sniffer_capture(ble_sniffer):
    try:
        logger().info("Stopping BLE sniffer capture...")
        ble_sniffer.interfaces.sniffer.stop_capture()
    except Exception as err:
        logger().warning(f"Failed to stop BLE sniffer capture cleanly: {err}")


def _run_with_ble_sniffer_capture(ble_sniffer, capture_file, run_fn):
    capture_started = False
    try:
        _start_ble_sniffer_capture(ble_sniffer, capture_file=capture_file)
        capture_started = True
        return run_fn()
    finally:
        if capture_started:
            _stop_ble_sniffer_capture(ble_sniffer)

def _parse_ble_device_state(raw):
    if raw is None or isinstance(raw, bool):
        return -1
    if isinstance(raw, int):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = raw.decode('ascii', errors='ignore')
        except Exception:
            return -1
    else:
        text = str(raw)
    match = re.search(r'-?\d+', text)
    if not match:
        return -1
    try:
        return int(match.group(0))
    except ValueError:
        return -1
        
def wait_for_dut_ble_connected(ble_dut, label, timeout_sec=90, poll_interval_sec=2.0):
    deadline = time.time() + timeout_sec
    last_state = None
    saw_connected_bit = False
    state_int = -1
    while time.time() < deadline:
        raw = ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = _parse_ble_device_state(raw)
        if state_int != last_state:
            logger().info(f"{label}: DUT BLE state = {state_int} (raw={raw!r})")
            last_state = state_int
        if state_int >= 0 and (state_int & BLEDeviceState.Connected):
            saw_connected_bit = True
        if state_int == BLEDeviceState.Connected:
            return state_int
        time.sleep(poll_interval_sec)
    raise AssertionError(
        f"{label}: DUT BLE state did not settle at Connected (8) within "
        f"{timeout_sec}s; last state = {state_int}; "
        f"connected_bit_ever_seen = {saw_connected_bit}"
    )

def _capture_dut_passkey_and_inject(ble_dut, remote_client, timeout_sec: int = 60):
    wifi_iface = ble_dut.interfaces.wifi
    byte_pattern = re.compile(rb"passkey:\s*(\d+)")
    try:
        baseline_idx = len(wifi_iface.bus.get_input_log())
    except Exception:
        baseline_idx = 0
    seen_record_idx = baseline_idx
    events_since = getattr(wifi_iface, "last_retrieved_event_timestamp", 0)
    tw = Stopwatch()
    while tw.elapsed_sec < timeout_sec:
        passkey = None
        try:
            events = wifi_iface.get_async_events(
                since_time=events_since,
                update_last_retrieved_timestamp=False,
            )
        except TypeError:
            events = wifi_iface.get_async_events()
        except Exception as err:
            logger().warning(f"get_async_events failed while capturing passkey: {err}")
            events = []
        for event in events:
            event_data = getattr(event, "event_data", None) or ""
            if isinstance(event_data, bytes):
                event_data = event_data.decode(errors="ignore")
            match = re.search(r"passkey:\s*(\d+)", event_data)
            if match:
                passkey = match.group(1)
                break

        if not passkey:
            try:
                records = wifi_iface.bus.get_input_log()
            except Exception as err:
                logger().warning(f"bus.get_input_log() failed while capturing passkey: {err}")
                records = []
            new_records = records[seen_record_idx:]
            seen_record_idx = len(records)
            for entry in new_records:
                # Records are typically (timestamp, bytes). Defensive shape.
                raw = entry[1] if isinstance(entry, tuple) and len(entry) >= 2 else entry
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                if b"passkey" not in raw:
                    continue
                match = byte_pattern.search(raw)
                if match:
                    passkey = match.group(1).decode(errors="ignore")
                    break

        if passkey:
            logger().info(f"Captured DUT-displayed passkey: {passkey}")
            remote_client.interfaces.bluetooth.set_pin(pin_code=passkey)
            return passkey
        time.sleep(1)
    logger().error(f"Failed to capture DUT-displayed passkey within {timeout_sec}s")
    return None


def _pair_and_connect_with_retry(central_iface, dev_addr: str, total_timeout_sec: int = 180, retry_interval_sec: int = 8,):
    deadline = time.time() + total_timeout_sec
    attempt = 0
    last_err = None
    while time.time() < deadline:
        attempt += 1
        try:
            ok = central_iface.pair_and_connect(dev_addr)
            if ok:
                logger().info(
                    f"pair_and_connect succeeded for {dev_addr} on attempt {attempt}"
                )
                return True
            logger().info(
                f"pair_and_connect attempt {attempt} returned False for {dev_addr} "
                f"(device likely not yet discovered by BlueZ); retrying in "
                f"{retry_interval_sec}s"
            )
        except Exception as err:
            last_err = err
            logger().warning(
                f"pair_and_connect attempt {attempt} raised for {dev_addr}: {err}; "
                f"retrying in {retry_interval_sec}s"
            )
        time.sleep(retry_interval_sec)
    logger().error(
        f"pair_and_connect gave up for {dev_addr} after {attempt} attempts "
        f"(last error: {last_err})"
    )
    return False


def _validate_dut_central_link(
    ble_dut,
    central_address,
    c_idx,
    *,
    ble_conn_interval_min=96,
    ble_conn_interval_max=96,
    ble_conn_latency=0,
    ble_supervision_timeout=400,
):
    try:
        ble_dut.interfaces.bluetooth.ble_update_conn_param(
            ble_remote_dev_address=central_address,
            ble_conn_interval_min=ble_conn_interval_min,
            ble_conn_interval_max=ble_conn_interval_max,
            ble_conn_latency=ble_conn_latency,
            ble_supervision_timeout=ble_supervision_timeout,
        )
        logger().info(
            f"Central-{c_idx + 1}: link validated via conn-param update "
            f"(attempt confirmed stable)"
        )
        return True
    except Exception as err:
        logger().warning(
            f"Central-{c_idx + 1}: link validation failed for {central_address} "
            f"(likely 0x04D05 socket-not-available, FW already tore link down "
            f"with 0x4e08/0x4e3e): {err}"
        )
        return False


def _cleanup_central_bluetooth_session(central, label):
    try:
        central.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        central.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    try:
        central.interfaces.bluetooth.close()
    except Exception as err:
        logger().info(f"{label}: BlueZ cleanup raised (continuing): {err}")

def _restart_central_bluetooth_stack(central, label):
    try:
        central.interfaces.bluetooth.restart(
            restart_dbus=False,
            experimental=True,
            compact=False,
            restart_bt_service=True,
        )
        logger().info(f"{label}: restarted central Bluetooth service")
    except TypeError:
        try:
            central.interfaces.bluetooth.restart()
            logger().info(f"{label}: restarted central Bluetooth service")
        except Exception as err:
            logger().warning(f"{label}: Bluetooth restart failed: {err}")
    except Exception as err:
        logger().warning(f"{label}: Bluetooth restart failed: {err}")


def _start_central_smp_scan_with_recovery(central, scan_kwargs, *, c_idx, attempt, max_attempts):
    last_err = None
    for scan_try in range(1, 4):
        try:
            central.interfaces.bluetooth.start_smp_scan(**scan_kwargs)
            return
        except Exception as err:
            last_err = err
            err_text = str(err)
            is_stale_handler = (
                isinstance(err, KeyError)
                or "already a handler" in err_text
                or "object-path handler" in err_text
                or "utf_agent" in err_text
            )
            if is_stale_handler:
                logger().warning(
                    f"Central-{c_idx + 1}: start_smp_scan hit stale handler state "
                    f"on attempt {attempt}/{max_attempts}, scan try {scan_try}/3: {err}"
                )
            else:
                logger().warning(
                    f"Central-{c_idx + 1}: start_smp_scan failed "
                    f"on attempt {attempt}/{max_attempts}, scan try {scan_try}/3: {err}"
                )
            _cleanup_central_bluetooth_session(
                central,
                f"Central-{c_idx + 1} start_smp_scan recovery cleanup",
            )
            time.sleep(5)
            _restart_central_bluetooth_stack(
                central,
                f"Central-{c_idx + 1} stale scan handler recovery",
            )
            time.sleep(3)
    raise last_err


BACKGROUND_TX_TIME = 0x0780
BACKGROUND_BUFFER_MODE = 1
BACKGROUND_BUFFER_COUNT = 2
PERIPHERAL_FAST_CI = 160   # 200 ms
PERIPHERAL_SLOW_CI = 240   # 300 ms
CENTRAL_1_CI = 36          # 45 ms
CENTRAL_2_CI = 400         # 500 ms
CONN_LATENCY = 0
SUPERVISION_TIMEOUT = 800


def _peripheral_ci_for_index(idx):
    if idx < 4:
        return PERIPHERAL_FAST_CI
    return PERIPHERAL_SLOW_CI


def _central_ci_for_index(c_idx):
    if c_idx == 0:
        return CENTRAL_1_CI
    return CENTRAL_2_CI


def _configure_background_payload_for_conn(bt_iface, conn_id, payload_len):
    bt_iface.unified_ble_payload_config(
        conn_id=conn_id,
        payload_len=payload_len,
        tx_time=BACKGROUND_TX_TIME,
        buffer_mode=BACKGROUND_BUFFER_MODE,
        buffer_count=BACKGROUND_BUFFER_COUNT,
    )


def _configure_background_wwr_transfer_for_conn(bt_iface, conn_id):
    bt_iface.unified_ble_transfer_config(
        conn_id=conn_id,
        mode=0,
        acl_tx_disable=0,
        acl_rx_disable=0,
        acl_rx_on_data_len=1,
        acl_rx_off_data_len=0,
        acl_tx_on_data_len=0,
        tx_on=1,
        tx_rx_mode=1,
        tx_phy=1,
        rx_phy=1,
        coded_phy=0,
    )


def _uint16_to_le_hex_string(value):
    return f"0x{value & 0xFF:02X} 0x{(value >> 8) & 0xFF:02X}"


def _update_central_live_conn_params(
    central_device,
    dut_addr,
    remote_addr,
    target_ci,
    bt_iface,
    conn_latency=None,
    supervision_timeout=None,
):
    if conn_latency is None:
        conn_latency = CONN_LATENCY
    if supervision_timeout is None:
        supervision_timeout = SUPERVISION_TIMEOUT
    ci_hex = _uint16_to_le_hex_string(target_ci)
    latency_hex = _uint16_to_le_hex_string(conn_latency)
    supervision_timeout_hex = _uint16_to_le_hex_string(supervision_timeout)
    central_device.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
        dev_addr=dut_addr,
        connection_interval_min=ci_hex,
        connection_interval_max=ci_hex,
        max_latency=latency_hex,
        supervision_timeout=supervision_timeout_hex,
    )
    time.sleep(1)
    bt_iface.ble_update_conn_param(
        ble_remote_dev_address=remote_addr,
        ble_conn_interval_min=target_ci,
        ble_conn_interval_max=target_ci,
        ble_conn_latency=conn_latency,
        ble_supervision_timeout=supervision_timeout,
    )



def _enable_power_save(ble_dut):
    logger().info("Enabling DUT power save before BLE connections")
    enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(
        mode="power_save_low_latency"
    )
    assert enable_wifi_ps == 0, "Failed to enable DUT low-latency power-save profile"
    enable_bt_ps = ble_dut.interfaces.wifi.enable_bt_power_save()
    assert enable_bt_ps == 0, "Failed to enable DUT BT power save"
    time.sleep(2)
    logger().info("DUT power save enabled successfully")


CUSTOM_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
CUSTOM_CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
INDICATE_SERVICE_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
INDICATE_CHAR_UUID = "00001bb1-0000-1000-8000-00805f9b34fb"
PAIR_MODE_NONSECURE = "nonsecure"
PAIR_MODE_DEFAULT = "default"
PAIR_MODE_JUST_WORKS = "justworks"
PAIR_MODE_PASSKEY = "passkey"
PAIR_MODE_NUMERIC = "numeric_comparison"


def _uuid_pair_for_transfer(transfer_config_fn):
    if transfer_config_fn is _configure_background_ind_transfer_for_conn:
        return INDICATE_SERVICE_UUID, INDICATE_CHAR_UUID
    return CUSTOM_SERVICE_UUID, CUSTOM_CHAR_UUID


def _configure_dut_pair_mode(ble_dut, pair_mode):
    if pair_mode == PAIR_MODE_NONSECURE:
        ble_dut.interfaces.bluetooth.ble_set_smp(set_smp=0)
        logger().info("SMP disabled for all connections (non-secure mode)")
        time.sleep(1)
    elif pair_mode == PAIR_MODE_PASSKEY:
        ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=0, mitm=1)
        logger().info("DUT IO Capability set to DisplayOnly (Passkey Entry), MITM=1")
    elif pair_mode == PAIR_MODE_NUMERIC:
        ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
        logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")
        time.sleep(1)


def _peripheral_capability_for_pair_mode(pair_mode):
    if pair_mode == PAIR_MODE_PASSKEY:
        return "KeyboardOnly"
    if pair_mode == PAIR_MODE_JUST_WORKS:
        return "NoInputNoOutput"
    if pair_mode == PAIR_MODE_NUMERIC:
        return "DisplayYesNo"
    return None


def _central_scan_capability_for_pair_mode(pair_mode):
    if pair_mode == PAIR_MODE_NUMERIC:
        return "DisplayYesNo"
    return "NoInputNoOutput"


def _start_peripheral_adv_for_pair_mode(client, bt_dut_address, svc, pair_mode):
    adv_kwargs = {
        "bt_dut_address": bt_dut_address,
        "service_classes": [svc],
    }
    capability = _peripheral_capability_for_pair_mode(pair_mode)
    if capability is not None:
        adv_kwargs["capability"] = capability
    if pair_mode == PAIR_MODE_PASSKEY:
        adv_kwargs["pin_code"] = "-8"
    return client.interfaces.bluetooth.start_smp_adv(**adv_kwargs)


def _configure_background_notify_transfer_for_conn(bt_iface, conn_id):
    bt_iface.unified_ble_transfer_config(
        conn_id=conn_id,
        mode=1,
        acl_tx_disable=0,
        acl_rx_disable=0,
        acl_rx_on_data_len=0,
        acl_rx_off_data_len=0,
        acl_tx_on_data_len=0,
        tx_on=1,
        tx_rx_mode=1,
        tx_phy=1,
        rx_phy=1,
        coded_phy=0,
    )


def _configure_background_wnr_transfer_for_conn(bt_iface, conn_id):
    bt_iface.unified_ble_transfer_config(
        conn_id=conn_id,
        mode=0,
        acl_tx_disable=0,
        acl_rx_disable=0,
        acl_rx_on_data_len=1,
        acl_rx_off_data_len=0,
        acl_tx_on_data_len=0,
        tx_on=1,
        tx_rx_mode=1,
        tx_phy=1,
        rx_phy=1,
        coded_phy=0,
    )


def _configure_background_ind_transfer_for_conn(bt_iface, conn_id):
    bt_iface.unified_ble_transfer_config(
        conn_id=conn_id,
        mode=0,
        acl_tx_disable=1,
        acl_rx_disable=0,
        acl_rx_on_data_len=0,
        acl_rx_off_data_len=0,
        acl_tx_on_data_len=0,
        tx_on=1,
        tx_rx_mode=1,
        tx_phy=1,
        rx_phy=1,
        coded_phy=0,
    )


def _connect_passkey_central_with_retry_extended(
    ble_dut, central, c_idx, bt_dut_address, *, capability="KeyboardOnly", max_attempts=3, service_classes=None
):
    svc = "HealthThermometerService"
    central_address = None
    for attempt in range(1, max_attempts + 1):
        logger().info(
            f"===== Central-{c_idx + 1} connect attempt {attempt}/{max_attempts} (passkey) ====="
        )
        _cleanup_central_bluetooth_session(central, f"Central-{c_idx + 1} pre-scan cleanup")
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_start_advertising(
            ble_adv_int_min=160,
            ble_adv_int_max=320,
        )
        time.sleep(2)
        scan_kwargs = {
            "bt_dut_address": bt_dut_address,
            "pin_code": "-8",
        }
        if capability is not None:
            scan_kwargs["capability"] = capability
        if service_classes is not None:
            scan_kwargs["service_classes"] = service_classes
        else:
            scan_kwargs["service_classes"] = [svc]
        try:
            _start_central_smp_scan_with_recovery(
                central,
                scan_kwargs,
                c_idx=c_idx,
                attempt=attempt,
                max_attempts=max_attempts,
            )
        except Exception as err:
            logger().warning(
                f"Central-{c_idx + 1}: start_smp_scan recovery failed on outer "
                f"attempt {attempt}/{max_attempts}: {err}"
            )
            if attempt < max_attempts:
                try:
                    ble_dut.interfaces.bluetooth.ble_stop_advertising()
                except Exception as stop_err:
                    logger().info(
                        f"Central-{c_idx + 1}: stop_adv after start_smp_scan failure "
                        f"raised (continuing): {stop_err}"
                    )
                time.sleep(2)
                _cleanup_central_bluetooth_session(
                    central,
                    f"Central-{c_idx + 1} outer retry cleanup after start_smp_scan failure",
                )
                time.sleep(3)
                continue
            raise
        time.sleep(2)
        if central_address is None:
            try:
                central_address = central.interfaces.bluetooth.get_address()
            except Exception as err:
                logger().warning(f"Central-{c_idx + 1}: failed to resolve adapter address: {err}")
        pair_thread = threading.Thread(
            target=_pair_and_connect_with_retry,
            args=(central.interfaces.bluetooth, bt_dut_address),
            kwargs={"total_timeout_sec": 180, "retry_interval_sec": 8},
            daemon=True,
        )
        pair_thread.start()
        passkey = _capture_dut_passkey_and_inject(ble_dut, central, timeout_sec=180)
        pair_thread.join(timeout=180)
        if passkey:
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_get_device_state()
            if central_address is None or _validate_dut_central_link(ble_dut, central_address, c_idx):
                try:
                    central.interfaces.bluetooth.stop_scanning()
                except Exception:
                    pass
                return central_address
        if attempt < max_attempts:
            try:
                ble_dut.interfaces.bluetooth.ble_stop_advertising()
            except Exception:
                pass
            time.sleep(2)
            _cleanup_central_bluetooth_session(central, f"Central-{c_idx + 1} retry cleanup")
            time.sleep(3)
    pytest.fail(f"Central-{c_idx + 1} could not establish a stable passkey link to DUT")

def _connect_central_no_passkey_with_retry(
    ble_dut, central, c_idx, bt_dut_address, max_attempts=3,
    settle_after_pair_sec=20,
    min_conn_interval=None,
    max_conn_interval=None,
    conn_latency=None,
    supervision_timeout=None,
    validate_link_with_conn_update=True,
    service_classes=None,
    capability = "NoInputNoOutput",
):
    central_address = None

    for attempt in range(1, max_attempts + 1):
        logger().info(
            f"===== Central-{c_idx + 1} connect attempt "
            f"{attempt}/{max_attempts} (no-passkey) ====="
        )
        _cleanup_central_bluetooth_session(central, f"Central-{c_idx + 1} pre-scan cleanup")
        time.sleep(1)

        ble_dut.interfaces.bluetooth.ble_start_advertising(
            ble_adv_int_min=160,  # 100 ms
            ble_adv_int_max=320,  # 200 ms
        )
        time.sleep(2)

        scan_kwargs = {"bt_dut_address": bt_dut_address}
        if service_classes is not None:
            scan_kwargs["service_classes"] = service_classes
        if capability is not None:
            scan_kwargs["capability"] = capability
        try:
            _start_central_smp_scan_with_recovery(
                central,
                scan_kwargs,
                c_idx=c_idx,
                attempt=attempt,
                max_attempts=max_attempts,
            )
        except Exception as err:
            logger().warning(
                f"Central-{c_idx + 1}: start_smp_scan recovery failed on outer "
                f"attempt {attempt}/{max_attempts}: {err}"
            )
            if attempt < max_attempts:
                try:
                    ble_dut.interfaces.bluetooth.ble_stop_advertising()
                except Exception as stop_err:
                    logger().info(
                        f"Central-{c_idx + 1}: stop_adv after start_smp_scan failure "
                        f"raised (continuing): {stop_err}"
                    )
                time.sleep(2)
                _cleanup_central_bluetooth_session(
                    central,
                    f"Central-{c_idx + 1} outer retry cleanup after start_smp_scan failure",
                )
                time.sleep(3)
                continue
            raise
        time.sleep(2)

        if central_address is None:
            try:
                central_address = central.interfaces.bluetooth.get_address()
                logger().info(
                    f"Central-{c_idx + 1}: BlueZ adapter address resolved "
                    f"-> {central_address}"
                )
            except Exception as err:
                logger().warning(
                    f"Central-{c_idx + 1}: could not fetch BlueZ adapter "
                    f"address even after start_smp_scan ({err}); link "
                    f"validation will be skipped this attempt"
                )

        try:
            if any(
                value is not None
                for value in (
                    min_conn_interval,
                    max_conn_interval,
                    conn_latency,
                    supervision_timeout,
                )
            ):
                central.interfaces.bluetooth.connect(
                    dev_addr=bt_dut_address,
                    min_conn_interval=min_conn_interval,
                    max_conn_interval=max_conn_interval,
                    conn_latency=conn_latency,
                    supervision_timeout=supervision_timeout,
                )
            else:
                central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        except Exception as err:
            logger().warning(
                f"Central-{c_idx + 1}: pair_and_connect raised on attempt "
                f"{attempt}/{max_attempts}: {err}"
            )

        time.sleep(settle_after_pair_sec)  # let any 0x4e08/0x4e3e surface
        ble_dut.interfaces.bluetooth.ble_get_device_state()

        link_ok = False
        if central_address is None:
            logger().info(
                f"Central-{c_idx + 1}: pair/connect completed but BlueZ adapter "
                f"address is unavailable, treating link as unstable and retrying"
            )
        else:
            validation_min = min_conn_interval if min_conn_interval is not None else 96
            validation_max = max_conn_interval if max_conn_interval is not None else validation_min
            validation_latency = conn_latency if conn_latency is not None else CONN_LATENCY
            validation_timeout = (
                supervision_timeout if supervision_timeout is not None else SUPERVISION_TIMEOUT
            )
            if not validate_link_with_conn_update:
                logger().info(
                    f"Central-{c_idx + 1}: validating link using the requested CI "
                    f"parameters instead of the generic probe"
                )
            if _validate_dut_central_link(
                ble_dut,
                central_address,
                c_idx,
                ble_conn_interval_min=validation_min,
                ble_conn_interval_max=validation_max,
                ble_conn_latency=validation_latency,
                ble_supervision_timeout=validation_timeout,
            ):
                logger().info(
                    f"Central-{c_idx + 1}: link survived pair/connect; advancing"
                )
                link_ok = True
            else:
                logger().warning(
                    f"Central-{c_idx + 1}: link dropped after pair/connect "
                    f"on attempt {attempt}/{max_attempts}"
                )
        if link_ok:
            try:
                central.interfaces.bluetooth.stop_scanning()
            except Exception:
                pass
            return central_address
        else:
            logger().warning(
                f"Central-{c_idx + 1}: retrying after unstable or missing link "
                f"on attempt {attempt}/{max_attempts}"
            )

        # Tear down both sides before the next attempt.
        if attempt < max_attempts:
            try:
                ble_dut.interfaces.bluetooth.ble_stop_advertising()
            except Exception as err:
                logger().info(
                    f"Central-{c_idx + 1}: stop_adv raised "
                    f"(expected if FW already stopped): {err}"
                )
            time.sleep(2)
            _cleanup_central_bluetooth_session(central, f"Central-{c_idx + 1} retry cleanup")
            time.sleep(3)

    pytest.fail(
        f"Central-{c_idx + 1} could not establish a stable LL link to DUT "
        f"after {max_attempts} attempts (last symptom: 0x4e08/0x4e3e "
        f"disconnect within ~1 s of pair_and_connect). Reduce 8P load or "
        f"increase advertising interval further."
    )

def _run_8p_2c_all_tx_background_test(
    ble_dut,
    ble_client,
    ble_clients,
    *,
    pair_mode,
    payload_len,
    svc,
    transfer_config_fn,
    transfer_label,
    subscribe_peripheral,
    subscribe_central = False,
    defer_central_subscription_until_all_connected=False,
):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    # peripheral_clients = [ble_client]
    central_clients = [ble_clients[7], ble_clients[8]]

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _configure_dut_pair_mode(ble_dut, pair_mode)

    _enable_power_save(ble_dut=ble_dut)

    bt_iface = ble_dut.interfaces.bluetooth
    transfer_service_uuid, transfer_char_uuid = _uuid_pair_for_transfer(transfer_config_fn)

    for conn_id in range(10):
        transfer_config_fn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)

    client_addresses = []

    logger().info("=" * 60)
    logger().info(f"PHASE 1: Connecting to 8 peripheral devices ({transfer_label})")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")
        target_ci = _peripheral_ci_for_index(idx)
        client_address = _start_peripheral_adv_for_pair_mode(
            client, bt_dut_address, svc, pair_mode
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)

        servs, chars = [], []
        max_connect_attempts = 3
        passkey = None

        def _scan_and_connect(addr):
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=addr)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=addr)

        for connect_attempt in range(1, max_connect_attempts + 1):
            if pair_mode == PAIR_MODE_PASSKEY:
                connect_thread = threading.Thread(
                    target=_scan_and_connect,
                    args=(client_address,),
                    daemon=True,
                )
                connect_thread.start()
                passkey = _capture_dut_passkey_and_inject(ble_dut, client, timeout_sec=180)
                connect_thread.join(timeout=180)
                if not passkey:
                    logger().warning(
                        f"Peripheral {idx + 1}: DUT did not emit passkey display event on "
                        f"connect run {connect_attempt}/{max_connect_attempts}"
                    )
                else:
                    ble_dut.interfaces.bluetooth.ble_get_device_state()
                    time.sleep(5)
            else:
                try:
                    _scan_and_connect(client_address)
                except Exception as e:
                    logger().warning(
                        f"Peripheral {idx + 1}: ble_connect raised on attempt "
                        f"{connect_attempt}/{max_connect_attempts}: {e}"
                    )
                wait_for_dut_ble_connected(ble_dut, f"Peripheral {idx + 1}", timeout_sec=90)

            servs, chars = [], []
            max_discovery_attempts = 6
            for attempt in range(1, max_discovery_attempts + 1):
                servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                if len(servs) > 0 and len(chars) > 0:
                    logger().info(
                        f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt} "
                        f"(connect run {connect_attempt}/{max_connect_attempts})"
                    )
                    break
                logger().warning(
                    f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts} "
                    f"(connect run {connect_attempt}/{max_connect_attempts}); "
                    f"services={len(servs)}, chars={len(chars)}"
                )
                time.sleep(10)

            if len(servs) > 0 and len(chars) > 0:
                break

            if connect_attempt < max_connect_attempts:
                logger().warning(
                    f"Peripheral {idx + 1}: discovery empty after {max_discovery_attempts} attempts; "
                    f"retrying connect (run {connect_attempt + 1}/{max_connect_attempts})."
                )
                try:
                    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=client_address)
                    client.interfaces.bluetooth.disconnect(bt_dut_address)
                except Exception as e:
                    logger().info(
                        f"Peripheral {idx + 1}: DUT ble_disconnect cleanup raised "
                        f"(expected if FW already tore link down): {e}"
                    )
                time.sleep(2)
                try:
                    client.interfaces.bluetooth.close()
                except Exception as err:
                    logger().info(
                        f"Peripheral {idx + 1}: BlueZ close raised (continuing anyway): {err}"
                    )
                time.sleep(2)
                _start_peripheral_adv_for_pair_mode(
                    client, bt_dut_address, svc, pair_mode
                )
                time.sleep(2)

        if pair_mode == PAIR_MODE_PASSKEY:
            assert passkey, (
                f"DUT did not emit passkey display event for peripheral {idx + 1} "
                f"after {max_connect_attempts} connect attempts"
            )
        assert len(servs) > 0, (
            f"No services fetched for peripheral {idx + 1} after "
            f"{max_connect_attempts} connect attempts"
        )
        assert len(chars) > 0, (
            f"Fetched characters are empty for peripheral {idx + 1} after "
            f"{max_connect_attempts} connect attempts"
        )

        if subscribe_peripheral:
            char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=transfer_service_uuid,
                char_uid=transfer_char_uuid
            )
            assert char_path, f"Characters are empty for peripheral {idx + 1}"
            client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path,
                char_uid=transfer_char_uuid
            )

        time.sleep(5)
        _update_central_live_conn_params(
            central_device=client,
            dut_addr=bt_dut_address,
            remote_addr=client_address,
            target_ci=target_ci,
            bt_iface=bt_iface,
        )
        time.sleep(2)
        transfer_config_fn(bt_iface=bt_iface, conn_id=idx)
        logger().info(f"Peripheral {idx + 1} connected and ready for {transfer_label}")
        time.sleep(2)

    logger().info("=" * 60)
    logger().info(f"PHASE 2: Connecting 2 central devices ({transfer_label})")
    logger().info("=" * 60)

    pending_central_subscriptions = []

    def _setup_central_subscription(central, c_idx):
        try:
            central_servs, central_chars = (
                central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            )
            assert len(central_servs) > 0 and len(central_chars) > 0, (
                f"Central-{c_idx + 1}: no services/chars resolved on BlueZ"
            )
            central_char_path, _central_char_props = (
                central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=central_servs,
                    service_uid=transfer_service_uuid,
                    char_uid=transfer_char_uuid,
                )
            )
            assert central_char_path, f"Central-{c_idx + 1}: indicate char path empty on BlueZ"
            central.interfaces.bluetooth.gatt_adapter.read_charac_value(
                char_path=central_char_path
            )
            central.interfaces.bluetooth.gatt_adapter.enable_notifications(
                char_path=central_char_path
            )
            central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=central_char_path,
                char_uid=transfer_char_uuid,
            )

            logger().info(
                f"Central-{c_idx + 1}: DUT background {transfer_label} subscription ready"
            )
        except Exception as ex:
            logger().warning(
                f"Central-{c_idx + 1}: failed to set up DUT->{c_idx + 1} "
                f"{transfer_label} path: {ex}; continuing with DUT link only"
            )

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")
        central_ci = _central_ci_for_index(c_idx)

        if pair_mode == PAIR_MODE_PASSKEY:
            central_address = _connect_passkey_central_with_retry_extended(
                ble_dut=ble_dut,
                central=central,
                c_idx=c_idx,
                bt_dut_address=bt_dut_address,
                capability="KeyboardOnly",
                max_attempts=3,
                service_classes=[svc],
            )
        else:
            central_address = _connect_central_no_passkey_with_retry(
                ble_dut=ble_dut,
                central=central,
                c_idx=c_idx,
                bt_dut_address=bt_dut_address,
                max_attempts=3,
                settle_after_pair_sec=20,
                min_conn_interval=central_ci,
                max_conn_interval=central_ci,
                conn_latency=CONN_LATENCY,
                supervision_timeout=SUPERVISION_TIMEOUT,
                validate_link_with_conn_update=False,
                service_classes=[svc],
                capability=_central_scan_capability_for_pair_mode(pair_mode),
            )

        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT")

        if subscribe_central:
            if defer_central_subscription_until_all_connected:
                pending_central_subscriptions.append((central, c_idx))
            else:
                _setup_central_subscription(central, c_idx)
        time.sleep(5)
        _update_central_live_conn_params(
            central_device=central,
            dut_addr=bt_dut_address,
            remote_addr=central_address,
            target_ci=central_ci,
            bt_iface=bt_iface,
        )
        time.sleep(2)
        transfer_config_fn(bt_iface=bt_iface, conn_id=conn_id)

    if subscribe_central and defer_central_subscription_until_all_connected:
        logger().info(
            f"Deferring central subscription setup until both centrals are connected "
            f"for {transfer_label}"
        )
        for central, c_idx in pending_central_subscriptions:
            _setup_central_subscription(central, c_idx)

    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! DUT background {transfer_label} running for 5 min")
    logger().info("=" * 60)
    ble_dut.interfaces.bluetooth.ble_get_device_state()
    _run_basic_soak(
        ble_dut,
        duration_sec=5 * 60,
        interval_sec=60,
        label=f"{transfer_label} stability",
        expected_peripheral_count=8,
        expected_central_count=2,
    )
    logger().info(f"===== 5 minutes elapsed, background {transfer_label} complete =====")

    logger().info("=" * 60)
    logger().info("PHASE 5: Disconnecting all clients")
    logger().info("=" * 60)
    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("Disconnecting central-1")
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[0], "Central-1 final cleanup")
    logger().info("Disconnecting central-2")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[1], "Central-2 final cleanup")


def _connect_central_with_retry(
    ble_dut, central, c_idx, bt_dut_address, capability = "NoInputNoOutput", max_attempts=3):
    central_address = None

    for attempt in range(1, max_attempts + 1):
        logger().info(
            f"===== Central-{c_idx + 1} connect attempt "
            f"{attempt}/{max_attempts} ====="
        )

        
        ble_dut.interfaces.bluetooth.ble_start_advertising(
            ble_adv_int_min=160,  # 100 ms
            ble_adv_int_max=320,  # 200 ms
        )
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            pin_code="-8",
            capability=capability,
        )
        time.sleep(2)

        if central_address is None:
            try:
                central_address = central.interfaces.bluetooth.get_address()
                logger().info(
                    f"Central-{c_idx + 1}: BlueZ adapter address resolved "
                    f"-> {central_address}"
                )
            except Exception as err:
                logger().warning(
                    f"Central-{c_idx + 1}: could not fetch BlueZ adapter "
                    f"address even after start_smp_scan ({err}); link "
                    f"validation will be skipped this attempt"
                )

        pair_thread = threading.Thread(
            target=_pair_and_connect_with_retry,
            args=(central.interfaces.bluetooth, bt_dut_address),
            kwargs={"total_timeout_sec": 180, "retry_interval_sec": 8},
            daemon=True,
        )
        pair_thread.start()

        passkey = _capture_dut_passkey_and_inject(
            ble_dut, central, timeout_sec=180
        )
        pair_thread.join(timeout=180)

        link_ok = False
        if not passkey:
            logger().warning(
                f"Central-{c_idx + 1}: no passkey emitted on attempt "
                f"{attempt}/{max_attempts} (LL likely dropped before SMP)"
            )
        else:
            time.sleep(3)  # let any 0x4e08 / 0x4e3e disconnect surface
            ble_dut.interfaces.bluetooth.ble_get_device_state()
            if central_address is None:
                # Best-effort: assume link is up; we have no probe.
                logger().info(
                    f"Central-{c_idx + 1}: passkey delivered, validation "
                    f"skipped (no central address)"
                )
                link_ok = True
            elif _validate_dut_central_link(ble_dut, central_address, c_idx):
                logger().info(
                    f"Central-{c_idx + 1}: paired AND link survived; advancing"
                )
                link_ok = True
            else:
                logger().warning(
                    f"Central-{c_idx + 1}: paired but link dropped after pairing "
                    f"on attempt {attempt}/{max_attempts}"
                )

        if link_ok:
            return central_address

        # Tear down both sides before the next attempt.
        if attempt < max_attempts:
            try:
                ble_dut.interfaces.bluetooth.ble_stop_advertising()
            except Exception as err:
                logger().info(
                    f"Central-{c_idx + 1}: stop_adv raised "
                    f"(expected if FW already stopped): {err}"
                )
            time.sleep(2)
            try:
                central.interfaces.bluetooth.close()
            except Exception as err:
                logger().info(
                    f"Central-{c_idx + 1}: BlueZ close raised "
                    f"(continuing): {err}"
                )
            time.sleep(3)

    pytest.fail(
        f"Central-{c_idx + 1} could not establish a stable LL link to DUT "
        f"after {max_attempts} attempts (last symptom: 0x4e08/0x4e3e "
        f"disconnect within ~1 s of pairing). Reduce 8P load or increase "
        f"advertising interval further."
    )


def _connect_central_with_retry(
    ble_dut, central, c_idx, bt_dut_address, capability, max_attempts=3,
    service_classes=None,
):

    central_address = None

    for attempt in range(1, max_attempts + 1):
        logger().info(
            f"===== Central-{c_idx + 1} connect attempt "
            f"{attempt}/{max_attempts} ====="
        )

        ble_dut.interfaces.bluetooth.ble_start_advertising(
            ble_adv_int_min=160,  # 100 ms
            ble_adv_int_max=320,  # 200 ms
        )
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            pin_code="-8",
            capability=capability,
            service_classes=service_classes,
        )
        time.sleep(2)

        if central_address is None:
            try:
                central_address = central.interfaces.bluetooth.get_address()
                logger().info(
                    f"Central-{c_idx + 1}: BlueZ adapter address resolved "
                    f"-> {central_address}"
                )
            except Exception as err:
                logger().warning(
                    f"Central-{c_idx + 1}: could not fetch BlueZ adapter "
                    f"address even after start_smp_scan ({err}); link "
                    f"validation will be skipped this attempt"
                )

        pair_thread = threading.Thread(
            target=_pair_and_connect_with_retry,
            args=(central.interfaces.bluetooth, bt_dut_address),
            kwargs={"total_timeout_sec": 180, "retry_interval_sec": 8},
            daemon=True,
        )
        pair_thread.start()

        passkey = _capture_dut_passkey_and_inject(
            ble_dut, central, timeout_sec=180
        )
        pair_thread.join(timeout=180)

        link_ok = False
        if not passkey:
            logger().warning(
                f"Central-{c_idx + 1}: no passkey emitted on attempt "
                f"{attempt}/{max_attempts} (LL likely dropped before SMP)"
            )
        else:
            time.sleep(3)  # let any 0x4e08 / 0x4e3e disconnect surface
            ble_dut.interfaces.bluetooth.ble_get_device_state()
            if central_address is None:
                # Best-effort: assume link is up; we have no probe.
                logger().info(
                    f"Central-{c_idx + 1}: passkey delivered, validation "
                    f"skipped (no central address)"
                )
                link_ok = True
            elif _validate_dut_central_link(ble_dut, central_address, c_idx):
                logger().info(
                    f"Central-{c_idx + 1}: paired AND link survived; advancing"
                )
                link_ok = True
            else:
                logger().warning(
                    f"Central-{c_idx + 1}: paired but link dropped after pairing "
                    f"on attempt {attempt}/{max_attempts}"
                )

        if link_ok:
            return central_address

        # Tear down both sides before the next attempt.
        if attempt < max_attempts:
            try:
                ble_dut.interfaces.bluetooth.ble_stop_advertising()
            except Exception as err:
                logger().info(
                    f"Central-{c_idx + 1}: stop_adv raised "
                    f"(expected if FW already stopped): {err}"
                )
            time.sleep(2)
            try:
                central.interfaces.bluetooth.close()
            except Exception as err:
                logger().info(
                    f"Central-{c_idx + 1}: BlueZ close raised "
                    f"(continuing): {err}"
                )
            time.sleep(3)

    pytest.fail(
        f"Central-{c_idx + 1} could not establish a stable LL link to DUT "
        f"after {max_attempts} attempts (last symptom: 0x4e08/0x4e3e "
        f"disconnect within ~1 s of pairing). Reduce 8P load or increase "
        f"advertising interval further."
    )




REMOTE_NOTIFY_CHAR_NAME = "CustomNotifyCharacteristic"
REMOTE_NOTIFY_CHAR_UUID = "00001aa2-0000-1000-8000-00805f9b34fb"


def _build_rx_payload(payload_len):
    seed = f"remote_rx_payload_{payload_len}_bytes_"
    return (seed * ((payload_len // len(seed)) + 2))[:payload_len]


def _capture_dut_log_baseline(ble_dut):
    try:
        return len(ble_dut.interfaces.wifi.bus.get_input_log())
    except Exception:
        return 0


def _extract_custom_notify_handle_from_records(records, label):
    uuid_candidates = (
        REMOTE_NOTIFY_CHAR_UUID.upper().replace("-", ""),
        "00001AA200001000800000805F9B34FB",
        "00001AA2",
        "1AA2",
    )
    pattern = re.compile(
        rf"UUID:\s*0x(?:{'|'.join(re.escape(candidate) for candidate in uuid_candidates)})\s*Handle:\s*0x([0-9A-Fa-f]+)",
        flags=re.IGNORECASE,
    )
    decoded_chunks = []
    for entry in records:
        raw = entry[1] if isinstance(entry, tuple) and len(entry) >= 2 else entry
        if isinstance(raw, (bytes, bytearray)):
            decoded_chunks.append(raw.decode(errors="ignore"))
        elif isinstance(raw, str):
            decoded_chunks.append(raw)
    log_blob = "\n".join(decoded_chunks)
    matches = pattern.findall(log_blob)
    assert matches, f"{label}: custom notify handle not found in DUT GATT dump"
    handle_hex = matches[-1]
    handle = int(handle_hex, 16)
    logger().info(
        f"{label}: parsed CustomNotifyCharacteristic ({REMOTE_NOTIFY_CHAR_UUID}) "
        f"handle 0x{handle_hex}"
    )
    return handle


def _resolve_custom_notify_handle_from_dut_log(ble_dut, label, baseline_idx=0):
    wifi_iface = ble_dut.interfaces.wifi
    records = wifi_iface.bus.get_input_log()
    relevant_records = records[baseline_idx:] if baseline_idx < len(records) else []
    if relevant_records:
        try:
            return _extract_custom_notify_handle_from_records(relevant_records, label)
        except Exception as err:
            logger().warning(f"{label}: recent DUT log slice did not contain handle info: {err}")
    return _extract_custom_notify_handle_from_records(records, label)


def _enable_dut_rx_notifications(bt_iface, ble_dut, cache, rx_notify_handles, remote_addr, label, baseline_idx=0):
    if remote_addr in cache:
        write_handle = cache[remote_addr]
    else:
        write_handle = _resolve_custom_notify_handle_from_dut_log(ble_dut, label, baseline_idx=baseline_idx)
        cache[remote_addr] = write_handle
    bt_iface.ble_set_att_value(
        ble_remote_dev_address=remote_addr,
        handle=(write_handle + 1),
        enable_notify=1,
    )
    rx_notify_handles.append((remote_addr, write_handle, label))
    logger().info(f"{label}: DUT RX notifications enabled on handle {write_handle + 1}")
    return write_handle


def _start_rx_notify_thread(rx_notify_threads, rx_stop_flags, remote_device, svc, payload, label, notify_interval=1):
    stop_flag = {'stop': False}
    rx_stop_flags.append(stop_flag)

    def _continuous_rx_notify():
        count = 0
        while not stop_flag['stop']:
            try:
                remote_device.interfaces.bluetooth.send_gatt_charc_notification(
                    svc,
                    REMOTE_NOTIFY_CHAR_NAME,
                    payload,
                )
                count += 1
            except Exception as e:
                logger().warning(f"[{label}] RX Notification #{count + 1} failed: {e}")
            time.sleep(notify_interval)
        logger().info(f"[{label}] RX Notification thread stopped after {count} notifications")

    thread = threading.Thread(target=_continuous_rx_notify, daemon=True)
    thread.start()
    rx_notify_threads.append(thread)
    logger().info(f"[{label}] RX Notification thread STARTED")


def _stop_rx_notify_threads(rx_stop_flags, rx_notify_threads, bt_iface, rx_notify_handles):
    for stop_flag in rx_stop_flags:
        stop_flag['stop'] = True
    for idx, thread in enumerate(rx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"RX notification thread {idx + 1} joined")
    for remote_addr, write_handle, label in rx_notify_handles:
        try:
            bt_iface.ble_set_att_value(
                ble_remote_dev_address=remote_addr,
                handle=(write_handle + 1),
                enable_notify=0,
            )
            logger().info(f"{label}: DUT RX notifications disabled on handle {write_handle + 1}")
        except Exception as err:
            logger().warning(f"{label}: failed to disable DUT RX notifications: {err}")




def _run_8p_2c_split_notify_rx_test(ble_dut, ble_client, ble_clients, *, pair_mode, payload_len, label):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"
    rx_payload = _build_rx_payload(payload_len)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _configure_dut_pair_mode(ble_dut, pair_mode)
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth

    for conn_id in (8, 9):
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)

    client_addresses = []
    rx_notify_threads = []
    rx_stop_flags = []
    rx_notify_handles = []
    cached_rx_notify_handles = {}

    CUSTOM_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
    CUSTOM_CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"

    for idx, client in enumerate(peripheral_clients):
        link_label = f"Peripheral {idx + 1}"
        target_ci = _peripheral_ci_for_index(idx)
        client_address = _start_peripheral_adv_for_pair_mode(
            client, bt_dut_address, svc, pair_mode
        )
        assert client_address
        client_addresses.append(client_address)

        servs, chars, passkey = [], [], None
        max_connect_attempts = 3

        def _scan_and_connect(addr):
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=addr)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=addr)

        for connect_attempt in range(1, max_connect_attempts + 1):
            if pair_mode == PAIR_MODE_PASSKEY:
                t = threading.Thread(target=_scan_and_connect, args=(client_address,), daemon=True)
                t.start()
                passkey = _capture_dut_passkey_and_inject(ble_dut, client, timeout_sec=180)
                t.join(timeout=180)
                if passkey:
                    ble_dut.interfaces.bluetooth.ble_get_device_state()
                    time.sleep(5)
            else:
                try:
                    _scan_and_connect(client_address)
                except Exception as err:
                    logger().warning(f"{link_label}: ble_connect raised on attempt {connect_attempt}/{max_connect_attempts}: {err}")
                wait_for_dut_ble_connected(ble_dut, link_label, timeout_sec=100)
                time.sleep(5)

            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                break
            if connect_attempt < max_connect_attempts:
                try:
                    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=client_address)
                    client.interfaces.bluetooth.disconnect(bt_dut_address)
                except Exception:
                    pass
                time.sleep(2)

        if pair_mode == PAIR_MODE_PASSKEY:
            assert passkey, f"{link_label}: passkey flow failed"
        assert len(servs) > 0 and len(chars) > 0, f"{link_label}: no GATT discovery"
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        assert char_path, f"{link_label}: characteristic path missing"
        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=CUSTOM_CHAR_UUID)
        baseline = _capture_dut_log_baseline(ble_dut)
        bt_iface.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)
        _enable_dut_rx_notifications(bt_iface, ble_dut, cached_rx_notify_handles, rx_notify_handles, client_address, link_label, baseline)
        time.sleep(5)
        _update_central_live_conn_params(client, bt_dut_address, client_address, target_ci, bt_iface)
        _start_rx_notify_thread(rx_notify_threads, rx_stop_flags, client, svc, rx_payload, link_label)

    for c_idx, central in enumerate(central_clients):
        central_ci = _central_ci_for_index(c_idx)
        if pair_mode == PAIR_MODE_PASSKEY:
            central_address = _connect_passkey_central_with_retry_extended(
                ble_dut, central, c_idx, bt_dut_address,
                capability="KeyboardOnly",
                service_classes=[svc],
            )
        else:
            central_address = _connect_central_no_passkey_with_retry(
                ble_dut=ble_dut,
                central=central,
                c_idx=c_idx,
                bt_dut_address=bt_dut_address,
                max_attempts=3,
                settle_after_pair_sec=20,
                min_conn_interval=central_ci,
                max_conn_interval=central_ci,
                conn_latency=CONN_LATENCY,
                supervision_timeout=SUPERVISION_TIMEOUT,
                validate_link_with_conn_update=False,
                service_classes=[svc],
                capability=_central_scan_capability_for_pair_mode(pair_mode),
            )
        conn_id = 8 + c_idx
        central_servs, central_chars = (
            central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(central_servs) > 0 and len(central_chars) > 0, f"Central {c_idx + 1}: no GATT discovery"
        char_path, _ = central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=central_servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        central.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        central.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path, char_uid=CUSTOM_CHAR_UUID
        )
        _update_central_live_conn_params(central, bt_dut_address, central_address, central_ci, bt_iface)
        time.sleep(5)
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)

    logger().info(f"{label}: all links up, running split TX/RX for 5 minutes")
    ble_dut.interfaces.bluetooth.ble_get_device_state()
    _run_basic_soak(
        ble_dut,
        duration_sec=5 * 60,
        interval_sec=60,
        label=f"{label} split notify/rx stability",
        expected_peripheral_count=8,
        expected_central_count=2,
    )
    _stop_rx_notify_threads(rx_stop_flags, rx_notify_threads, bt_iface, rx_notify_handles)

    for idx, addr in enumerate(client_addresses):
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[0], "Central-1 final cleanup")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[1], "Central-2 final cleanup")


def _run_8p_2c_bidirectional_notify_test(ble_dut, ble_client, ble_clients, *, payload_len, label):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"
    rx_payload = _build_rx_payload(payload_len)
    passkey_capability = "KeyboardOnly"
    CUSTOM_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
    CUSTOM_CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=0, mitm=1)
    logger().info("DUT IO Capability set to DisplayOnly (Passkey Entry), MITM=1")
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth

    for conn_id in range(10):
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)

    client_addresses = []
    rx_notify_threads = []
    rx_stop_flags = []
    rx_notify_handles = []
    cached_rx_notify_handles = {}

    for idx, client in enumerate(peripheral_clients):
        link_label = f"Peripheral {idx + 1}"
        target_ci = _peripheral_ci_for_index(idx)
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, pin_code="-8", capability=passkey_capability, service_classes=[svc]
        )
        assert client_address
        client_addresses.append(client_address)

        servs, chars, passkey = [], [], None
        def _scan_and_connect(addr):
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=addr)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=addr)
        for connect_attempt in range(1, 4):
            t = threading.Thread(target=_scan_and_connect, args=(client_address,), daemon=True)
            t.start()
            passkey = _capture_dut_passkey_and_inject(ble_dut, client, timeout_sec=180)
            t.join(timeout=180)
            if passkey:
                ble_dut.interfaces.bluetooth.ble_get_device_state()
                time.sleep(5)
                servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                if len(servs) > 0 and len(chars) > 0:
                    break
            if connect_attempt < 3:
                try:
                    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=client_address)
                except Exception:
                    pass
                time.sleep(2)
        assert passkey and len(servs) > 0 and len(chars) > 0, f"{link_label}: connect failed"
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=CUSTOM_CHAR_UUID)
        baseline = _capture_dut_log_baseline(ble_dut)
        bt_iface.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)
        _enable_dut_rx_notifications(bt_iface, ble_dut, cached_rx_notify_handles, rx_notify_handles, client_address, link_label, baseline)
        time.sleep(5)
        _update_central_live_conn_params(client, bt_dut_address, client_address, target_ci, bt_iface)
        time.sleep(5)
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=idx)
        _start_rx_notify_thread(rx_notify_threads, rx_stop_flags, client, svc, rx_payload, link_label)

    for c_idx, central in enumerate(central_clients):
        link_label = f"Central {c_idx + 1}"
        central_ci = _central_ci_for_index(c_idx)
        central_address = _connect_passkey_central_with_retry_extended(
            ble_dut, central, c_idx, bt_dut_address, capability=passkey_capability, service_classes=[svc]
        )
        central_servs, central_chars = central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(central_servs) > 0 and len(central_chars) > 0, f"{link_label}: no GATT discovery"
        central_char_path, _ = central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=central_servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        central.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=central_char_path)
        central.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=central_char_path)
        central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=central_char_path, char_uid=CUSTOM_CHAR_UUID)
        baseline = _capture_dut_log_baseline(ble_dut)
        bt_iface.ble_get_profiles_async(ble_remote_dev_address=central_address)
        time.sleep(10)
        _enable_dut_rx_notifications(bt_iface, ble_dut, cached_rx_notify_handles, rx_notify_handles, central_address, link_label, baseline)
        conn_id = 8 + c_idx
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)
        _update_central_live_conn_params(central, bt_dut_address, central_address, central_ci, bt_iface)
        _start_rx_notify_thread(rx_notify_threads, rx_stop_flags, central, svc, rx_payload, link_label)

    logger().info(f"{label}: all links up, running bidirectional TX/RX for 5 minutes")
    ble_dut.interfaces.bluetooth.ble_get_device_state()
    _run_basic_soak(
        ble_dut,
        duration_sec=5 * 60,
        interval_sec=60,
        label=f"{label} bidirectional notify stability",
        expected_peripheral_count=8,
        expected_central_count=2,
    )
    _stop_rx_notify_threads(rx_stop_flags, rx_notify_threads, bt_iface, rx_notify_handles)

    for idx, addr in enumerate(client_addresses):
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[0], "Central-1 final cleanup")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[1], "Central-2 final cleanup")


def _run_8p_2c_mixed_tx_test(
    ble_dut, ble_client, ble_clients, *, payload_len, label, peripheral_svc, peripheral_transfer_config_fn, peripheral_subscribe
):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    # peripheral_clients = [ble_client, ble_clients[0]]
    central_clients = [ble_clients[7], ble_clients[8]]
    central_svc = "HealthThermometerService"
    passkey_capability = "KeyboardOnly"
    peripheral_service_uuid, peripheral_char_uuid = _uuid_pair_for_transfer(peripheral_transfer_config_fn)
    central_service_uuid = CUSTOM_SERVICE_UUID
    central_char_uuid = CUSTOM_CHAR_UUID

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=0, mitm=1)
    logger().info("DUT IO Capability set to DisplayOnly (Passkey Entry), MITM=1")
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth

    for conn_id in range(8):
        peripheral_transfer_config_fn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)
    for conn_id in (8, 9):
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)

    client_addresses = []
    for idx, client in enumerate(peripheral_clients):
        link_label = f"Peripheral {idx + 1}"
        target_ci = _peripheral_ci_for_index(idx)
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, pin_code="-8", capability=passkey_capability, service_classes=[peripheral_svc]
        )
        assert client_address
        client_addresses.append(client_address)
        servs, chars, passkey = [], [], None

        def _scan_and_connect(addr):
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=addr)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=addr)

        for connect_attempt in range(1, 4):
            t = threading.Thread(target=_scan_and_connect, args=(client_address,), daemon=True)
            t.start()
            passkey = _capture_dut_passkey_and_inject(ble_dut, client, timeout_sec=180)
            t.join(timeout=180)
            if passkey:
                ble_dut.interfaces.bluetooth.ble_get_device_state()
                time.sleep(5)
                servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                if len(servs) > 0 and len(chars) > 0:
                    break
            if connect_attempt < 3:
                try:
                    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=client_address)
                except Exception:
                    pass
                time.sleep(2)
        assert passkey and len(servs) > 0 and len(chars) > 0, f"{link_label}: connect failed"
        if peripheral_subscribe:
            char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=peripheral_service_uuid, char_uid=peripheral_char_uuid
            )
            client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=peripheral_char_uuid)
        _update_central_live_conn_params(client, bt_dut_address, client_address, target_ci, bt_iface)
        peripheral_transfer_config_fn(bt_iface=bt_iface, conn_id=idx)
    for c_idx, central in enumerate(central_clients):
        central_ci = _central_ci_for_index(c_idx)
        central_address = _connect_passkey_central_with_retry_extended(
            ble_dut, central, c_idx, bt_dut_address, capability=passkey_capability, service_classes=[central_svc],
        )
        central_servs, central_chars = (
                central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            )
        assert len(central_servs) > 0 and len(central_chars) > 0, (
            f"{label}: no services/chars resolved on BlueZ "
        )
        central_char_path, _central_char_props = (
            central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=central_servs,
                service_uid=central_service_uuid,
                char_uid=central_char_uuid,
            )
        )
        assert central_char_path, f"{label}: notify char path empty on BlueZ"
        central.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=central_char_path
        )
        central.interfaces.bluetooth.gatt_adapter.enable_notifications(
            char_path=central_char_path
        )
        central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=central_char_path,
            char_uid=central_char_uuid,
        )
        conn_id = 8 + c_idx
        _update_central_live_conn_params(central, bt_dut_address, central_address, central_ci, bt_iface)
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)

    logger().info(f"{label}: all links up, running mixed traffic for 5 minutes")
    ble_dut.interfaces.bluetooth.ble_get_device_state()
    _run_basic_soak(
        ble_dut,
        duration_sec=5 * 60,
        interval_sec=60,
        label=f"{label} mixed traffic stability",
        expected_peripheral_count=8,
        expected_central_count=2,
    )

    for idx, addr in enumerate(client_addresses):
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[0], "Central-1 final cleanup")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    _cleanup_central_bluetooth_session(central_clients[1], "Central-2 final cleanup")


def _connect_single_peripheral(
    ble_dut, client, idx, bt_dut_address, svc, *, pair_mode=PAIR_MODE_DEFAULT, target_ci=None,
    conn_latency=CONN_LATENCY, supervision_timeout=SUPERVISION_TIMEOUT
):
    client_address = _start_peripheral_adv_for_pair_mode(
        client, bt_dut_address, svc, pair_mode
    )
    assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"

    def _scan_and_connect(addr):
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=addr)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=addr)

    servs, chars, passkey = [], [], None
    for connect_attempt in range(1, 4):
        if pair_mode == PAIR_MODE_PASSKEY:
            t = threading.Thread(target=_scan_and_connect, args=(client_address,), daemon=True)
            t.start()
            passkey = _capture_dut_passkey_and_inject(ble_dut, client, timeout_sec=180)
            t.join(timeout=180)
            if passkey:
                ble_dut.interfaces.bluetooth.ble_get_device_state()
                time.sleep(5)
        else:
            try:
                _scan_and_connect(client_address)
            except Exception as err:
                logger().warning(f"Peripheral {idx + 1}: ble_connect raised on attempt {connect_attempt}/3: {err}")
            wait_for_dut_ble_connected(ble_dut, f"Peripheral {idx + 1}", timeout_sec=90)

        for attempt in range(1, 7):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                break
            time.sleep(10)
        if len(servs) > 0 and len(chars) > 0:
            break
        if connect_attempt < 3:
            try:
                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=client_address)
                client.interfaces.bluetooth.disconnect(bt_dut_address)
            except Exception:
                pass
            time.sleep(2)

    if pair_mode == PAIR_MODE_PASSKEY:
        assert passkey, f"Peripheral {idx + 1}: passkey flow failed"
    assert len(servs) > 0 and len(chars) > 0, f"Peripheral {idx + 1}: no GATT discovery"

    if target_ci is not None:
        _update_central_live_conn_params(
            central_device=client,
            dut_addr=bt_dut_address,
            remote_addr=client_address,
            target_ci=target_ci,
            bt_iface=ble_dut.interfaces.bluetooth,
            conn_latency=conn_latency,
            supervision_timeout=supervision_timeout,
        )
        time.sleep(2)
    return client_address, servs, chars


def _connect_single_central(
    ble_dut, central, c_idx, bt_dut_address, svc=None, *, pair_mode=PAIR_MODE_DEFAULT, target_ci=None,
    conn_latency=CONN_LATENCY, supervision_timeout=SUPERVISION_TIMEOUT
):
    if pair_mode == PAIR_MODE_PASSKEY:
        central_address = _connect_passkey_central_with_retry_extended(
            ble_dut, central, c_idx, bt_dut_address, capability="KeyboardOnly",
            service_classes=[svc] if svc else None
        )
    else:
        central_address = _connect_central_no_passkey_with_retry(
            ble_dut=ble_dut,
            central=central,
            c_idx=c_idx,
            bt_dut_address=bt_dut_address,
            max_attempts=3,
            settle_after_pair_sec=20,
            min_conn_interval=target_ci,
            max_conn_interval=target_ci,
            conn_latency=conn_latency if target_ci is not None else None,
            supervision_timeout=supervision_timeout if target_ci is not None else None,
            validate_link_with_conn_update=False if target_ci is not None else True,
            service_classes=[svc] if svc else None,
            capability=_central_scan_capability_for_pair_mode(pair_mode),
        )
    if target_ci is not None:
        _update_central_live_conn_params(
            central_device=central,
            dut_addr=bt_dut_address,
            remote_addr=central_address,
            target_ci=target_ci,
            bt_iface=ble_dut.interfaces.bluetooth,
            conn_latency=conn_latency,
            supervision_timeout=supervision_timeout,
        )
        time.sleep(2)
    return central_address



def _decode_dut_log_entries(records):
    decoded_chunks = []
    for entry in records:
        raw = entry[1] if isinstance(entry, tuple) and len(entry) >= 2 else entry
        if isinstance(raw, (bytes, bytearray)):
            decoded_chunks.append(raw.decode(errors="ignore"))
        elif isinstance(raw, str):
            decoded_chunks.append(raw)
        else:
            decoded_chunks.append(str(raw))
    return decoded_chunks


def _scan_stability_log_for_disconnects(
    decoded_chunks,
    *,
    label,
    expected_peripheral_count=None,
    expected_central_count=None,
):
    if not decoded_chunks:
        return None

    log_blob = "\n".join(decoded_chunks)
    disconnect_patterns = (
        r"peripheral\s+is\s+disconnected",
        r"central\s+is\s+disconnected",
        r"device\s+is\s+disconnected",
        r"reason\s*:\s*0x4e08",
        r"reason\s*:\s*0x4e3e",
        r"connection_id_disc\s*:",
    )
    for pattern in disconnect_patterns:
        match = re.search(pattern, log_blob, flags=re.IGNORECASE)
        if match:
            snippet_lines = [
                line.strip()
                for line in log_blob[max(0, match.start() - 160): match.end() + 240].splitlines()
                if line.strip()
            ]
            snippet = " | ".join(snippet_lines[:6])
            return (
                f"{label}: disconnect detected during stability window via DUT log "
                f"pattern '{match.group(0)}'. Snippet: {snippet}"
            )

    if expected_peripheral_count is not None:
        peripheral_matches = re.findall(
            r"Number of connected peripheral devices:\s*(\d+)",
            log_blob,
            flags=re.IGNORECASE,
        )
        if peripheral_matches:
            latest_peripheral_count = int(peripheral_matches[-1])
            if latest_peripheral_count < expected_peripheral_count:
                return (
                    f"{label}: peripheral connection count dropped during stability "
                    f"window ({latest_peripheral_count} < {expected_peripheral_count})"
                )

    if expected_central_count is not None:
        central_matches = re.findall(
            r"Number of connected central devices:\s*(\d+)",
            log_blob,
            flags=re.IGNORECASE,
        )
        if central_matches:
            latest_central_count = int(central_matches[-1])
            if latest_central_count < expected_central_count:
                return (
                    f"{label}: central connection count dropped during stability "
                    f"window ({latest_central_count} < {expected_central_count})"
                )

    return None


def _run_basic_soak(
    ble_dut,
    duration_sec=5 * 60,
    interval_sec=60,
    label="soak",
    expected_peripheral_count=None,
    expected_central_count=None,
):
    baseline_idx = _capture_dut_log_baseline(ble_dut)
    elapsed = 0
    while elapsed < duration_sec:
        sleep_time = min(interval_sec, duration_sec - elapsed)
        time.sleep(sleep_time)
        elapsed += sleep_time
        raw_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = _parse_ble_device_state(raw_state)
        logger().info(
            f"{label}: stability check at {elapsed // 60} min {elapsed % 60} sec "
            f"(dut_state={state_int}, raw={raw_state!r})"
        )
        try:
            records = ble_dut.interfaces.wifi.bus.get_input_log()
        except Exception as err:
            logger().warning(f"{label}: failed to read DUT log during stability check: {err}")
            records = []
        new_records = records[baseline_idx:] if baseline_idx < len(records) else []
        baseline_idx = len(records)
        failure_reason = _scan_stability_log_for_disconnects(
            _decode_dut_log_entries(new_records),
            label=label,
            expected_peripheral_count=expected_peripheral_count,
            expected_central_count=expected_central_count,
        )
        assert failure_reason is None, failure_reason


def _run_adv_scan_visibility_test(ble_dut, ble_client, ble_clients, *, scan_interval, scan_window, label):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"
    adv_int = 338

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _enable_power_save(ble_dut=ble_dut)

    peripheral_addresses = []
    for idx, client in enumerate(peripheral_clients):
        addr = client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address, service_classes=[svc])
        assert addr, f"Peripheral {idx + 1} failed to advertise"
        peripheral_addresses.append(addr)

    for addr in peripheral_addresses:
        ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=addr,
            ble_scan_interval=scan_interval,
            ble_scan_window=scan_window,
        )
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)

    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=adv_int, ble_adv_int_max=adv_int)
    time.sleep(5)
    for c_idx, central in enumerate(central_clients):
        _cleanup_central_bluetooth_session(central, f"{label}: Central {c_idx + 1} pre-scan cleanup")
        _start_central_smp_scan_with_recovery(
            central,
            {"bt_dut_address": bt_dut_address},
            c_idx=c_idx,
            attempt=1,
            max_attempts=1,
        )
        time.sleep(10)
        central.interfaces.bluetooth.stop_scanning()
        found_devices = central.interfaces.bluetooth.get_devices()
        assert bt_dut_address.upper() in found_devices, f"{label}: DUT not visible to central scan"
        _cleanup_central_bluetooth_session(central, f"{label}: Central {c_idx + 1} post-scan cleanup")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()


def _run_pairing_only_test(ble_dut, ble_client, ble_clients, *, pair_mode, label):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"
    bt_pair_mode = pair_mode

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _configure_dut_pair_mode(ble_dut, bt_pair_mode)
    _enable_power_save(ble_dut=ble_dut)

    client_addresses = []
    for idx, client in enumerate(peripheral_clients):
        addr, servs, chars = _connect_single_peripheral(
            ble_dut, client, idx, bt_dut_address, svc,
            pair_mode=bt_pair_mode,
            target_ci=_peripheral_ci_for_index(idx),
        )
        client_addresses.append(addr)
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        assert char_path, f"Peripheral {idx + 1}: characteristic missing"

    for c_idx, central in enumerate(central_clients):
        _connect_single_central(
            ble_dut, central, c_idx, bt_dut_address, svc,
            pair_mode=bt_pair_mode,
            target_ci=_central_ci_for_index(c_idx),
        )

    _run_basic_soak(
        ble_dut,
        label=label,
        expected_peripheral_count=8,
        expected_central_count=2,
    )
    for addr in client_addresses:
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    for central in central_clients:
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)
        _cleanup_central_bluetooth_session(central, "Central final cleanup")


def _run_topology_visibility_test(
    ble_dut, ble_client, ble_clients, *, connected_peripherals, connected_centrals, scan_adv_only=False,
    scan_dut_on_central=False, label=""
):
    all_peripherals = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                       ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    connected_peripheral_clients = all_peripherals[:connected_peripherals]
    adv_only_client = all_peripherals[connected_peripherals] if scan_adv_only else None
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _enable_power_save(ble_dut=ble_dut)

    adv_only_address = None
    if adv_only_client is not None:
        adv_only_address = adv_only_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, service_classes=[svc]
        )
        assert adv_only_address, f"{label}: failed to start adv-only peripheral"
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()

    client_addresses = []
    for idx, client in enumerate(connected_peripheral_clients):
        addr, servs, chars = _connect_single_peripheral(
            ble_dut, client, idx, bt_dut_address, svc,
            pair_mode=PAIR_MODE_DEFAULT,
            target_ci=_peripheral_ci_for_index(idx),
        )
        client_addresses.append(addr)
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        assert char_path, f"Peripheral {idx + 1}: characteristic missing"

    for c_idx in range(connected_centrals):
        _connect_single_central(
            ble_dut, central_clients[c_idx], c_idx, bt_dut_address, svc,
            pair_mode=PAIR_MODE_DEFAULT, target_ci=_central_ci_for_index(c_idx),
        )

    scan_only_central = central_clients[connected_centrals] if scan_dut_on_central and connected_centrals < 2 else None
    if scan_only_central is not None:
        _cleanup_central_bluetooth_session(scan_only_central, f"{label}: Scan-only central pre-scan cleanup")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)
        _start_central_smp_scan_with_recovery(
            scan_only_central,
            {"bt_dut_address": bt_dut_address},
            c_idx=connected_centrals,
            attempt=1,
            max_attempts=1,
        )
        time.sleep(10)
        scan_only_central.interfaces.bluetooth.stop_scanning()
        found_devices = scan_only_central.interfaces.bluetooth.get_devices()
        assert bt_dut_address.upper() in found_devices, f"{label}: DUT not visible on scan-only central"

    for _ in range(5):
        if adv_only_address is not None:
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
            time.sleep(10)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if scan_only_central is not None:
            _cleanup_central_bluetooth_session(scan_only_central, f"{label}: Scan-only central loop pre-scan cleanup")
            _start_central_smp_scan_with_recovery(
                scan_only_central,
                {"bt_dut_address": bt_dut_address},
                c_idx=connected_centrals,
                attempt=1,
                max_attempts=1,
            )
            time.sleep(10)
            scan_only_central.interfaces.bluetooth.stop_scanning()
            _cleanup_central_bluetooth_session(scan_only_central, f"{label}: Scan-only central loop post-scan cleanup")
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(48)

    if scan_only_central is not None:
        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        _cleanup_central_bluetooth_session(scan_only_central, "Scan-only central final cleanup")
    for addr in client_addresses:
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    for c_idx in range(connected_centrals):
        central_clients[c_idx].interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)


def _run_diff_conn_intervals_test(ble_dut, ble_client, ble_clients, *, central_ci, label):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _enable_power_save(ble_dut=ble_dut)

    client_addresses = []
    for idx, client in enumerate(peripheral_clients):
        ci = _peripheral_ci_for_index(idx)
        addr, servs, chars = _connect_single_peripheral(
            ble_dut, client, idx, bt_dut_address, svc,
            pair_mode=PAIR_MODE_DEFAULT, target_ci=ci
        )
        client_addresses.append(addr)
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        assert char_path

    for c_idx, central in enumerate(central_clients):
        _connect_single_central(
            ble_dut, central, c_idx, bt_dut_address, svc,
            pair_mode=PAIR_MODE_DEFAULT, target_ci=central_ci
        )

    _run_basic_soak(
        ble_dut,
        label=label,
        expected_peripheral_count=8,
        expected_central_count=2,
    )
    for addr in client_addresses:
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    for central in central_clients:
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)
        _cleanup_central_bluetooth_session(central, "Central final cleanup")


def _run_reconnect_diff_ci_test(
    ble_dut,
    ble_client,
    ble_clients,
    *,
    label,
    iterations=5,
    peripheral_ci_map=None,
    central_ci_map=None,
    conn_latency=CONN_LATENCY,
    supervision_timeout=SUPERVISION_TIMEOUT,
):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _enable_power_save(ble_dut=ble_dut)

    for iteration in range(1, iterations + 1):
        client_addresses = []
        for idx, client in enumerate(peripheral_clients):
            target_ci = peripheral_ci_map.get(idx, _peripheral_ci_for_index(idx)) if peripheral_ci_map else _peripheral_ci_for_index(idx)
            addr, servs, chars = _connect_single_peripheral(
                ble_dut, client, idx, bt_dut_address, svc,
                pair_mode=PAIR_MODE_DEFAULT,
                target_ci=target_ci,
                conn_latency=conn_latency,
                supervision_timeout=supervision_timeout,
            )
            client_addresses.append((addr, client))
            char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
            )
            assert char_path
        for c_idx, central in enumerate(central_clients):
            target_ci = central_ci_map.get(c_idx, _central_ci_for_index(c_idx)) if central_ci_map else _central_ci_for_index(c_idx)
            _connect_single_central(
                ble_dut, central, c_idx, bt_dut_address, svc,
                pair_mode=PAIR_MODE_DEFAULT,
                target_ci=target_ci,
                conn_latency=conn_latency,
                supervision_timeout=supervision_timeout,
            )
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)
        for addr, client in client_addresses:
            client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)
            client.interfaces.bluetooth.close()
            time.sleep(1)
        for central in central_clients:
            central.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)
            _cleanup_central_bluetooth_session(central, "Central reconnect cleanup")
            time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)


def _run_peripheral_rx_central_reconnect_test(ble_dut, ble_client, ble_clients, *, label, iterations=5):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"
    bt_dut_address = None

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=0, mitm=1)
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth

    client_addresses = []
    rx_notify_threads = []
    rx_stop_flags = []
    rx_notify_handles = []
    cached_rx_notify_handles = {}
    rx_payload = _build_rx_payload(20)
    CUSTOM_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
    CUSTOM_CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
    for idx, client in enumerate(peripheral_clients):
        addr, servs, chars = _connect_single_peripheral(
            ble_dut, client, idx, bt_dut_address, svc, pair_mode=PAIR_MODE_PASSKEY, target_ci=_peripheral_ci_for_index(idx)
        )
        client_addresses.append(addr)
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
        )
        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=CUSTOM_CHAR_UUID)
        baseline = _capture_dut_log_baseline(ble_dut)
        bt_iface.ble_get_profiles_async(ble_remote_dev_address=addr)
        time.sleep(10)
        _enable_dut_rx_notifications(bt_iface, ble_dut, cached_rx_notify_handles, rx_notify_handles, addr, f"Peripheral {idx + 1}", baseline)
        _start_rx_notify_thread(rx_notify_threads, rx_stop_flags, client, svc, rx_payload, f"Peripheral {idx + 1}")

    for iteration in range(1, iterations + 1):
        for c_idx, central in enumerate(central_clients):
            _connect_single_central(
                ble_dut, central, c_idx, bt_dut_address, svc,
                pair_mode=PAIR_MODE_PASSKEY, target_ci=_central_ci_for_index(c_idx)
            )
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)
        for central in central_clients:
            central.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)
            _cleanup_central_bluetooth_session(central, "Central reconnect cleanup")
            time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

    _stop_rx_notify_threads(rx_stop_flags, rx_notify_threads, bt_iface, rx_notify_handles)
    for addr in client_addresses:
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)


def _run_central_notify_peripheral_reconnect_test(ble_dut, ble_client, ble_clients, *, label, iterations=5):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    svc = "HealthThermometerService"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=0, mitm=1)
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth
    for conn_id in (8, 9):
        _configure_background_notify_transfer_for_conn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=230)

    CUSTOM_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
    CUSTOM_CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"

    logger().info(f"{label}: PHASE 1 - connecting 2 centrals first and enabling TX notifications")
    for c_idx, central in enumerate(central_clients):
        central_ci = _central_ci_for_index(c_idx)
        central_address = _connect_single_central(
            ble_dut, central, c_idx, bt_dut_address, svc,
            pair_mode=PAIR_MODE_PASSKEY, target_ci=central_ci
        )

        central_servs, central_chars = [], []
        for attempt in range(1, 7):
            central_servs, central_chars = central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(central_servs) > 0 and len(central_chars) > 0:
                break
            logger().warning(
                f"{label}: Central {c_idx + 1} service discovery empty on attempt {attempt}/6"
            )
            time.sleep(5)
        assert len(central_servs) > 0 and len(central_chars) > 0, (
            f"{label}: Central {c_idx + 1} failed GATT discovery after connect"
        )

        central_char_path, _ = central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=central_servs,
            service_uid=CUSTOM_SERVICE_UUID,
            char_uid=CUSTOM_CHAR_UUID,
        )
        assert central_char_path, f"{label}: Central {c_idx + 1} characteristic path missing"
        central.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=central_char_path)
        central.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=central_char_path)
        central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=central_char_path,
            char_uid=CUSTOM_CHAR_UUID,
        )

        logger().info(
            f"{label}: Central {c_idx + 1} connected, subscribed, and ready for "
            f"230-byte DUT TX notifications (background TX was pre-armed)"
        )

    ble_dut.interfaces.bluetooth.ble_get_device_state()
    time.sleep(5)

    logger().info(f"{label}: PHASE 2 - reconnecting 8 peripherals for {iterations} iterations while 2 centrals stay up")
    for iteration in range(1, iterations + 1):
        logger().info(f"{label}: Peripheral reconnect iteration {iteration}/{iterations}")
        peripheral_addresses = []
        for idx, client in enumerate(peripheral_clients):
            addr, servs, chars = _connect_single_peripheral(
                ble_dut, client, idx, bt_dut_address, svc,
                pair_mode=PAIR_MODE_PASSKEY,
                target_ci=_peripheral_ci_for_index(idx),
            )
            peripheral_addresses.append((addr, client))
            char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=CUSTOM_SERVICE_UUID, char_uid=CUSTOM_CHAR_UUID
            )
            assert char_path, f"{label}: Peripheral {idx + 1} characteristic path missing"

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        for idx, (addr, client) in enumerate(peripheral_addresses):
            logger().info(f"{label}: Disconnecting peripheral {idx + 1} in iteration {iteration}")
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
            time.sleep(1)
            client.interfaces.bluetooth.close()
            time.sleep(0.5)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

    logger().info(f"{label}: PHASE 3 - disconnecting 2 centrals after peripheral churn completes")
    for central in central_clients:
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        _cleanup_central_bluetooth_session(central, "Central final cleanup")
        time.sleep(1)


def _run_tx_enable_disable_test(
    ble_dut,
    ble_client,
    ble_clients,
    *,
    pair_mode,
    payload_len,
    svc,
    transfer_config_fn,
    label,
    iterations=10,
):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]
    transfer_service_uuid, transfer_char_uuid = _uuid_pair_for_transfer(transfer_config_fn)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()
    _configure_dut_pair_mode(ble_dut, pair_mode)
    _enable_power_save(ble_dut=ble_dut)
    bt_iface = ble_dut.interfaces.bluetooth

    client_addresses = []
    peripheral_char_paths = []
    central_char_paths = []
    for conn_id in range(10):
        transfer_config_fn(bt_iface=bt_iface, conn_id=conn_id)
        _configure_background_payload_for_conn(bt_iface=bt_iface, conn_id=conn_id, payload_len=payload_len)
    for idx, client in enumerate(peripheral_clients):
        addr, servs, chars = _connect_single_peripheral(
            ble_dut, client, idx, bt_dut_address, svc,
            pair_mode=pair_mode,
            target_ci=_peripheral_ci_for_index(idx),
        )
        client_addresses.append(addr)
        char_path, _ = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=transfer_service_uuid, char_uid=transfer_char_uuid
        )
        assert char_path, f"{label}: Peripheral {idx + 1} characteristic missing"
        peripheral_char_paths.append(char_path)
    for c_idx, central in enumerate(central_clients):
        _connect_single_central(
            ble_dut, central, c_idx, bt_dut_address, svc,
            pair_mode=pair_mode,
            target_ci=_central_ci_for_index(c_idx),
        )
        central_servs, central_chars = central.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(central_servs) > 0 and len(central_chars) > 0, f"{label}: Central {c_idx + 1} failed GATT discovery"
        central_char_path, _ = central.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=central_servs, service_uid=transfer_service_uuid, char_uid=transfer_char_uuid
        )
        assert central_char_path, f"{label}: Central {c_idx + 1} characteristic missing"
        central_char_paths.append(central_char_path)
    for iteration in range(1, iterations + 1):
        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=peripheral_char_paths[idx])
            client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=peripheral_char_paths[idx], char_uid=transfer_char_uuid
            )
        for idx, central in enumerate(central_clients):
            central.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=central_char_paths[idx])
            central.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=central_char_paths[idx], char_uid=transfer_char_uuid
            )
        time.sleep(30)
        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=peripheral_char_paths[idx])
        for idx, central in enumerate(central_clients):
            central.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=central_char_paths[idx])
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(3)
    for addr in client_addresses:
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)
    for central in central_clients:
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)
        _cleanup_central_bluetooth_session(central, "Central final cleanup")


def _run_indicate_enable_disable_test(ble_dut, ble_client, ble_clients, *, label, iterations=10):
    _run_tx_enable_disable_test(
        ble_dut,
        ble_client,
        ble_clients,
        pair_mode=PAIR_MODE_PASSKEY,
        payload_len=230,
        svc="HealthThermometerService",
        transfer_config_fn=_configure_background_ind_transfer_for_conn,
        label=label,
        iterations=iterations,
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768088')
def test_8p_2c_connection_tx_indicate_20_bytes_just_works_C768088(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768088_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Just Works, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768089')
def test_8p_2c_connection_tx_write_with_resp_20_bytes_C768089(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768089_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_DEFAULT,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (default SMP, 20 bytes)",
            subscribe_peripheral=True,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768096')
def test_8p_2c_tx_notify_20_bytes_passkey_entry_C768096(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768096_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (Passkey Entry, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768098')
def test_8p_2c_tx_indicate_20_bytes_passkey_entry_C768098(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768098_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Passkey Entry, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
            defer_central_subscription_until_all_connected=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768099')
def test_8p_2c_tx_write_with_resp_20_bytes_passkey_entry_C768099(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768099_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (Passkey Entry, 20 bytes)",
            subscribe_peripheral=True,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768101')
def test_8p_2c_connection_tx_notify_230_bytes_C768101(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768101_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_DEFAULT,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (default SMP, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768103')
def test_2c_8p_connection_tx_indicate_230_bytes_just_works_C768103(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768103_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Just Works, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768104')
def test_2c_8p_connection_tx_write_with_resp_230_bytes_just_works_C768104(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768104_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (Just Works, 230 bytes)",
            subscribe_peripheral=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768111')
def test_8p_2c_tx_notify_230_bytes_passkey_entry_C768111(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768111_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (Passkey Entry, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768113')
def test_8p_2c_tx_indicate_230_bytes_passkey_entry_C768113(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768113_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Passkey Entry, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
            defer_central_subscription_until_all_connected=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768114')
def test_8p_2c_tx_write_with_resp_230_bytes_passkey_entry_C768114(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768114_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (Passkey Entry, 230 bytes)",
            subscribe_peripheral=True,
        ),
    )



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768082')
def test_2c_tx_notify_8p_rx_notify_20_bytes_nonsecure_C768082(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768082_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NONSECURE,
            payload_len=20,
            label="C768082",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768087')
def test_2c_tx_notify_8p_rx_notify_20_bytes_just_works_C768087(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768087_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=20,
            label="C768087",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768097')
def test_2c_tx_notify_8p_rx_notify_20_bytes_passkey_entry_C768097(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768097_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=20,
            label="C768097",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768102')
def test_2c_tx_notify_230_bytes_8p_rx_notify_just_works_C768102(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768102_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=230,
            label="C768102",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768112')
def test_2c_tx_notify_8p_rx_notify_230_bytes_passkey_entry_C768112(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768112_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=230,
            label="C768112",
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768119')
def test_2c_tx_notify_8p_tx_indicate_230_bytes_passkey_entry_C768119(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768119_sniffer_capture",
        lambda: _run_8p_2c_mixed_tx_test(
            ble_dut, ble_client, ble_clients,
            payload_len=230,
            label="C768119",
            peripheral_svc="HealthThermometerService",
            peripheral_transfer_config_fn=_configure_background_ind_transfer_for_conn,
            peripheral_subscribe=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768120')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_passkey_entry_C768120(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768120_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=20, label="C768120"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768121')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_passkey_entry_C768121(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768121_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=230, label="C768121"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768122')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_2m_phy_passkey_entry_C768122(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768122_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=20, label="C768122"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768123')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_2m_phy_passkey_entry_C768123(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768123_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=230, label="C768123"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768124')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_coded_phy_500kbps_passkey_entry_C768124(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768124_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=20, label="C768124"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768125')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_coded_phy_500kbps_passkey_entry_C768125(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768125_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=230, label="C768125"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768126')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_coded_phy_125kbps_passkey_entry_C768126(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768126_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=20, label="C768126"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768127')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_coded_phy_125kbps_passkey_entry_C768127(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768127_sniffer_capture",
        lambda: _run_8p_2c_bidirectional_notify_test(
            ble_dut, ble_client, ble_clients, payload_len=230, label="C768127"
        ),
    )



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768068')
def test_adv_211ms_scan_33ms_C768068(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768068_sniffer_capture",
        lambda: _run_adv_scan_visibility_test(
            ble_dut, ble_client, ble_clients,
            scan_interval=53, scan_window=53, label="C768068"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768069')
def test_adv_211ms_scan_si33_sw14_C768069(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768069_sniffer_capture",
        lambda: _run_adv_scan_visibility_test(
            ble_dut, ble_client, ble_clients,
            scan_interval=53, scan_window=23, label="C768069"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768070')
def test_adv_211ms_scan_si33_sw11_C768070(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768070_sniffer_capture",
        lambda: _run_adv_scan_visibility_test(
            ble_dut, ble_client, ble_clients,
            scan_interval=53, scan_window=18, label="C768070"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768071')
def test_adv_211ms_scan_si6600_sw3300_C768071(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768071_sniffer_capture",
        lambda: _run_adv_scan_visibility_test(
            ble_dut, ble_client, ble_clients,
            scan_interval=10560, scan_window=5280, label="C768071"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768072')
def test_8p_1c_adv_with_connections_C768072(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768072_sniffer_capture",
        lambda: _run_topology_visibility_test(
            ble_dut, ble_client, ble_clients,
            connected_peripherals=8,
            connected_centrals=1,
            scan_adv_only=False,
            scan_dut_on_central=True,
            label="C768072",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768073')
def test_7p_2c_scan_with_connections_C768073(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768073_sniffer_capture",
        lambda: _run_topology_visibility_test(
            ble_dut, ble_client, ble_clients,
            connected_peripherals=7,
            connected_centrals=2,
            scan_adv_only=True,
            scan_dut_on_central=False,
            label="C768073",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768074')
def test_7p_1c_adv_scan_with_connections_C768074(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768074_sniffer_capture",
        lambda: _run_topology_visibility_test(
            ble_dut, ble_client, ble_clients,
            connected_peripherals=7,
            connected_centrals=1,
            scan_adv_only=True,
            scan_dut_on_central=True,
            label="C768074",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768075')
def test_2c_8p_diff_conn_intervals_C768075(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768075_sniffer_capture",
        lambda: _run_diff_conn_intervals_test(
            ble_dut, ble_client, ble_clients, central_ci=9, label="C768075"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768076')
def test_8p_2c_diff_conn_intervals_C768076(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768076_sniffer_capture",
        lambda: _run_diff_conn_intervals_test(
            ble_dut, ble_client, ble_clients, central_ci=36, label="C768076"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768077')
def test_8p_2c_conn_disconn_reconn_diff_ci_C768077(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768077_sniffer_capture",
        lambda: _run_reconnect_diff_ci_test(
            ble_dut,
            ble_client,
            ble_clients,
            label="C768077",
            iterations=5,
            peripheral_ci_map={
                0: 80,   # P1: 100 ms
                1: 160,  # P2: 200 ms
                2: 160,  # P3: 200 ms
                3: 160,  # P4: 200 ms
                4: 160,  # P5: 200 ms
                5: 240,  # P6: 300 ms
                6: 240,  # P7: 300 ms
                7: 240,  # P8: 300 ms
            },
            central_ci_map={
                0: 96,   # C1: 120 ms
                1: 96,   # C2: 120 ms
            },
            conn_latency=0,
            supervision_timeout=400,  # 4000 ms
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768078')
def test_8p_2c_just_works_pairing_C768078(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768078_sniffer_capture",
        lambda: _run_pairing_only_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS, label="C768078"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768080')
def test_8p_2c_passkey_entry_pairing_C768080(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768080_sniffer_capture",
        lambda: _run_pairing_only_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY, label="C768080"
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768116')
def test_8p_rx_notify_2c_disconn_reconn_passkey_entry_C768116(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768116_sniffer_capture",
        lambda: _run_peripheral_rx_central_reconnect_test(
            ble_dut, ble_client, ble_clients, label="C768116", iterations=5
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768117')
def test_2c_tx_notify_230_8p_disconn_reconn_passkey_entry_C768117(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768117_sniffer_capture",
        lambda: _run_central_notify_peripheral_reconnect_test(
            ble_dut, ble_client, ble_clients, label="C768117", iterations=5
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768129')
def test_2c_8p_indicate_enable_disable_230_bytes_passkey_entry_C768129(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768129_sniffer_capture",
        lambda: _run_indicate_enable_disable_test(
            ble_dut, ble_client, ble_clients, label="C768129", iterations=10
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768079')
def test_2c_8p_numeric_comparison_pairing_C768079(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768079_sniffer_capture",
        lambda: _run_pairing_only_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            label="C768079",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768091')
def test_8p_2c_tx_notify_20_bytes_numeric_comparison_C768091(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768091_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (Numeric Comparison, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768092')
def test_2c_tx_notify_8p_rx_notify_20_bytes_numeric_comparison_C768092(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768092_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=20,
            label="C768092",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768093')
def test_8p_2c_tx_indicate_20_bytes_numeric_comparison_C768093(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768093_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Numeric Comparison, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768106')
def test_2c_8p_tx_notify_230_bytes_numeric_comparison_C768106(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768106_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (Numeric Comparison, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768107')
def test_2c_tx_notify_8p_rx_notify_230_bytes_numeric_comparison_C768107(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768107_sniffer_capture",
        lambda: _run_8p_2c_split_notify_rx_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            label="C768107",
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768108')
def test_2c_8p_tx_indicate_230_bytes_numeric_comparison_C768108(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768108_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (Numeric Comparison, 230 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768128')
def test_2c_8p_notify_enable_disable_230_bytes_numeric_comparison_C768128(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768128_sniffer_capture",
        lambda: _run_tx_enable_disable_test(
            ble_dut,
            ble_client,
            ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            label="C768128",
            iterations=10,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768081')
def test_8p_2c_connection_tx_notify_20_bytes_nonsecure_C768081(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768081_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NONSECURE,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (non-secure, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768083')
def test_8p_2c_connection_tx_indicate_20_bytes_nonsecure_C768083(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768083_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NONSECURE,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_ind_transfer_for_conn,
            transfer_label="indicate (non-secure, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768086')
def test_8p_2c_connection_tx_notify_20_bytes_C768086(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768086_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_DEFAULT,
            payload_len=20,
            svc="HealthThermometerService",
            transfer_config_fn=_configure_background_notify_transfer_for_conn,
            transfer_label="notify (default SMP, 20 bytes)",
            subscribe_peripheral=True,
            subscribe_central=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768084')
def test_8p_2c_connection_tx_write_with_resp_20_bytes_nonsecure_C768084(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768084_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NONSECURE,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (non-secure, 20 bytes)",
            subscribe_peripheral=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768109')
def test_2c_8p_tx_write_with_resp_230_bytes_numeric_comparison_C768109(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768109_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (Numeric Comparison, 230 bytes)",
            subscribe_peripheral=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768094')
def test_8p_2c_tx_write_with_resp_20_bytes_numeric_comparison_C768094(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768094_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wwr_transfer_for_conn,
            transfer_label="write-with-resp (Numeric Comparison, 20 bytes)",
            subscribe_peripheral=True,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768090')
def test_8p_2c_connection_tx_write_no_resp_20_bytes_C768090(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768090_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_DEFAULT,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (default SMP, 20 bytes)",
            subscribe_peripheral=False,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768100')
def test_8p_2c_tx_write_no_resp_20_bytes_passkey_entry_C768100(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768100_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (Passkey Entry, 20 bytes)",
            subscribe_peripheral=False,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768105')
def test_2c_8p_connection_tx_write_no_resp_230_bytes_just_works_C768105(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768105_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_JUST_WORKS,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (Just Works, 230 bytes)",
            subscribe_peripheral=False,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768115')
def test_8p_2c_tx_write_no_resp_230_bytes_passkey_entry_C768115(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768115_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_PASSKEY,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (Passkey Entry, 230 bytes)",
            subscribe_peripheral=False,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768118')
def test_2c_tx_notify_8p_tx_write_no_resp_230_bytes_passkey_entry_C768118(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768118_sniffer_capture",
        lambda: _run_8p_2c_mixed_tx_test(
            ble_dut, ble_client, ble_clients,
            payload_len=230,
            label="C768118",
            peripheral_svc="GenericDataService",
            peripheral_transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            peripheral_subscribe=False,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768085')
def test_2c_8p_connection_tx_write_no_resp_20_bytes_nonsecure_C768085(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768085_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NONSECURE,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (non-secure, 20 bytes)",
            subscribe_peripheral=False,
        ),
    )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768110')
def test_2c_8p_tx_write_no_resp_230_bytes_numeric_comparison_C768110(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768110_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=230,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (Numeric Comparison, 230 bytes)",
            subscribe_peripheral=False,
        ),
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id('C768095')
def test_8p_2c_tx_write_no_resp_20_bytes_numeric_comparison_C768095(
    ble_dut, ble_client, ble_clients, ble_sniffer
):
    _run_with_ble_sniffer_capture(
        ble_sniffer,
        "test_C768095_sniffer_capture",
        lambda: _run_8p_2c_all_tx_background_test(
            ble_dut, ble_client, ble_clients,
            pair_mode=PAIR_MODE_NUMERIC,
            payload_len=20,
            svc="GenericDataService",
            transfer_config_fn=_configure_background_wnr_transfer_for_conn,
            transfer_label="write-no-resp (Numeric Comparison, 20 bytes)",
            subscribe_peripheral=False,
        ),
    )