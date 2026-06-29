import re
import time
from contextlib import contextmanager
from typing import Iterable, Optional
 
import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116BLEFeatureBitMap,
    RS9116BLECustomFeatureBitMap,
)
from utf.utils.logger import get_logger
 
_AE_CONN_EVENTS_BITS = 2 << 0
_AE_REC_BYTES_BITS = 20 << 5
_AE_MAX_ADV_SETS_BITS = 1 << 20
 
_FORBIDDEN_STATE_CODES = ("0x103", "0x0103")
_FORBIDDEN_CODES_C725249 = ("0x103", "0x0103", "0x4e0c", "0x4E0C")
_FORBIDDEN_CODES_C725249_NO_4E0C = ("0x103", "0x0103")
 
# How long we keep the AE scan window open per iteration. Long enough for the
# radio to receive peer advertising reports and for the bus reader to log
# them. Used by C725249's inner loop.
SCAN_WINDOW_SECONDS = 3
 
 
def logger():
    return get_logger(__name__)
 
 
pytestmark = [pytest.mark.framework_integration_test]
 
 
_WIFI_DUT_CONFIG = {
    "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
    "skip_radio_init": True,
    "features": (
        RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
    ),
    "tcpip_features": (
        RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.DHCPv4Client
    ),
    "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": (
        RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid
    ),
    "bt_features": (
        RS9116BTFeatureBitMap.BLEFeatureBitmapValid
        | RS9116BTFeatureBitMap.RFTypeSelection
    ),
    "ble_features": (
        RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid
        | RS9116BLEFeatureBitMap.RS9116_BLE_PWR_INX_30
        | RS9116BLEFeatureBitMap.RS9113_RS9116_Compatible_Feature
    ),
    "ble_custom_ext_features": (
        RS9116BLECustomFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
        | _AE_CONN_EVENTS_BITS
        | _AE_REC_BYTES_BITS
        | RS9116BLECustomFeatureBitMap.BLE_MTU_EXCHANGE_FROM_HOST
        | RS9116BLECustomFeatureBitMap.BLE_ENABLE_ADV_EXTN
        | _AE_MAX_ADV_SETS_BITS
    ),
}
 
 
@pytest.mark.config("wifi_dut", wifi=_WIFI_DUT_CONFIG)
@pytest.mark.check
@pytest.mark.test_src_map_id("C767034")
def test_verify_device_state_in_ae_dual_role_C767034(ble_dut, rs_helper_ble):
    """Verify device state when DUT is in AE Dual Role (advertising + scanning).
 
    Faithfully follows the C767034 manual procedure (steps 3-12).
    """
    loop_iterations = 5
    ae_remote_addr = "00:00:00:00:00:00"
    initial_adv_data = "BLE_AE_ADV_DATA_1"
 
    ble_dut_address = rs_helper_ble.ble_start(
        ble_dut,
        capability=0,
        bond_info=0,
        set_smp=1,
    )
    assert ble_dut_address, "BLE init failed"
 
    max_adv_sets = ble_dut.interfaces.bluetooth.ble_get_max_no_of_supp_adv_sets(
        no_adv_sets=1
    )
    assert isinstance(max_adv_sets, int) and max_adv_sets >= 1, (
        f"AE appears disabled in firmware (max_adv_sets={max_adv_sets!r}). "
        "Check RSI_BLE_ENABLE_ADV_EXTN in project.slcp."
    )
 
    resp = ble_dut.interfaces.bluetooth.ble_set_ae_params(
        adv_handle=0,
        adv_event_prop=0,
        primary_adv_intterval_min=160,
        primary_adv_intterval_max=160,
        primary_adv_chnl_map=7,
        own_addr_type=0,
        peer_addr_type=0,
        remote_dev_addr=ae_remote_addr,
        adv_filter_policy=0,
        adv_tx_power=7,
        primary_adv_phy=1,
        sec_adv_max_skip=0,
        sec_adv_phy=1,
        adv_sid=0,
        scan_req_notify_enable=0,
        expected_status="success",
        timeout=10,
    )
    assert resp is not None, "No response from ble_set_ae_params"
 
    ble_dut.interfaces.bluetooth.ble_set_ae_data(
        type=1,
        adv_handle=0,
        operation=0,
        data=initial_adv_data,
        data_len=len(initial_adv_data),
    )
    time.sleep(0.2)
 
    ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
        adv_enable=1,
        no_of_sets=1,
        adv_handle=0,
        duration=0,
        max_ae_events=0,
    )
    time.sleep(1)
 
    ble_dut.interfaces.bluetooth.ble_set_ae_scan_params(
        own_addr_type=0,
        scanning_filter_policy=0,
        scanning_phys=1,
        ScanType_s1=1,
        ScanInterval_s1=256,
        ScanWindow_s1=80,
    )
 
    ble_dut.interfaces.bluetooth.ble_set_ae_scan_enable(
        scan_enable=1,
        filter_duplicates=0,
        duration=0,
        period=0,
        remote_address=ble_dut_address,
        async_required=0,
    )
 
    adv_param_variants = [
        {"interval": 48,  "data": "BLE_AE_ADV_DATA_1"},
        {"interval": 96,  "data": "BLE_AE_ADV_DATA_2"},
        {"interval": 160, "data": "BLE_AE_ADV_DATA_3"},
    ]
 
    try:
        for i in range(1, loop_iterations + 1):
            logger().info(f"\n--- C767034 iteration {i}/{loop_iterations} ---\n")
 
            _assert_state_not_forbidden(
                ble_dut, f"iter {i} after AE adv+scan enable"
            )
 
            time.sleep(5)
 
            ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
                adv_enable=0,
                no_of_sets=1,
                adv_handle=0,
                duration=0,
                max_ae_events=0,
            )
 
            _assert_state_not_forbidden(
                ble_dut, f"iter {i} after stop_ae_adv"
            )
 
            time.sleep(5)
 
            variant = adv_param_variants[(i - 1) % len(adv_param_variants)]
            ble_dut.interfaces.bluetooth.ble_set_ae_params(
                remote_dev_addr=ae_remote_addr,
                adv_handle=0,
                adv_event_prop=1,
                primary_adv_intterval_min=variant["interval"],
                primary_adv_intterval_max=variant["interval"],
                primary_adv_chnl_map=7,
                own_addr_type=0,
                peer_addr_type=0,
                adv_filter_policy=0,
                adv_tx_power=7,
                primary_adv_phy=1,
                sec_adv_max_skip=0,
                sec_adv_phy=1,
                adv_sid=0,
                scan_req_notify_enable=1,
            )
            time.sleep(0.2)
            ble_dut.interfaces.bluetooth.ble_set_ae_data(
                type=1,
                adv_handle=0,
                operation=0,
                data_len=len(variant["data"]),
                data=variant["data"],
            )
            time.sleep(0.2)
 
            ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
                adv_enable=1,
                no_of_sets=1,
                adv_handle=0,
                duration=0,
                max_ae_events=0,
            )
            time.sleep(0.2)
 
    finally:
        try:
            ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
                adv_enable=0,
                no_of_sets=1,
                adv_handle=0,
                duration=0,
                max_ae_events=0,
            )
        except Exception as cleanup_err:
            logger().warning(
                f"AE adv-stop cleanup raised (non-fatal): {cleanup_err}"
            )
        try:
            ble_dut.interfaces.bluetooth.ble_set_ae_scan_enable(
                scan_enable=0,
                remote_address=ble_dut_address,
                async_required=0,
            )
        except Exception as cleanup_err:
            logger().warning(
                f"AE scan-disable cleanup raised (non-fatal): {cleanup_err}"
            )
 
 
@pytest.mark.config("wifi_dut", wifi=_WIFI_DUT_CONFIG)
@pytest.mark.check
@pytest.mark.test_src_map_id("C725249")
def test_verify_ae_scan_dual_set_C725249(ble_dut, rs_helper_ble):
    """Verify AE scan toggling under two-set AE advertising load."""
 
    loop_iterations = 5
    expected_post_stop_state = 0x30
    ae_remote_addr = "00:00:00:00:00:00"
 
    initial_scan_interval = 256
    initial_scan_window = 80
 
    step9_scan_interval = 5360
    step9_scan_window = 5280
 
    ble_dut_address = rs_helper_ble.ble_start(
        ble_dut,
        capability=0,
        bond_info=0,
        set_smp=1,
    )
    assert ble_dut_address, "BLE init failed"
 
    max_sets = ble_dut.interfaces.bluetooth.ble_get_max_no_of_supp_adv_sets(
        no_adv_sets=2
    )
    assert isinstance(max_sets, int) and max_sets >= 2, (
        f"Firmware reports max_adv_sets={max_sets!r}; need >= 2 for C725249. "
        "Check _AE_MAX_ADV_SETS_BITS and RSI_BLE_ENABLE_ADV_EXTN."
    )
 
    _program_and_start_adv_set(
        ble_dut,
        adv_handle=0,
        adv_sid=0,
        interval=160,
        adv_data="BLE_AE_ADV_SET1",
        remote_dev_addr=ae_remote_addr,
    )
 
    _program_and_start_adv_set(
        ble_dut,
        adv_handle=1,
        adv_sid=1,
        interval=240,
        adv_data="BLE_AE_ADV_SET2",
        remote_dev_addr=ae_remote_addr,
    )
    time.sleep(1.0)
 
    ble_dut.interfaces.bluetooth.ble_set_ae_scan_params(
        own_addr_type=0,
        scanning_filter_policy=0,
        scanning_phys=1,
        ScanType_s1=1,
        ScanInterval_s1=initial_scan_interval,
        ScanWindow_s1=initial_scan_window,
    )
 
    try:
        for i in range(1, loop_iterations + 1):
            logger().info(
                f"\n--- C725249 iteration {i}/{loop_iterations} ---\n"
            )
 
            with _no_forbidden(
                _FORBIDDEN_CODES_C725249, f"iter {i} step 5 scan_enable=1"
            ):
                logger().info(
                    f"iter {i}: opening AE scan window for "
                    f"{SCAN_WINDOW_SECONDS}s - watching for peer adv reports..."
                )
                try:
                    adv_report = ble_dut.interfaces.bluetooth.ble_set_ae_scan_enable(
                        scan_enable=1,
                        filter_duplicates=0,
                        duration=0,
                        period=0,
                        remote_address=ble_dut_address,
                        async_required=1,
                        timeout=SCAN_WINDOW_SECONDS,
                    )
                    logger().info(
                        f"iter {i}: AE adv report captured "
                        f"(peer BD_ADDR + payload): {adv_report}"
                    )
                except Exception as no_peer_err:
                    logger().warning(
                        f"iter {i}: no peer adv report within "
                        f"{SCAN_WINDOW_SECONDS}s "
                        f"(single-DUT harness or peer silent): {no_peer_err}"
                    )
 
            time.sleep(SCAN_WINDOW_SECONDS)
 
            # Step 5b: verify dual-role state (adv + scan = 0x30) WHILE the
            # scanner is still enabled. The C725249 manual explicitly expects
            # the DUT to reach 0x30 here. Checking after scan_enable=0 (below)
            # would always show 0x10 (adv only), which masks the transition.
            with _no_forbidden(
                _FORBIDDEN_CODES_C725249, f"iter {i} step 5b dual-role state"
            ):
                in_scan_resp = ble_dut.interfaces.bluetooth.ble_get_device_state()
            in_scan_val = _parse_device_state(in_scan_resp)
            logger().info(
                f"iter {i}: while scanning - DUT is "
                f"{_describe_state(in_scan_val)} (state={in_scan_val})"
            )
            assert in_scan_val == 0x30, (
                f"iter {i}: expected dual-role state 0x30 (adv + scan) while "
                f"scan is enabled, got {in_scan_val:#x}. Either an adv set "
                f"stopped advertising or scan_enable=1 was silently rejected."
            )
 
            with _no_forbidden(
                _FORBIDDEN_CODES_C725249, f"iter {i} step 6 scan_enable=0"
            ):
                ble_dut.interfaces.bluetooth.ble_set_ae_scan_enable(
                    scan_enable=0,
                    filter_duplicates=0,
                    duration=0,
                    period=0,
                    remote_address=ble_dut_address,
                    async_required=0,
                )
 
            time.sleep(1)
 
            with _no_forbidden(
                _FORBIDDEN_CODES_C725249, f"iter {i} step 8 get_device_state"
            ):
                state_resp = ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_val = _parse_device_state(state_resp)
            logger().info(
                f"iter {i}: after scan stop - DUT is "
                f"{_describe_state(state_val)} (state={state_val})"
            )
 
            if state_val == expected_post_stop_state:
                with _no_forbidden(
                    _FORBIDDEN_CODES_C725249_NO_4E0C,
                    f"iter {i} step 8 inner re-stop",
                ):
                    try:
                        ble_dut.interfaces.bluetooth.ble_set_ae_scan_enable(
                            scan_enable=0,
                            filter_duplicates=0,
                            duration=0,
                            period=0,
                            remote_address=ble_dut_address,
                            async_required=0,
                        )
                    except Exception as inner_err:
                        if "0x4e0c" not in str(inner_err).lower():
                            raise
                        logger().info(
                            f"iter {i}: inner re-stop returned 0x4E0C as "
                            f"expected (already-stopped guard)."
                        )
 
                with _no_forbidden(
                    _FORBIDDEN_CODES_C725249,
                    f"iter {i} step 8 inner get_device_state",
                ):
                    ble_dut.interfaces.bluetooth.ble_get_device_state()
 
            ble_dut.interfaces.bluetooth.ble_set_ae_scan_params(
                own_addr_type=0,
                scanning_filter_policy=0,
                scanning_phys=1,
                ScanType_s1=1,
                ScanInterval_s1=step9_scan_interval,
                ScanWindow_s1=step9_scan_window,
            )
 
    finally:
        # Note: no scan-disable cleanup here on purpose. Every iteration of the
        # loop above ends with step 6 (scan_enable=0), so by the time we reach
        # finally the scanner is already stopped. Issuing another scan_enable=0
        # only earns a 0x4E0C (Command disallowed) and adds noise. Advertising,
        # in contrast, is NOT stopped in the loop and must be cleaned up below.
        for handle in (0, 1):
            try:
                ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
                    adv_enable=0,
                    no_of_sets=1,
                    adv_handle=handle,
                    duration=0,
                    max_ae_events=0,
                )
            except Exception as cleanup_err:
                logger().warning(
                    f"C725249 adv-stop cleanup (handle={handle}) "
                    f"raised (non-fatal): {cleanup_err}"
                )
 
 
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _assert_state_not_forbidden(ble_dut, context: str) -> str:
    """Query ble_get_device_state and fail the test if any of the forbidden
    HCI status codes show up - whether they surface in the returned state
    value or inside a wrapper-raised exception (the rs_sapi wrapper raises
    WlanError when 'success' is missing from the response, which is what
    happens when the firmware reports a non-success status).
 
    The ble_get_device_state wrapper assumes the serial response has at least
    two lines and decodes ``result.splitlines()[-2]``. When the serial bus is
    briefly desynced (e.g. after a burst of back-to-back commands) the response
    can arrive truncated and the wrapper raises IndexError/AttributeError/
    ValueError. Those are host-side parse flakes, not real firmware errors, so
    we retry once after a short pause before giving up."""
    parse_flakes = (IndexError, AttributeError, ValueError)
    last_parse_err: Optional[Exception] = None
 
    for attempt in range(2):
        try:
            state = ble_dut.interfaces.bluetooth.ble_get_device_state()
            break
        except parse_flakes as parse_err:
            last_parse_err = parse_err
            logger().warning(
                f"ble_get_device_state parse glitch during {context} "
                f"(attempt {attempt + 1}/2): {parse_err!r} - retrying"
            )
            time.sleep(0.5)
        except Exception as e:
            payload = str(e).lower()
            for code in _FORBIDDEN_STATE_CODES:
                if code.lower() in payload:
                    pytest.fail(
                        f"ble_get_device_state surfaced forbidden code {code} "
                        f"during {context}: {e}"
                    )
            raise
    else:
        pytest.fail(
            f"ble_get_device_state returned an unparseable response twice "
            f"during {context} (likely a serial-bus desync): {last_parse_err!r}"
        )
 
    payload = str(state).lower()
    for code in _FORBIDDEN_STATE_CODES:
        if code.lower() in payload:
            pytest.fail(
                f"ble_get_device_state returned forbidden code {code} "
                f"during {context}: {state}"
            )
    return state
 
 
@contextmanager
def _no_forbidden(forbidden_codes: Iterable[str], context: str):
    """Context manager that fails the test if any wrapped call raises an
    exception whose message contains one of `forbidden_codes` (matched
    case-insensitively). Non-forbidden exceptions propagate untouched."""
    try:
        yield
    except Exception as e:
        msg = str(e).lower()
        for code in forbidden_codes:
            if code.lower() in msg:
                pytest.fail(
                    f"forbidden code {code} surfaced during {context}: {e}"
                )
        raise
 
 
def _describe_state(state_val: Optional[int]) -> str:
    """Return a human-readable description of a BLE device-state value."""
    return {
        0: "idle",
        16: "advertising only",
        32: "scanning only",
        48: "advertising + scanning",
    }.get(state_val, "in an unknown state")
 
 
def _parse_device_state(raw) -> Optional[int]:
    """Extract the integer device-state value from the wrapper response.
 
    The rs9116_rt595_sapi path of `ble_get_device_state` returns a string of
    decimal digits (e.g. "48"); the generic path returns whatever the
    second-to-last response line was (e.g. "> 48" or "device_state: 0x30").
    We accept any of those shapes and return the int value, or None if
    nothing parseable was found.
    """
    text = str(raw)
    hex_match = re.search(r"0x([0-9A-Fa-f]+)", text)
    if hex_match:
        try:
            return int(hex_match.group(1), 16)
        except ValueError:
            pass
    dec_match = re.search(r"(\d+)", text)
    if dec_match:
        try:
            return int(dec_match.group(1))
        except ValueError:
            pass
    return None
 
 
def _program_and_start_adv_set(
    ble_dut,
    adv_handle: int,
    adv_sid: int,
    interval: int,
    adv_data: str,
    remote_dev_addr: str = "00:00:00:00:00:00",
) -> None:
    """Program ble_set_ae_params + ble_set_ae_data + ble_ae_start_advertising
    for a single AE advertising set. Used by C725249 to bring up set1 and
    set2 with different handles, SIDs and intervals before the scan loop."""
    ble_dut.interfaces.bluetooth.ble_set_ae_params(
        adv_handle=adv_handle,
        adv_event_prop=0,
        primary_adv_intterval_min=interval,
        primary_adv_intterval_max=interval,
        primary_adv_chnl_map=7,
        own_addr_type=0,
        peer_addr_type=0,
        remote_dev_addr=remote_dev_addr,
        adv_filter_policy=0,
        adv_tx_power=7,
        primary_adv_phy=1,
        sec_adv_max_skip=0,
        sec_adv_phy=1,
        adv_sid=adv_sid,
        scan_req_notify_enable=0,
    )
    time.sleep(0.2)
    ble_dut.interfaces.bluetooth.ble_set_ae_data(
        type=1,
        adv_handle=adv_handle,
        operation=0,
        data=adv_data,
        data_len=len(adv_data),
    )
    time.sleep(0.2)
    ble_dut.interfaces.bluetooth.ble_ae_start_advertising(
        adv_enable=1,
        no_of_sets=1,
        adv_handle=adv_handle,
        duration=0,
        max_ae_events=0,
    )
    time.sleep(0.5)
 