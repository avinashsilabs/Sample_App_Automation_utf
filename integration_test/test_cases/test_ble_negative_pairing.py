import time
import pytest
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116AsyncEventType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands


pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        },
    ),
]


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "DisplayOnly", -1),  # Do not respond to authorization request
        (1, "DisplayYesNo", -1),  # Do not confirm passkey
        (2, "KeyboardOnly", 123456),  # Wrong passkey
        (2, "KeyboardOnly", -1),  # Do not respond to passkey request
        (3, "NoInputNoOutput", -1),  # Do not respond to authorization request
    ],
)
@pytest.mark.test_src_map_id('SM11813')
def test_ble_advertisement_wrong_pass_key(
    wifi_dut,
    wifi_access_point,
    ble_client,
    logger,
    dut_capability,
    client_capability,
    pin_code,
):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=dut_capability)
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    # pin_code should be 0 to make the test case as pass_key was set to 0 in test agent
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        pin_code=pin_code, capability=client_capability, bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
        ):
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    start_time = time.perf_counter_ns()

    connected = ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    time.sleep(1)
    assert not connected

    smp_failed_event_found = False

    events = wifi_dut.interfaces.wifi.get_async_events(since_time=start_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.RSI_BLE_SMP_FAILED_EVENT:
            smp_failed_event_found = True

    assert smp_failed_event_found, "SMP Failed event not found"


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "DisplayOnly", -1),  # Do not respond to authorization request
        (1, "DisplayYesNo", -1),  # Do not confirm passkey
        (2, "KeyboardOnly", 123456),  # Wrong passkey
        (2, "KeyboardOnly", -1),  # Do not respond to passkey request
        (3, "NoInputNoOutput", -1),  # Do not respond to authorization request
    ],
)
@pytest.mark.test_src_map_id('SM11819')
def test_ble_scanning_wrong_pass_key(
    wifi_dut,
    wifi_access_point,
    ble_client,
    logger,
    dut_capability,
    client_capability,
    pin_code,
):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=dut_capability)
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        pin_code=pin_code, capability=client_capability, bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(
        ble_client_address=bt_client_address, timeout=60
    )
    timeout = 120
    start_time = time.perf_counter_ns()

    wifi_dut.interfaces.wifi.ble_connect(
        ble_remote_dev_address=bt_client_address,
        expected="RSI_BLE_SMP_FAILED_EVENT", timeout=timeout
    )

    smp_failed_event_found = False

    events = wifi_dut.interfaces.wifi.get_async_events(since_time=start_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.RSI_BLE_SMP_FAILED_EVENT:
            smp_failed_event_found = True

    assert smp_failed_event_found, "SMP Failed event not found"
