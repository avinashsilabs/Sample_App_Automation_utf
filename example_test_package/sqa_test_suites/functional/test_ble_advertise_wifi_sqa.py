# Test author: Vinod.G
# Test suite: BLE GAP test suite
import time
import pytest

from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
)
from utf.interfaces.wifi import WlanError

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in Wifi+Bluetooth dual mode
        2. Put DUT in BLE advertising mode
        3. Put RaspberryPi in scan mode
        4. Initiate connection from Raspberry pi over BLE
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake
            | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
            | RS9116ExtCustomFeatureBitMap.FeatureLowPower
            | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
        },
    )
]


def test_ble_undirected_connectable_adv_T3244(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_connectable_adv_T3244_{int(time.time())}.log",
    ) as bt_logs:
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
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
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type


# def test_ble_undirected_connectable_adv_T3245(wifi_dut, ble_client, bt_logs):
#
#     # Set up DUT for BLE advertising
#     wifi_dut.interfaces.wifi.ble_start()
#     wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=129)
#
#     # Begin Scanning for BLE devices
#     ble_client.interfaces.bluetooth.start_scanning()
#     time.sleep(5)
#
#     # Stop advertising and quit scanning
#     wifi_dut.interfaces.wifi.ble_stop_advertising()
#     ble_client.interfaces.bluetooth.stop_scanning()
#     bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
#
#     assert 'Connectable undirected - ADV_IND (0x00)' in bt_logs.device_adv_type


def test_ble_undirected_scannable_adv_T3246(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_scannable_adv_T3246_{int(time.time())}.log",
    ) as bt_logs:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=130)

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
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
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        assert "Scannable undirected - ADV_SCAN_IND (0x02)" in bt_logs.device_adv_type


def test_ble_undirected_non_connectable_adv_T3247(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_non_connectable_adv_T3247_{int(time.time())}.log",
    ) as bt_logs:
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131)

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
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
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        assert (
            "Non connectable undirected - ADV_NONCONN_IND (0x03)"
            in bt_logs.device_adv_type
        )


def test_ble_connect_T3275(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    wifi_dut.interfaces.wifi.ble_start_advertising()

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
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

    ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)

    time.sleep(5)

    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)


def test_ble_advertisement_repeat_T3292(wifi_dut, ble_client):
    bt_dut_address = None
    for count in range(0, 15):
        if count == 0:
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        wifi_dut.interfaces.wifi.ble_start_advertising()

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        if count == 0:
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None
        else:
            ble_client.interfaces.bluetooth.start_scanning()

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

        wifi_dut.interfaces.wifi.ble_stop_advertising()
        wifi_dut.interfaces.wifi.bt_deinit()
        time.sleep(2)


def test_ble_advertisement_setname_T3293(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    wifi_dut.interfaces.wifi.ble_start_advertising(
        ble_advertising_data="ble_1234567890"
    )
    # wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
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
    wifi_dut.interfaces.wifi.ble_stop_advertising()


# Notes by Rama :
# From the online documentation https://docs.silabs.com/rs9116-wiseconnect/2.4/wifibt-wc-sapi-reference/bt-ble#rsi-bt-set-local-name
# "For BLE alone Opermode : When the name of the local device is set to a value with length more than 16 bytes then error is returned with an error code 0x4E66."
# Hence setting the coex_mode to BLE. However it is still passing. This needs to be verified with firmware team
# If this issue fixed and you start seeing 0x4E66, you should add this error code to WlanError class to be able to catch the exception correctly
@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": 0, "coex_mode": RS9116CoexMode.BLE},
)
def test_ble_local_name_17bytes_neg_testcase60(wifi_dut):
    # with pytest.raises(WlanError) as exc_info:
    wifi_dut.interfaces.wifi.bt_set_local_name("A2345678901234567")  # 17 Bytes
    wifi_dut.interfaces.wifi.bt_set_local_name(
        "A2345678901234567A2345678901234567"
    )  # 17x2 Bytes
    wifi_dut.interfaces.wifi.bt_set_local_name(
        "A2345678901234567A2345678901234567A2345678901234567"
    )  # 17x3 Bytes
    # assert exc_info.value.error_code == 0x4E66, "Observed wrong error code.expected is 0x4E66"


def test_ble_set_localname_testcase61(wifi_dut):
    for count in range(0, 2):
        if count == 0:
            set_local_name = "ABCDE"
        else:
            set_local_name = "BLETEST123"
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        assert set_local_name == status
