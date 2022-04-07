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
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)


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


@pytest.mark.config(
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



def test_ble_undirected_connectable_adv_T3244(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_connectable_adv_T3244_{int(time.time())}.log",
    ) as bt_logs:
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)

        logger().info("Enabling power save ")
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
        logger().info("Initiating stop scanning from remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Dut not found in scan results"
        logger().info("Initiating stop advertising from DUT")
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(bt_logs)

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type

        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")


@pytest.mark.config(
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
def test_ble_undirected_scannable_adv_T3246(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_scannable_adv_T3246_{int(time.time())}.log",
    ) as bt_logs:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_scannable ADV mode")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=130)

        logger().info("Initiating power save")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating BLE scanning from remote device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"BLE Scan results : {found_devices}")
            if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break
        logger().info("Initiating stop scanning from remote Raspberry PI")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found,"Dut not found in scan results"
        logger().info("Initiating stop advertising from DUT")
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
        logger().info(bt_logs)

        assert "Scannable undirected - ADV_SCAN_IND (0x02)" in bt_logs.device_adv_type
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")

@pytest.mark.config(
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
def test_ble_undirected_non_connectable_adv_T3247(wifi_dut, ble_client):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_undirected_non_connectable_adv_T3247_{int(time.time())}.log",
    ) as bt_logs:
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_non_connectable_adv mode")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131)

        logger().info("Initiating power save")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating scanning from Remote remote device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"BLE Scan results : {found_devices}")
            if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break
        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "dut not found in scan results"

        logger().info("initiating stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
        logger().info(bt_logs)

        assert (
            "Non connectable undirected - ADV_NONCONN_IND (0x03)"
            in bt_logs.device_adv_type
        )
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")

@pytest.mark.config(
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
def test_ble_connect_T3275(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT ")

    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()

        logger().info(f"BLE scan results :{found_devices}")
        if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
        ):
            device_found = True
            break

    logger().info("Initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found,"DUT not found in scan results"

    logger().info("Initiating connection from remote device")

    ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)

    time.sleep(60)

    logger().info("Initiating disconnection from remote device")

    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)

@pytest.mark.config(
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
def test_ble_advertisement_repeat_T3292(wifi_dut, ble_client):
    bt_dut_address = None
    for count in range(0, 15):
        if count == 0:
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")
        wifi_dut.interfaces.wifi.ble_start_advertising()

        logger().info("Initiating power save")

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

            logger().info(f"BLE scan results :{found_devices}")

            if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break

        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "dut not found in scan results"

        logger().info("initiating stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("De initialising BT")
        wifi_dut.interfaces.wifi.bt_deinit()
        time.sleep(2)

@pytest.mark.config(
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
def test_ble_advertisement_setname_T3293(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT with the name ble_1234567890 ")
    wifi_dut.interfaces.wifi.ble_start_advertising(
        ble_advertising_data="ble_1234567890"
    )
    # wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)

    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")
    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()

        logger().info(f"Scan results : {found_devices}")
        if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
        ):
            device_found = True
            break
    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found,"dut not found in scan results"

    logger().info("initiating stop advertising")
    wifi_dut.interfaces.wifi.ble_stop_advertising()


@pytest.mark.config(
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
def test_ble_set_localname_testcase61(wifi_dut):

    for count in range(0, 2):
        if count == 0:
            set_local_name = "ABCDE"
        else:
            set_local_name = "BLETEST123"
        logger().info(f"Setting BLE local name {set_local_name}")
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"getting the local name : {status}")
        assert set_local_name == status,"Set local name and get local name not matched "


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": 0, "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE},
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_local_name_17bytes_neg_testcase60(wifi_dut):

    with pytest.raises(WlanError) as exc_info:

        logger().info("Setting BLE local name A2345678901234567 of 17 bytes")
        wifi_dut.interfaces.wifi.bt_set_local_name("A2345678901234567")  # 17 Bytes
    assert exc_info.value.error_code == 0x4E66, "Observed wrong error code.expected is 0x4E66"