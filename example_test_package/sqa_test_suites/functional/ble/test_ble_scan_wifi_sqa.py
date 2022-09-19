import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf.utils.logger import get_logger

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in Wifi+Bluetooth dual mode
        2. Put RaspberryPi in advertising mode
        3. Put DUT in scan mode
        4. Initiate connection from DUT over BLE
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""

def logger():
    return get_logger(__name__)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
            }
        )
    ]
def test_ble_scan_testcase5(wifi_dut, ble_client):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to load ble in dut"
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"
    logger().info(f"client_address ==== {bt_client_address}")

    # Start scanning and connect to ble client
    scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    assert scan_results,"no devices found"
    logger().info(f"scan results are {scan_results}")
    logger().info(type(bt_client_address))
    assert bt_client_address in str(scan_results),"device not found"
    time.sleep(30)

def test_ble_scan_multiple_times_testcase10(wifi_dut, ble_client):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to load ble in dut"
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"
    logger().info(f"bt_client_address is {bt_client_address}")
    ble_client.interfaces.bluetooth.stop_advertising()

    for count in range(0, 2):
        # Start scanning and connect to ble client
        ble_client.interfaces.bluetooth.start_advertising()
        scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)
        time.sleep(15)
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        assert scan_results, "no devices found"
        logger().info(f"scan results are {scan_results}")
        logger().info(type(bt_client_address))
        assert bt_client_address in str(scan_results), "device not found"
        time.sleep(30)

def test_ble_master_connection_testcase33(wifi_dut, ble_client, logger):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in master mode"

def test_ble_connection_request_testcase35(wifi_dut, ble_client, bt_logs, logger):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in master mode"

def test_ble_master_disconnect_testcase36(wifi_dut, ble_client, logger):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in master mode"
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected, "dut is unable to disconnect in master mode"

'''=================== ble gap power save test cases ==============='''

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_power_save3_when_dut_Advertising(wifi_dut,ble_client,logger):
    # Set up DUT for BLE advertising
    logger.info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger.info("Set DUT in advertise mode")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger.info("Enable wlan power save")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode3)

    logger.info("Enable bt power save")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode3)

    logger.info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in rpi"
    time.sleep(5)
    logger.info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger.info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices

    logger.info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger.info("Disconnecting the bt host....")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
