import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth import BLEConnectError


def logger():
    return get_logger(__name__)


""" Author: Sirisha Ayyagari
This test plan aims to verify the BLE_GATT services test cases
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Do Scan the AP
Step3: Connect to the AP
Step4 : Fetch all/particular profiles and characteritics 
This test case needs a sqa_test_agent_multi_gatt.hex file to be loaded on EFR merged in m18.

""" 
 

@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_fetch_profiles_from_RD1_C19860(wifi_dut,  ble_client):
    logger().info(" ******* start ble GATT service ******* ")
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None
     
    logger().info(" ******* Fetching ble client address ******* ")
 
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None
    
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger().info(" Connected to the BLE device ")
    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

  # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect ")



@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_fetch_a_particular_profiles_from_RD1_C19861(wifi_dut, ble_client):
    logger().info(" ******* start ble GATT service ******* ")
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None
     
    logger().info(" ******* Fetching ble client address ******* ")
 
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None
    
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger().info(" Connected to the BLE device ")
    
    # get all profiles
    logger().info(" Fetching all the profiles from RD1")
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

    # resolve battery profile
    logger().info(" Resolving Battery profile from RD1")
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                             uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None
    assert end_handle is not None
  
  # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect.... ")


@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_fetch_characteristis_from_RD1_C19863(wifi_dut, ble_client):

    logger().info(" ******* start ble GATT service ******* ")
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None
     
    logger().info(" ******* Fetching ble client address ******* ")
 
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None
    
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger().info(" Connected to the BLE device ")
    
    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

    logger().info(" Resolving Battery profile from RD1")
    # resolve battery profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                             uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None
    assert end_handle is not None

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(ble_remote_dev_address=bt_client_address,
                    start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert BatteryLevelCharacteristic.UUID in uuids
    index = uuids.index(BatteryLevelCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

      # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
l   logger().info(" Issued BLE disconnect.... ")


@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_to_read_particular_value_and_get_all_values_of_descriptor_from_RD1_C19866_C19867(wifi_dut, ble_client):
    logger().info(" ******* start ble GATT service ******* ")
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None
     
    logger().info(" ******* Fetching ble client address ******* ")
 
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None
    
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger().info(" Connected to the BLE device ")
    
    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

    logger().info(" Resolving Battery profile from RD1")
    # resolve battery profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                             uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None
    assert end_handle is not None
  
  # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect.... ")

