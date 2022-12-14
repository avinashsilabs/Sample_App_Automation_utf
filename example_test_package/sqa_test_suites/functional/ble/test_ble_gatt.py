import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap


def logger():
    return get_logger(__name__)


""" Author: Sirisha Ayyagari/RaviNemali
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_fetch_profiles_from_RD1_C19860(ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start GATT Services in DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE Client address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address, service_classes=[BatteryService])
    assert bt_client_address is not None, "Failed to configure remote device in Advertise Mode"
    logger().info(" ******* Scanning and Connecting to BLE Client ******* ")

    # Start scanning and connect to ble client
    scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    assert bt_client_address in str(scan_results), "Remote Device not listed in Scan Results"
    timeout = 60
    logger().info(f"Initiating the Connection can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout, expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(60)

    # Enables the wifi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps, "Failed to enable BT power save"

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"

    logger().info(" Connected to the BLE device ")
    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids is not None, "Could not fetch the battery profile"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect ")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_fetch_a_particular_profiles_from_RD1_C19861(ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    logger().info(f"bt_server_ip is {bt_dut_address}")
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching ble client address ******* ")
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address, service_classes=[BatteryService])
    logger().info(f"bt_server_ip is {bt_client_address}")
    assert bt_client_address is not None, "Could not get the client address"
    logger().info(" *******Scanning and connecting to ble client ******* ")

    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Enables the wifi power save in dut
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout, expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(30)

    # Enables the wifi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps, "Failed to enable BT power save"

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,  "Device isn't in connected state"
    assert state_int is not None, "BLE Connection failed"
    logger().info(" Connected to the BLE device ")

    # get all profiles
    logger().info(" Fetching all the profiles from RD1")
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids is not None, "Could not fetch the profiles"
    # resolve battery profile
    logger().info(" Resolving Battery profile from RD1")
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                              uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect.... ")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_fetch_characteristis_from_RD1_C19863(ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching ble client address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address, service_classes=[BatteryService])
    assert bt_client_address is not None
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Enables the wifi power save in dut
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")

    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout, expected="RSI_BLE_SECURITY_KEYS_EVENT")

    #enable power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps, "failed to enable wifi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    logger().info(" Connected to the BLE device ")

    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

    logger().info(" Resolving Battery profile from RD1")
    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                              uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert BatteryLevelCharacteristic.BLEVEL_UUID in uuids
    index = uuids.index(BatteryLevelCharacteristic.BLEVEL_UUID)

    assert char_properties[index].isdigit()
    assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info("issued BLE disconnect....")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_to_read_particular_value_and_get_all_values_of_descriptor_from_RD1_C19866_C19867(ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching ble client address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address, service_classes=[BatteryService])
    assert bt_client_address is not None
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout, expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    logger().info(" Connected to the BLE device ")

    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address,timeout=20)
    assert BatteryService.UUID in uuids

    logger().info(" Resolving Battery profile from RD1")
    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                              uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect.... ")


@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": 0,
                        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
                        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
                        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
                        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
                        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
                        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
                    },
                    )
def test_validate_add_services_in_server_slave_C19878(ble_dut, ble_client):
    #start BLE in DUT
    logger().info(" ******* Start BLE GATT Service ******* ")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "Failed to load bt address..."
    ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
    logger().info("enabled battery service")

    #Advertise data from DUT
    logger().info("start ble advertising....")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("scanning for ble client.. ")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "The client address is not found"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("verifying device in scan list...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()

    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "failed to find dut address in scan list..."
    assert (found_devices[ble_dut.interfaces.bluetooth.ble_address] == ble_dut.interfaces.bluetooth.ble_advertising_data), "failed to find dut in scan list..."

    logger().info("connecting to dut....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    #stability for 60sec and then disconnection
    time.sleep(60)

    logger().info("verifying dut state after the conn......")
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,  "Device isn't in connected state"

    #Disconnection
    logger().info("Disconnecting from dut...")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


# witten by Himaja
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_linkloss_profilesfrom_RD1_C19874(ble_dut, ble_client):
    # BLE DUT initialization
    logger().info(" ******* start ble GATT service ******* ")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "Failed to load bt address..."

    ble_dut.interfaces.bluetooth.ble_start_advertising()
    # Enables the wifi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps, "failed to enable wifi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)
    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "failed to start ble client"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
            break
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "device isn't present in scan list..."
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(60)
    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected , "Device isn't in connected state"
    logger().info(" Connected to the BLE device ")

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
def test_ble_multi_connect_disconnect_C19875(ble_dut, ble_client):
    # Start BLE Service
    logger().info(".....Starting BLE Service.....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None, "failed to load bt address"
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    # Begin Scanning for BLE devices through bt client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "failed to load bt client address"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
            break
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found
    for i in range(10):
        logger().info(f"Connecting & Disconnecting for {i+1} time")
        time.sleep(5)
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        # Get the state of the dut
        state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "Device isn't in Connected State"
        assert state_int is not None, "BLE Connection failed"
        logger().info(" Connected to the BLE device ")
        if state_int is not None:
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)
            logger().info(" Disconnected with the BLE device ")
        #since at this point the disconnection is already completed hence start advertising again
        ble_dut.interfaces.bluetooth.ble_start_advertising()