import time
import pytest
import re
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.blood_pressure_service import \
    BloodPressureMeasurementCharacteristic, BloodPressureService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    HealthThermometerMeasurementCharacteristic, HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116AsyncEventType


def logger():
    return get_logger(__name__)


class BleDeviceState:
    advertising = 1
    scanning = 2
    initiating = 4
    connected = 8
    standby = 0


""" Author: Achal Raghav / RaviNemali
This test plan aims to verify the BLE_GATT services test cases

Setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

This test case needs a sqa_test_agent_multi_gatt.hex file to be loaded on EFR merged in m34.

"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_fetch_profiles_from_RD1_C19860(firmware_loader, ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start GATT Services in DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE Client address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    assert bt_client_address is not None, "Failed to configure remote device in Advertise Mode"
    logger().info(" ******* Scanning and Connecting to BLE Client ******* ")

    # Start scanning and connect to ble client
    scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    assert bt_client_address in str(scan_results), "Remote Device not listed in Scan Results"
    timeout = 60
    logger().info(f"Initiating the Connection can take up to {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(60)

    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_fetch_a_particular_profiles_from_RD1_C19861(firmware_loader, ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    logger().info(f"bt_server_ip is {bt_dut_address}")
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE CLIENT address ******* ")
    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    logger().info(f"bt_server_ip is {bt_client_address}")
    assert bt_client_address is not None, "Could not get the client address"
    logger().info(" ******* Scanning and Connecting to BLE CLIENT ******* ")

    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Enables the Wi-Fi power save in dut
    timeout = 60
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(30)

    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable BT power save"

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    assert state_int is not None, "BLE Connection failed"
    logger().info(" Connected to the BLE device ")

    # get all profiles
    logger().info(" Fetching all the profiles from RD1")
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids is not None, "Could not fetch the profiles"
    # resolve battery profile
    logger().info(" Resolving Battery profile from RD1")
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_fetch_characteristis_from_RD1_C19863(firmware_loader, ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE CLIENT address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    assert bt_client_address is not None
    logger().info(" ******* Scanning and connecting to BLE CLIENT ******* ")
    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Enables the Wi-Fi power save in dut
    timeout = 60
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")

    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # enable power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
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
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
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
    logger().info("Issued BLE Disconnect....")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_to_read_particular_value_and_get_all_values_of_descriptor_from_RD1_C19866_C19867(firmware_loader,
                                                                                          ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE CLIENT address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    assert bt_client_address is not None
    logger().info(" *******Scanning and connecting to ble client ******* ")
    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(15)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 60
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    logger().info(" Connected to the BLE device ")

    logger().info(" Fetching all the profiles from RD1")
    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address, timeout=20)
    assert BatteryService.UUID in uuids

    logger().info(" Resolving Battery profile from RD1")
    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(BatteryService.UUID, 16))
    logger().info(f"Start handle is {start_handle} and data type is {type(start_handle)}")
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address, char_property=14)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    logger().info(" Issued BLE disconnect.... ")


@pytest.mark.config(
    "wifi_dut", wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.
        ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_validate_add_services_in_server_slave_C19878(ble_dut, ble_client):
    service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
    char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
    char_uid2 = "00002a38-0000-1000-8000-00805f9b34fb"
    char_uid3 = "00002a39-0000-1000-8000-00805f9b34fb"
    # start BLE in DUT
    logger().info(" ******* Start BLE GATT Service ******* ")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "Failed to load bt address..."

    # adding service, attributes, values
    index = 1
    # ble_add_service 6157 -> Heart rate service(0x180D)
    ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)

    # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index,
                                                       value_handler_num=index + 1)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1)

    # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                       value_handler_num=index + 3)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3)

    # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                       value_handler_num=index + 5)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5)
    logger().info("enabled battery service")

    # Advertise data from DUT
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
    assert (found_devices[
                ble_dut.interfaces.bluetooth.ble_address] == ble_dut.interfaces.bluetooth.ble_advertising_data), \
        "failed to find dut in scan list..."

    logger().info("connecting to dut....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    # stability for 60sec and then disconnection
    time.sleep(60)

    logger().info("verifying dut state after the conn......")
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"

    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid1)
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid2)
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid3)
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"

    ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
    # Disconnection
    logger().info("Disconnecting from dut...")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


# witten by Himaja
@pytest.mark.config("wifi_dut", wifi={
    "oper_mode": 0,
    "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    "features": RS9116FeatureBitMap.ULPGPIOHandshake,
    "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
    "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    "bt_features": RS9116BTFeatureBitMap.Default,
    "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
}
                    )
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_link_loss_profiles_from_rd1_c19872_c19874(firmware_loader, ble_dut, ble_client):
    service_uid = "00001803-0000-1000-8000-00805f9b34fb"
    char_uid = "00002a06-0000-1000-8000-00805f9b34fb"

    # BLE DUT initialization
    logger().info(" ******* Start BLE GATT service ******* ")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "Failed to load bt address..."

    # adding services, attributes and values
    ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1803)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A06)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A06)

    ble_dut.interfaces.bluetooth.ble_start_advertising()
    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
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
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    logger().info(" Connected to the BLE device ")

    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)

    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    for i in range(0, 3):
        data = str(i)
        logger().info(f"The data being sent is {data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
        time.sleep(1)
        result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        received = re.search(r"\d+(\.\d+)?", result)
        logger().info(f"The data received is {received.group(0)}")
        assert received.group(0) == data, "Data isn't matching"
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)


@pytest.mark.skip(reason="This testcase is still in development")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
    }
)
def test_ble_multi_connect_disconnect_C19875(ble_dut, ble_client):
    # Start BLE Service
    logger().info(".....Starting BLE Service.....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None, "failed to load bt address"
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

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
        logger().info(f"Connecting & Disconnecting for {i + 1} time")
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
        # since at this point the disconnection is already completed hence start advertising again
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        ble_dut.interfaces.bluetooth.ble_start_advertising()


@pytest.mark.config("wifi_dut", wifi={
    "oper_mode": 0,
    "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    "features": RS9116FeatureBitMap.ULPGPIOHandshake,
    "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
    "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    "bt_features": RS9116BTFeatureBitMap.Default,
    "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
    RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
}
                    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_advertising",
                                         "ble_stop_scan"])
def test_fetch_profiles_from_rd1_c19862(firmware_loader, ble_dut, ble_client):
    logger().info(" ******* Start BLE GATT Service ******* ")
    # Start GATT Services in DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address is not None, "failed to load bt address"
    logger().info(" ******* Fetching BLE Client address ******* ")

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "Failed to configure remote device in Advertise Mode"
    logger().info(" ******* Scanning and Connecting to BLE Client ******* ")

    # Start scanning and connect to ble client
    scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                                   timeout=60)
    time.sleep(15)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    assert bt_client_address in str(scan_results), "Remote Device not listed in Scan Results"
    timeout = 60
    logger().info(f"Initiating the Connection can take up to {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(60)

    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable BT power save"

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"

    logger().info("Connected to the BLE device ")
    logger().info("Fetching all the profiles from RD1")
    # get all profiles

    ble_dut.interfaces.bluetooth.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                       uuid=int(HeartRateService.UUID, 16),
                                                       expected="RSI_BLE_GATT_ERROR - total_remote_profiles 0")
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_battery_service_connection_stability_in_client_role_c19882(firmware_loader, ble_dut, ble_client):
    bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None, "unable to start BLE GATT on DUT"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    assert bt_client_address is not None, "Failed to start RD advertising"

    # Start scanning and connect to ble client
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                        expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT and RD are not connected"

    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids, "Failed to get RD profiles"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                             uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))

    logger().info(f"uuids, write_handles, char_properties: {uuids, write_handles, char_properties}")
    assert BatteryLevelCharacteristic.BLEVEL_UUID in uuids, "Unable to find BatteryLevelCharacteristic UUID"
    index = uuids.index(BatteryLevelCharacteristic.BLEVEL_UUID)

    assert char_properties[index].isdigit()
    assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    # read value
    val = ble_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                          char_property=write_handle)
    assert int(val) > 0

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.wifi.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                    char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.wifi.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data  # capturing the last value notified by Gatt server
    assert int(latest_val) < int(val)

    # read value
    val = ble_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                          char_property=write_handle)
    assert int(val) <= int(latest_val)
    # Disconnect
    ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


def gatt_conn_stability(service_uuid, char_uuid, data, service, characteristic, ble_dut, ble_client, rs_helper_ble):
    gatt_obj = rs_helper_ble.ble_gatt(ble_dut=ble_dut, ble_remote=ble_client)

    try:
        # Configuring BLE Server on DUT
        # ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address is not None, "failed to load bt address"
        gatt_obj.add_service(service_uuid=service)  # adding heartrate Service
        gatt_obj.add_characteristic(characteristic_uuid=characteristic)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=characteristic, data=data)

        # Establishing BLE connection with DUT as slave
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.enable_power_save(ble_dut=ble_dut)
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                               smp_flag=True)

        # resolving charecteristic
        char_path = gatt_obj.service_discovery_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)

        # # reading value on characterisics from remote (GATT_client)
        # gatt_obj.gatt_read(char_path=char_path, data=data)

        # subscribe to notifications
        gatt_obj.gatt_notify_tx(char_path=char_path, char_uuid=char_uuid, notify_time=60, data=data)

        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client,
                                                 ble_dut_address=ble_dut_address, start_adv=False)
    except Exception as e:
        assert False, "Test case failed with exception: {}".format(str(e))
    else:
        logger().info("\n\n\n *** Test case is passed successfully..! ***")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address,
                                  ble_remotes={ble_client: BleDeviceState.standby})


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,  # | RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.
            DHCPv4Client,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
            ConfigFeatureBitmapValid,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
            RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        },
    ),
]


def test_gatt_server_conn_stability_HeartRateService_C19879(ble_dut, ble_client, rs_helper_ble):
    # test case to verify GATT connection stability in server role with HeartRateService
    service_uuid = "0000180d-0000-1000-8000-00805f9b34fb"  # HeartRateService
    char_uuid = "00002a37-0000-1000-8000-00805f9b34fb"  # HeartRateMeasurementCharacteristic
    data = "HeartRateMeasurement:74bpm"

    gatt_conn_stability(service_uuid=service_uuid, char_uuid=char_uuid, data=data, service=0x180d,
                        characteristic=0x2A37, ble_dut=ble_dut, ble_client=ble_client,
                        rs_helper_ble=rs_helper_ble)


# Not working
def test_gatt_server_conn_stability_BatteryService_C19881(ble_dut, ble_client, rs_helper_ble):
    # test case to verify GATT connection stability in server role with BatteryService
    service_uuid = "0000180f-0000-1000-8000-00805f9b34fb"  # BatteryService
    char_uuid = "00002a19-0000-1000-8000-00805f9b34fb"  # BatteryLevelCharacteristic
    data = "BatteryLevel:20%"

    gatt_conn_stability(service_uuid=service_uuid, char_uuid=char_uuid, data=data, service=0x180f,
                        characteristic=0x2A19, ble_dut=ble_dut, ble_client=ble_client,
                        rs_helper_ble=rs_helper_ble)


def test_gatt_server_conn_stability_BloodPressureService_C19883(ble_dut, ble_client, rs_helper_ble):
    # test case to verify GATT connection stability in server role with BloodPressureService
    service_uuid = "00001810-0000-1000-8000-00805f9b34fb"  # BloodPressureService
    char_uuid = "00002a35-0000-1000-8000-00805f9b34fb"  # BloodPressureMeasurementCharacteristic
    data = "Systolic:83.0mmHg,Diastolic:50.0mmHg,MeanAP:61.0mmHg"

    gatt_conn_stability(service_uuid=service_uuid, char_uuid=char_uuid, data=data, service=0x1810,
                        characteristic=0x2A35, ble_dut=ble_dut, ble_client=ble_client,
                        rs_helper_ble=rs_helper_ble)


def test_gatt_server_conn_stability_health_thermometer_service_C19885(ble_dut, ble_client, rs_helper_ble):
    # test case to verify GATT connection stability in server role with health_thermometer_service
    service_uuid = "00001809-0000-1000-8000-00805f9b34fb"  # health_thermometer_service
    char_uuid = "00002a1c-0000-1000-8000-00805f9b34fb"  # HealthThermometerMeasurementCharacteristic
    data = "38.010002'C,38.320004'C,38.630005'C,38.940006'C"

    gatt_conn_stability(service_uuid=service_uuid, char_uuid=char_uuid, data=data, service=0x1809,
                        characteristic=0x2A1C, ble_dut=ble_dut, ble_client=ble_client,
                        rs_helper_ble=rs_helper_ble)


def test_gatt_server_conn_stability_glucose_service_C19887(ble_dut, ble_client, rs_helper_ble):
    # test case to verify GATT connection stability in server role with glucose service
    service_uuid = "00001808-0000-1000-8000-00805f9b34fb"  # glucose_service
    char_uuid = "00002a18-0000-1000-8000-00805f9b34fb"  # GlucoseMeasurementCharacteristic
    data = "Sequence_Number:1,Base_Time:28_Sep_2017,02:15:00,Glucose_Concentration:0.00549mol/l,"\
           "Sample_Type:Capillary_Whole_blood,Sample_Location:Finger,Context_information_follows:false"

    gatt_conn_stability(service_uuid=service_uuid, char_uuid=char_uuid, data=data, service=0x1808,
                        characteristic=0x2A18, ble_dut=ble_dut, ble_client=ble_client,
                        rs_helper_ble=rs_helper_ble)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_blood_pressure_connection_stability_in_client_role_c19884(firmware_loader, ble_dut, ble_client):
    bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None, "unable to start BLE GATT on DUT"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BloodPressureService"])
    assert bt_client_address is not None, "Failed to start RD advertising"

    # Start scanning and connect to ble client
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.wifi.ble_stop_scanning()

    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable BT power save"

    timeout = 120
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                        expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT and RD are not connected"

    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BloodPressureService.UUID in uuids, "Failed to get RD profiles"

    # resolve BloodPressureService profile
    start_handle, end_handle = ble_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                             uuid=int(BloodPressureService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # resolve characteristics of BloodPressureService profile
    uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))

    assert BloodPressureMeasurementCharacteristic.BP_Measure_UUID.lower() in uuids, "Unable to find BloodPressure " \
                                                                                    "Measurement Characteristic UUID"
    index = uuids.index(BloodPressureMeasurementCharacteristic.BP_Measure_UUID.lower())

    logger().info(f"uuids, write_handles, char_properties: {uuids, write_handles, char_properties}")

    assert char_properties[index].isdigit()
    logger().info(f"BloodPressureMeasurementCharacteristic.BP_Measure_UUID:"
                  f"{BloodPressureMeasurementCharacteristic.BP_Measure_UUID}")
    logger().info(f"int(char_properties[index]):{int(char_properties[index])}")
    assert BloodPressureMeasurementCharacteristic.prop_int == int(char_properties[index])
    logger().info(f"write_handle:{write_handles}")
    logger().info(f"index:{index}")
    logger().info(f"start_handle:{int(start_handle, 16)}")
    logger().info(f"end_handle:{int(end_handle, 16)}")

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    logger().info(f"write_handles[index]:{write_handles[index]}")
    logger().info(f"write_handle:{write_handle}")

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.wifi.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                    char_property=21, value=1)
    time.sleep(6)
    events = ble_dut.interfaces.wifi.get_async_events(since_time=since_time)
    assert len(events) > 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.GATT_WRITE_EVENT:
            logger().info(f"Received GATT_WRITE_EVENT")
        else:
            assert False, "Did not receive GATT_WRITE_EVENT"

    # Disconnect
    ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_health_thermometer_service_stability_in_client_role_c19886(firmware_loader, ble_dut, ble_client):
    bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None, "unable to start BLE GATT on DUT"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HealthThermometerService"])
    assert bt_client_address is not None, "Failed to start RD advertising"

    # Start scanning and connect to ble client
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.wifi.ble_stop_scanning()

    # Enables the Wi-Fi power save in dut
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable WiFi power save"
    # Enables the bt power save in dut
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable BT power save"

    timeout = 120
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                        expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT and RD are not connected"

    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HealthThermometerService.UUID in uuids, "Failed to get RD profiles"

    # resolve Health thermometer profile
    start_handle, end_handle = ble_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                             uuid=int(HealthThermometerService.UUID, 16)
                                                                             )
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    # resolve characteristics of Health thermometer profile
    uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))

    logger().info(f"uuids, write_handles, char_properties: {uuids, write_handles, char_properties}")
    assert HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID in uuids, \
        "Unable to find HealthThermometerMeasurementCharacteristic UUID"
    index = uuids.index(HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID)

    logger().info(f"write_handle:{write_handles}")
    logger().info(f"index:{index}")
    logger().info(f"start_handle:{int(start_handle, 16)}")
    logger().info(f"end_handle:{int(end_handle, 16)}")

    assert char_properties[index].isdigit()
    assert HealthThermometerMeasurementCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    logger().info(f"write_handles[index]:{write_handles[index]}")
    logger().info(f"write_handle:{write_handle}")

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.wifi.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                    char_property=(write_handle + 1), value=1)
    # read value
    ble_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                    char_property=write_handle)
    time.sleep(6)
    events = ble_dut.interfaces.wifi.get_async_events(since_time=since_time)
    assert len(events) > 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.GATT_WRITE_EVENT:
            logger().info(f"Received GATT_WRITE_EVENT")
        else:
            assert False, "Did not receive GATT_WRITE_EVENT"

    # Disconnect
    ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_to_fetch_descriptors_from_rd1_c19865(firmware_loader, ble_dut, ble_client):
    bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None, "unable to start BLE GATT on DUT"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address is not None, "Failed to start RD advertising"

    # Start scanning and connect to ble client
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    time.sleep(2)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                        expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT and RD are not connected"

    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                             uuid=int(HeartRateService.UUID, 16))
    assert start_handle is not None, "failed to fetch the RD1 address.."
    assert end_handle is not None, "failed to fetch the UUID.."

    ble_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=bt_client_address, start_handle=0x1,
                                                   end_handle=0xffff)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_to_fetch_descriptors_from_rd1_c19864(firmware_loader, ble_dut, ble_client):
    bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None, "unable to start BLE GATT on DUT"

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "Failed to start RD advertising"

    # Start scanning and connect to ble client
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.wifi.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take up to {timeout} seconds....")
    ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                        expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT and RD are not connected"

    time.sleep(2)
    ble_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=bt_client_address, start_handle=0x1,
                                                   end_handle=0xffff)
