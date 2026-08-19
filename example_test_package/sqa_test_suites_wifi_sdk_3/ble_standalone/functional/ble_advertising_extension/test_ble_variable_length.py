import time
import pytest
import re
import string
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
import random
from utf.interfaces.wifi import WlanError
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)
from utf.interfaces.bluetooth.bluez.gatt_application.glucose_service import (
    GlucoseService,
    GlucoseMeasurementCharacteristic,
)
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import (
    BatteryService,
)
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import (
    BatteryLevelCharacteristic,
)
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import (
    BatteryService,
)
from utf.interfaces.bluetooth.bluez.gatt_application.link_loss_service import (
    LinkLossService,
    LinkLossAlertLevelCharacteristic,
)
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (
    HeartRateService,
    HeartRateMeasurementCharacterstic,
    HeartRateControlPointCharacteristic,
)

from utf.interfaces.bluetooth.bluez.gatt_application.blood_pressure_service import (
    BloodPressureMeasurementCharacteristic,
    BloodPressureService,
)
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import (
    HealthThermometerMeasurementCharacteristic,
    HealthThermometerService,
)
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
import os
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
    BLEPermissions,
)

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Bhuvaneswari
"""


def logger():
    return get_logger(__name__)


pytestmark = [pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
        | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    }
)
]
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_slave_C777721(ble_dut, ble_client, sl_collections):
    """Verify BLE GATT write and read Operations with less than 20-Byte Variable Length in Slave Role."""
    # try:
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C19876.log_{int(time.time())}",
    ):
       
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
            write_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=18)
        )
        logger().info(" ******* Start BLE  Service ******* ")       
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."

        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning for ble client.. ")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        logger().info(f"ble_client address {bt_client_address}")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        logger().info("verifying device in scan list...")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."

        logger().info("connecting to dut....")
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(5)
        status = ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(f"Connection status in remote device '{ble_client}' is:{status}")
        assert status, f"Remote device '{ble_client.name}' is not connected to DUT"
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert (
            write_data != initial_data
        ), "peer must write a value different from the configured one"
        logger().info(
            f"writing 18 bytes from peer: {write_data} (configured value: {initial_data})"
        )
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )
        time.sleep(5)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1
        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)
        logger().info(
            f"Written value: {write_data} ({len(write_data)} bytes), "
            f"Read value: {result} ({wire_len} bytes on the wire)"
        )
        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes for an {len(write_data)}-byte write; "
                "the attribute is declared at the full 240-byte buffer and the value is zero-padded"
            )
        assert (
            result != initial_data
        ), "DUT returned the configured value; the peer write was not applied"
        assert result == write_data, "failed to read value"


@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_slave_C777722(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read Operations with 20-Byte
    Variable Length in Slave Role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777722.log_{int(time.time())}",
    ):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
        write_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=20)
        )
        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning for ble client.. ")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        logger().info(f"ble_client address {bt_client_address}")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        logger().info("verifying device in scan list...")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."

        logger().info("connecting to dut....")
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(5)
        status = ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(
            f"Connection status in remote device " f"'{ble_client}' is:{status}"
        )
        assert status, f"Remote device '{ble_client.name}' " f"is not connected to DUT"
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )

        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")

        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(
            f"writing 20 bytes from peer: {write_data} "
            f"(configured value: {initial_data})"
        )
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )
        time.sleep(5)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1
        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)

        logger().info(
            f"Written value: {write_data} "
            f"({len(write_data)} bytes), "
            f"Read value: {result} "
            f"({wire_len} bytes on the wire)"
        )
        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes for an "
                f"{len(write_data)}-byte write; "
                "the attribute is declared at the full "
                "240-byte buffer and the value is "
                "zero-padded"
            )
        assert len(write_data) == 20, "Test requires exactly 20 bytes"
        assert result != initial_data, ( "DUT returned the configured value; " "the peer write was not applied" )
        assert result == write_data, "failed to read value"


@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_slave_C777723(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read Operations with
    230-Byte Variable Length in Slave Role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777723.log_{int(time.time())}",
    ):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
        #
        # C777723 requires a 230-byte payload.
        #
        write_data = "".join(
            random.choices(
                string.ascii_uppercase + string.ascii_lowercase + string.digits, k=230
            )
        )
        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning for ble client.. ")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(5)
        status = ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)
        assert status, f"Remote device '{ble_client.name}' is not connected to DUT"
        time.sleep(3)
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(f"Initial value: {initial_data}")
        logger().info(f"Writing 230 bytes from peer: {write_data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )

        time.sleep(8)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1
        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)

        logger().info(f"Written value: {write_data} " f"({len(write_data)} bytes)")

        logger().info(f"Read value: {result} " f"({wire_len} bytes on the wire)")

        logger().info(
            f"Written length={len(write_data)}, "
            f"Read length={len(result)}, "
            f"Wire length={wire_len}"
        )
        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes "
                f"for a {len(write_data)}-byte write; "
                "the attribute buffer may be padded to "
                "the full 240-byte characteristic size."
            )
        assert len(write_data) == 230, "Test requires exactly 230 bytes"
        assert result != initial_data, (
            "DUT returned the configured value; " "the peer write was not applied"
        )
        assert result == write_data, "failed to read back the same 230-byte value"


@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_slave_C777724(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read Operations with
    240-Byte Variable Length in Slave Role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777724.log_{int(time.time())}",
    ):

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"

        #
        # C777724 requires a 240-byte payload.
        #
        write_data = "".join(
            random.choices(
                string.ascii_uppercase + string.ascii_lowercase + string.digits, k=240
            )
        )

        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning for ble client.. ")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(5)
        status = ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)
        assert status, f"Remote device '{ble_client.name}' is not connected to DUT"
        time.sleep(3)
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(f"Initial value: {initial_data}")
        logger().info(f"Writing 240 bytes from peer: {write_data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )
        time.sleep(8)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1
        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)
        logger().info(f"Written value: {write_data} " f"({len(write_data)} bytes)")
        logger().info(f"Read value: {result} " f"({wire_len} bytes on the wire)")
        logger().info(
            f"Written length={len(write_data)}, "
            f"Read length={len(result)}, "
            f"Wire length={wire_len}"
        )
        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes "
                f"for a {len(write_data)}-byte write; "
                "the attribute buffer may be padded."
            )
        assert len(write_data) == 240, "Test requires exactly 240 bytes"
        assert result != initial_data, (
            "DUT returned the configured value; " "the peer write was not applied"
        )
        assert result == write_data, "failed to read back same 240-byte value"



@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_master_C777725(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read operation with 20 bytes
    variable length in master role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777725.log_{int(time.time())}",
    ):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
        write_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=20)
        )

        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        logger().info("scanning from remote to verify DUT advertisements")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."
        logger().info("Remote advertises; DUT scans and connects as master")
        sl_collections.ble_connection(
            wifi_dut=ble_dut,
            ble_client=ble_client,
            ble_dut_address=bt_dut_address,
            timeout=20,
            mode="master",
            services=["HeartRateService"],
            # Connected (8) + still advertising (1) after dual-role connect
            dev_state=9,
        )
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(
            f"writing 20 bytes from peer: {write_data} "
            f"(configured value: {initial_data})"
        )
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )
        time.sleep(5)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1
        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)
        logger().info(
            f"Written value: {write_data} "
            f"({len(write_data)} bytes), "
            f"Read value: {result} "
            f"({wire_len} bytes on the wire)"
        )
        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes for an "
                f"{len(write_data)}-byte write; "
                "the attribute is declared at the full "
                "240-byte buffer and the value is "
                "zero-padded"
            )
        assert len(write_data) == 20, "Test requires exactly 20 bytes"
        assert result != initial_data, (
            "DUT returned the configured value; " "the peer write was not applied"
        )
        assert result == write_data, "failed to read value"


@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_master_C777726(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read operation with
    230 bytes variable length in master role.
    """
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777726.log_{int(time.time())}",
    ):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
        write_data = "".join(
            random.choices(string.ascii_letters + string.digits, k=230)
        )
        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning from remote to verify DUT advertisements")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."
        ble_client.interfaces.bluetooth.close()
        logger().info("Remote advertises; DUT scans and connects as master")
        sl_collections.ble_connection(
            wifi_dut=ble_dut,
            ble_client=ble_client,
            ble_dut_address=bt_dut_address,
            timeout=20,
            mode="master",
            services=["HeartRateService"],
            dev_state=9,
        )
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(f"Initial value: {initial_data}")
        logger().info(f"Writing 230 bytes from peer: {write_data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )
        time.sleep(8)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)

        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1

        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)

        logger().info(f"Written value: {write_data} " f"({len(write_data)} bytes)")
        logger().info(f"Read value: {result} " f"({wire_len} bytes on the wire)")
        logger().info(
            f"Written length={len(write_data)}, "
            f"Read length={len(result)}, "
            f"Wire length={wire_len}"
        )

        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes for a "
                f"{len(write_data)}-byte write; "
                "the attribute buffer may be padded "
                "to the full 240-byte characteristic size."
            )

        assert len(write_data) == 230, "Test requires exactly 230 bytes"
        assert result != initial_data, (
            "DUT returned the configured value; " "the peer write was not applied"
        )
        assert result == write_data, "failed to read value"



@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_master_C777727(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read operations with
    240 bytes variable length in master role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777727.log_{int(time.time())}",
    ):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        initial_data = "A0bC1dE2fG3hI4jK5l"
        write_data = "".join(
            random.choices(string.ascii_letters + string.digits, k=240)
        )

        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )

        logger().info("start ble advertising....")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )
        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning from remote to verify DUT advertisements")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."
        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."

        ble_client.interfaces.bluetooth.close()
        logger().info("Remote advertises; DUT scans and connects as master")
        sl_collections.ble_connection(
            wifi_dut=ble_dut,
            ble_client=ble_client,
            ble_dut_address=bt_dut_address,
            timeout=20,
            mode="master",
            services=["HeartRateService"],
            dev_state=9,
        )
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )

        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different from " "the configured one"
        )
        logger().info(f"Initial value: {initial_data}")
        logger().info(f"Writing 240 bytes from peer: {write_data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
            char_path=char_path, data=write_data, retries=3
        )

        time.sleep(8)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)
        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1

        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)
        logger().info(f"Written value: {write_data} " f"({len(write_data)} bytes)")
        logger().info(f"Read value: {result} " f"({wire_len} bytes on the wire)")
        logger().info(
            f"Written length={len(write_data)}, "
            f"Read length={len(result)}, "
            f"Wire length={wire_len}"
        )

        if wire_len != len(write_data):
            logger().warning(
                f"DUT returned {wire_len} bytes for a "
                f"{len(write_data)}-byte write; "
                "the attribute buffer may be padded "
                "to the full 240-byte characteristic size."
            )

        assert len(write_data) == 240, "Test requires exactly 240 bytes"
        assert result != initial_data, (
            "DUT returned the configured value; " "the peer write was not applied"
        )
        assert result == write_data, "failed to read value"



@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "ble_stop_scan",
        "ble_disconnect",
    ],
)
def test_ble_gatt_read_write_in_slave_C777844(ble_dut, ble_client, sl_collections):
    """
    Verify BLE GATT write and read operations with
    more than 240 bytes variable length in slave role.
    """

    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_C777844.log_{int(time.time())}",
    ):

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"

        initial_data = "A0bC1dE2fG3hI4jK5l"

        write_data = "".join(
            random.choices(string.ascii_letters + string.digits, k=241)
        )

        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        logger().info("adding custom_service to DUT")

        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, permissions=BLEPermissions.READ | BLEPermissions.WRITE
        )
        ble_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            data=initial_data,
            permissions=BLEPermissions.READ | BLEPermissions.WRITE,
            auth_read=0,
        )
        logger().info("start ble advertising....")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(
            mode="power_save_low_latency"
        )

        assert enable_wifi_ps == 0, "failed to enable wlan power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            Si91xPowerSaveModes.PowerSaveMode2,
            Si91xPowerSaveProcedureTypes.FastPowerSave,
        )

        assert enable_bt_ps == 0, "failed to enable bt power save"
        ble_client.interfaces.bluetooth.close()
        logger().info("scanning for ble client.. ")

        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        logger().info(f"ble_client address {bt_client_address}")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_dut.interfaces.bluetooth.ble_scanning = False
        ble_dut.interfaces.bluetooth.ble_advertising = False
        logger().info("verifying device in scan list...")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert (
            ble_dut.interfaces.bluetooth.ble_address in found_devices
        ), "failed to find dut address in scan list..."

        assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ), "failed to find dut in scan list..."

        logger().info("connecting to dut....")
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(5)
        status = ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(
            f"Connection status in remote device " f"'{ble_client}' is:{status}"
        )
        assert status, f"Remote device '{ble_client.name}' is not connected to DUT"
        time.sleep(3)
        logger().info("get all profiles")
        servs, chars = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )

        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid1
            )
        )
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("Running GATT write/read with BT power save still enabled....")
        assert write_data != initial_data, (
            "peer must write a value different " "from the configured one"
        )
        logger().info(f"Initial value: {initial_data}")
        logger().info(f"Writing 241 bytes from peer: {write_data}")
        assert len(write_data) > 240, "Test requires payload larger than 240 bytes"
        from dbus.exceptions import DBusException

        write_error = None
        try:
            ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(
                char_path=char_path, data=write_data, retries=0
            )
        except DBusException as exc:
            write_error = str(exc)
            logger().info(
                f"GATT write of {len(write_data)} bytes rejected: {write_error}"
            )
        assert write_error is not None, "Write larger than 240 bytes must be rejected"
        assert (
            "Invalid Length" in write_error
        ), f"Expected Invalid Length for >240-byte write, got: {write_error}"
        time.sleep(2)
        raw_read = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(
            char_path=char_path, type=bytes, retries=3
        )
        time.sleep(2)
        if isinstance(raw_read, bytes):
            result = raw_read.decode(errors="replace").rstrip("\x00")
            wire_len = len(raw_read)

        elif isinstance(raw_read, int):
            result = chr(raw_read & 0xFF)
            wire_len = 1

        else:
            result = str(raw_read).rstrip("\x00")
            wire_len = len(result)

        truncated = write_data[:240]
        logger().info(
            f"Rejected write length={len(write_data)}, "
            f"Read value: {result} "
            f"({wire_len} bytes on the wire)"
        )
        assert wire_len == 240, (
            f"DUT must cap the stored value at 240 bytes, "
            f"got {wire_len} on the wire"
        )
        assert len(result) == 240, (
            f"Read-back after >240-byte write must be 240 bytes, " f"got {len(result)}"
        )
        assert result == truncated, (
            "DUT must store the first 240 bytes of the "
            "oversized write, not the full 241-byte payload"
        )
        assert result != write_data, "Full 241-byte payload must not be stored"