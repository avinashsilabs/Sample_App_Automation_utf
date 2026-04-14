import time
import pytest
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes
)
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs


def logger():
    return get_logger(__name__)


'''
This script contains tests for Bluetooth Low Energy (BLE) functionality.

 Setup Requirements:
 1. Device Under Test (DUT) - RS9117
 2. Raspberry PI4 - Used as a client for testing

 Test Steps:
 1. Initiate the DUT in Coex i.e. WLAN and BT mode
 2. Initialize the BLE GATT task in DUT
 3. Initiate the client in Raspberry Pi
 4. Make LE connection to remote peer Raspberry Pi
 5. Validate the connection in BLE

 The BleThread class is used to handle BLE operations such as starting advertising, enabling power save mode,
 scanning and connecting.

 The test_ble_validate_ibeacon_adv_data_parameters_c19947 function is a test case to validate iBeacon advertising
 data parameters.

 The test_ble_hogp_smp_slave_mode_c19948 function is a test case to validate the Human Interface Device (HID) over
 GATT Profile (HOGP) in slave mode.
 
 Author: Achal Raghav
 '''


class BleThread(ThreadBase):
    ble_dut_addr = None

    def __init__(self, ble_dut=None, ble_client=None, testcase_id=None, ibeacon_info=0):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.testcase_id = testcase_id
        self.ibeacon_info = ibeacon_info

    def run(self):
        BleThread.ble_dut_addr = self.ble_dut.interfaces.wifi.ble_gatt_start()
        assert self.ble_dut_addr, "FAILED TO LOAD BT ADDRESS..."
        if self.testcase_id == 19948 and self.ble_dut.interfaces.wifi.add_hid_service:
            logger().info("....ADDING HID SERVICE....")
            self.ble_dut.interfaces.wifi.ble_add_hid_service()
        logger().info("..STARTING BLE ADVERTISEMENT..")
        self.ble_dut.interfaces.wifi.ble_start_advertising(ibeacon_info=self.ibeacon_info)
        logger().info("..ENTERING POWER SAVE MODE..")
        self.power_save()
        if self.testcase_id == 19948:
            self.scan_and_connect()

    def scan_and_connect(self):
        self.ble_client.interfaces.bluetooth.close()
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_addr)
        assert ble_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            if (
                    self.ble_dut_addr in found_devices
                    and found_devices[self.ble_dut_addr]
                    == self.ble_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break

        assert device_found, "FAILED TO FIND DUT IN SCAN LIST..."

        self.ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("..CONNECTING TO DEVICE..")
        assert self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_addr)
        time.sleep(2)
        # Get the state of the dut
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

    def power_save(self):
        enable_wifi_ps = self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, '..FAILED TO ENABLE WIFI POWER SAVE..'
        enable_bt_ps = self.ble_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, '..FAILED TO ENABLE BT POWER SAVE..'

    def validate_ibeacon_adv_data(self):
        ble_ibeacon_info = self.ble_client.interfaces.bluetooth.start_ibeacon_scanning(
            bt_dut_address=BleThread.ble_dut_addr
        )

        if ble_ibeacon_info:
            logger().info(f"iBeacon INFO FOUND: {ble_ibeacon_info} ")
            assert ble_ibeacon_info["mac_address"] == BleThread.ble_dut_addr.lower()
            assert ble_ibeacon_info["type"] == "iBeacon"
            assert ble_ibeacon_info["uuid"] == "fb0b57a2-8228-44cd-913a-94a122ba1206"
            assert ble_ibeacon_info["major"] == 4386
            assert ble_ibeacon_info["minor"] == 13124
            assert ble_ibeacon_info["tx_power"] == 51
        self.ble_client.interfaces.bluetooth.stop_ibeacon_scanning()

    def validate_hid_data(self):
        test_data = ["0xb", "0x0", "0x12", "0x0", "0xa", "0x0"]
        test_data_expected_from_raspi = [
            "11,00,00,0b,00,00,00,00,00,00,00,00",
            "11,00,00,00,00,00,00,00,00,00,00,00",
            "11,00,00,12,00,00,00,00,00,00,00,00",
            "11,00,00,00,00,00,00,00,00,00,00,00",
            "11,00,00,0a,00,00,00,00,00,00,00,00",
            "11,00,00,00,00,00,00,00,00,00,00,00",
        ]
        with HidRecorder() as hid_recorder:
            for item in test_data:
                self.ble_dut.interfaces.wifi.ble_hid_send_interrupt(item)
                time.sleep(0.5)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data), "LENGTH OF HID DATA DOESN'T MATCH..."
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data_expected_from_raspi[i], f"HID DATA {hid_logs[i]} DOESN'T MATCH WITH " \
                                                                    f"EXPECTED DATA {test_data_expected_from_raspi[i]}..."


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        },
    )
]


# test_ble_validate_ibeacon_adv_data_parameters_c19947: This test case is designed to validate the iBeacon
# advertising data parameters. The test case initiates the Device Under Test (DUT) in Coex mode (WLAN and BT mode),
# initializes the BLE GATT task in DUT, and starts BLE advertising. It then validates the iBeacon advertising data
# parameters such as mac_address, type, uuid, major, minor, and tx_power.
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19947')
def test_ble_validate_ibeacon_adv_data_parameters_c19947(ble_dut, ble_client, sl_collections):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_validate_ibeacon_adv_data_parameters_c19947.log_{int(time.time())}",
    ) as bt_logs:
        try:
            testcase_id = 19947
            ble_obj = BleThread(ble_dut=ble_dut, ble_client=ble_client, ibeacon_info=1, testcase_id=testcase_id)
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.validate_ibeacon_adv_data()
        except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=ble_dut, exception=Ex)
        finally:
            ble_dut.interfaces.wifi.ble_stop_advertising()


# test_ble_hogp_smp_slave_mode_c19948: This test case is designed to validate the Human Interface Device (HID)
# over GATT Profile (HOGP) in slave mode. The test case initiates the DUT in Coex mode (WLAN and BT mode),
# initializes the BLE GATT task in DUT, and starts BLE advertising. It then scans for the DUT from a client device,
# connects to the DUT, and validates the HID data sent from the DUT.
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19948')
def test_ble_hogp_smp_slave_mode_c19948(ble_dut, ble_client, sl_collections):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_hogp_smp_slave_mode_c19948.log_{int(time.time())}",
    ) as bt_logs:
        try:
            testcase_id = 19948
            ble_obj = BleThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id)
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.validate_hid_data()
            time.sleep(2)
        except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=ble_dut, exception=Ex)
        finally:
            ble_client.interfaces.bluetooth.disconnect(BleThread.ble_dut_addr)
            time.sleep(2)
            ble_client.interfaces.bluetooth.remove_device(BleThread.ble_dut_addr)
