import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Jyothi Nagireddy
"""


class BleFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_clients=None, bt_dut_address=None, ble_adv=None, ble_adv_connection=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.bt_dut_address = bt_dut_address
        self.ble_adv = ble_adv
        self.ble_adv_connection = ble_adv_connection

    def run(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        logger().info("initiating scan in rd_1")
        bt_client_address_1 = self.ble_clients.interfaces.bluetooth.start_smp_scan(self.bt_dut_address)
        assert bt_client_address_1, "failed to initiate ble in remote device"
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = self.ble_clients.interfaces.bluetooth.get_devices()
            if self.bt_dut_address in found_devices and \
                    found_devices[self.bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                device_found = True
                break

        self.ble_clients.interfaces.bluetooth.stop_scanning()
        assert device_found
        if self.ble_adv_connection:
            self.ble_clients.interfaces.bluetooth.connect(dev_addr=self.bt_dut_address)
    def check_device_state_on_dut(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def check_device_state_on_rasp(self):
        status = self.ble_clients.interfaces.bluetooth.get_connection_status(self.bt_dut_address)
        logger().info(f"Connection status in remote device '{self.ble_clients.name}' is:{status}")
        assert status, f"Remote device '{self.ble_clients.name}' is not connected to DUT"




pytestmark = [
  pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0  | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    },
)
  ]


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_1slave_1master_conn_disconn_reconn_C19917(wifi_dut, ble_clients, utf_constants, sl_collections):
    """verify slave connection and master connection from dut"""
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        iter_count = utf_constants.get('iter_count')
        logger().info("initiating ble in dut")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        for i in range(0, iter_count):
            ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, bt_dut_address=bt_dut_address,
                                       ble_adv_connection=True)
            ble_obj.start()
            ble_obj.wait_for_exit()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            ble_client_address = sl_collections.ble_connection(wifi_dut=wifi_dut, ble_client=ble_client2,
                                                               ble_dut_address=ble_obj.bt_dut_address,
                                                               mode="master")
            time.sleep(60)
            ble_obj.check_device_state_on_dut()
            ble_client1.interfaces.bluetooth.disconnect(ble_obj.bt_dut_address)
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            ble_client1.interfaces.bluetooth.close()
            ble_client2.interfaces.bluetooth.close()
            logger().info(f"iteration completed: {i+1}")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_1slave_conn_with_15ms_1master_conn_with_200ms_c19918(wifi_dut, ble_clients, bt_logs, sl_collections, utf_constants):
    """verify dual role connection from dut with 15ms minimum and maximum interval"""
    try:
        test_run_time = utf_constants.get('time_duration')
        assert len(ble_clients) >= 2
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1,  bt_dut_address=bt_dut_address, ble_adv="ble_adv_powersave",
                                   ble_adv_connection=False)
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client1.interfaces.bluetooth.connect(dev_addr=ble_obj.bt_dut_address, min_conn_interval=15,
                                                 max_conn_interval=15,
                                                 conn_latency=0, supervision_timeout=4000)
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        logger().info(f"change in function for ble role")
        ble_client_address = sl_collections.ble_connection(wifi_dut=wifi_dut, ble_client=ble_client2,
                                                           ble_dut_address=ble_obj.bt_dut_address, mode="master")
        time.sleep(5)
        sw = Stopwatch()
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            time.sleep(120)
        ble_obj.check_device_state_on_dut()
        ble_client1.interfaces.bluetooth.disconnect(ble_obj.bt_dut_address)
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_1slave_conn_with_20ms_1master_conn_with_200ms_c19919(wifi_dut, ble_clients, bt_logs, sl_collections, utf_constants):
    """verify dual role connection from dut with 200ms minimum and maximum interval"""
    try:
        test_run_time = utf_constants.get('time_duration')
        assert len(ble_clients) >= 2
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, bt_dut_address=bt_dut_address, ble_adv="ble_adv_powersave",
                                   ble_adv_connection=False)
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client1.interfaces.bluetooth.connect(dev_addr=ble_obj.bt_dut_address, min_conn_interval=20,
                                                 max_conn_interval=20,
                                                 conn_latency=0, supervision_timeout=4000)
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        logger().info(f"change in function for ble role")
        ble_client_address = sl_collections.ble_connection(wifi_dut=wifi_dut, ble_client=ble_client2, ble_dut_address=ble_obj.bt_dut_address, mode="master")
        time.sleep(5)
        sw = Stopwatch()
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            time.sleep(120)
        ble_obj.check_device_state_on_dut()
        ble_client1.interfaces.bluetooth.disconnect(ble_obj.bt_dut_address)
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_in_busy_environment_C19827_c19828(ble_dut, ble_clients, sl_collections):
    """Verify ble scan functionality with maximum number of ble clients"""
    try:
        remote_le_devices = 4
        assert len(ble_clients) >= remote_le_devices
        ble_advertisers = []
        for item in range(0, remote_le_devices):
            ble_advertisers.append(ble_clients[item])
        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        count = 0
        for ble_client in ble_advertisers:
            count = count + 1
            logger().info(f"**********{ble_client}*************")
            logger().info(f" ======= initialize ble adv in remote device {count}")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address, f"ble initialization failed in remote device{count}"

            logger().info(f"ble client address of remote device {count} is {bt_client_address}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)
        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)
