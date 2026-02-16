import time
import pytest
import os
import re
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
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
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
    def __init__(self, wifi_dut=None, ble_clients=None, ble_sniffer=None, bt_dut_address=None, ble_adv=None, ble_adv_connection=True, min_adv_int=None, max_adv_int=None, min_conn_int=None, max_conn_int=None, scan_type=None, scan_addr_type=None,adv_addr_type=None, own_addr_type=None, layer_name=None, capture_filename=None,stability_check_time=300,
                 iter=1, dual_role_dut_as_slave=False, dual_role_dut_as_master=False, ble_gatt_init=False, random_addr_on_dut=False, ble_client_address=None, ble_conn_interval_min=160, ble_conn_interval_max=160, ble_scan_interval=None, ble_advt=False, ble_scan=False, ble_scan_window=None, adv_and_scan=False, connection_update=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.bt_dut_address = bt_dut_address
        self.ble_adv = ble_adv
        self.ble_adv_connection = ble_adv_connection
        self.min_adv_int = min_adv_int
        self.max_adv_int = max_adv_int
        self.stability_check_time = stability_check_time
        self.min_conn_int = min_conn_int
        self.max_conn_int = max_conn_int
        self.scan_type = scan_type
        self.scan_addr_type = scan_addr_type
        self.adv_addr_type = adv_addr_type
        self.ble_sniffer = ble_sniffer
        self.layer_name = layer_name
        self.capture_filename = capture_filename
        self.own_addr_type = own_addr_type
        self.iter = iter
        self.dual_role_dut_as_slave = dual_role_dut_as_slave
        self.dual_role_dut_as_master = dual_role_dut_as_master
        self.random_addr_on_dut = random_addr_on_dut
        self.ble_client_address = ble_client_address
        self.ble_conn_interval_min = ble_conn_interval_min
        self.ble_conn_interval_max = ble_conn_interval_max
        self.ble_scan_interval=ble_scan_interval
        self.ble_advt = ble_advt
        self.ble_scan = ble_scan
        self.ble_scan_window = ble_scan_window
        self.adv_and_scan = adv_and_scan
        self.connection_update = connection_update


    def run(self):
        if self.adv_and_scan:
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
            assert device_found
            if self.ble_adv_connection:
                self.ble_clients.interfaces.bluetooth.connect(dev_addr=self.bt_dut_address)

        if self.ble_advt:
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
        if self.ble_scan:
            ble_scan_int = int(self.ble_scan_interval / 0.625)
            ble_scan_win = int(self.ble_scan_window / 0.625)
            logger().info(f"**********{self.bt_dut_address}")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_scan_interval=ble_scan_int,ble_scan_window=ble_scan_win, timeout=120)
            time.sleep(120)
        if self.dual_role_dut_as_slave:
            if self.random_addr_on_dut:
                bt_dut_address = "11:33:33:33:33:11"
                self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=bt_dut_address)
            if self.random_addr_on_dut:
                self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1)
            else:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(3)

            logger().info("\n\n======= enable power save in ble dut ========")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            self.ble_clients.interfaces.bluetooth.close()
            self.ble_client_address = self.ble_clients.interfaces.bluetooth.start_smp_scan(self.bt_dut_address)
            assert self.ble_client_address, "failed to initiate ble in remote device"

            time.sleep(5)

            logger().info("Check the dut is listed...")
            self.ble_clients.interfaces.bluetooth.get_devices()
            try:
                if self.connection_update:
                    logger().info("Connecting to the DUT ..")
                    self.ble_clients.interfaces.bluetooth.connect(self.bt_dut_address, min_conn_interval=self.ble_conn_interval_min, max_conn_interval=self.ble_conn_interval_max)
                    logger().info("Pairing and connection successful.")
                else:
                    logger().info("Connecting to the DUT ..")
                    self.ble_clients.interfaces.bluetooth.pair_and_connect(self.bt_dut_address, timeout=10)
                    logger().info("Pairing and connection successful.")
                time.sleep(60)
                status = self.ble_clients.interfaces.bluetooth.get_connection_status(self.bt_dut_address)
                logger().info(f"Connection status in remote device '{self.ble_clients.name}' is:{status}")
                assert status, f"Remote device '{self.ble_clients.name}' is not connected to DUT"
            except Exception as e:
                logger().error(f"Error during pairing and connection: {e}")
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                time.sleep(5)
                # Handle the exception (e.g., retry, log additional details, or raise the exception)
                raise



            # self.ble_clients.interfaces.bluetooth.pair_and_connect(self.bt_dut_address)
            # time.sleep(60)

        if self.dual_role_dut_as_master:
            if self.random_addr_on_dut:
                bt_dut_address = "11:33:33:33:33:11"
                self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=bt_dut_address)
            # start adv on ble_client1
            self.ble_clients.interfaces.bluetooth.close()
            logger().info("Start adv on client")
            self.ble_client_address = self.ble_clients.interfaces.bluetooth.start_smp_adv(bt_dut_address=self.bt_dut_address)
            assert self.ble_client_address is not None
            time.sleep(1)

            # Start scanning and connect to ble client

            if self.random_addr_on_dut:
                logger().info(f"Start scanning and connect to ble client with random address")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=self.ble_client_address, ble_address_type=1, timeout=30
                )
            else:
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=self.ble_client_address, timeout=30
                )

            logger().info("\n\n======= enable power save in ble dut ========")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.ble_client_address, ble_conn_interval_min=self.ble_conn_interval_min, ble_conn_interval_max=self.ble_conn_interval_max,timeout=120)
            time.sleep(60)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            logger().info(f"dev state: {state}")
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        self.ble_clients.interfaces.bluetooth.stop_scanning()


    def scan_advertse_on_dut(self):
        assert len(self.ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
        ble_client1 = self.ble_clients[1]
        ble_client2 = self.ble_clients[0]
        logger().info("Initiate ble service in DUT")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_client_address = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble initialization failed in remote device"
        logger().info("Start scanning....")
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                    timeout=100)
        time.sleep(10)
        logger().info(" **** START ADVERTISING FROM DUT **** ")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_dir_addr=ble_dut_address, ble_adv_int_min=int(self.min_adv_int) / 0.625,
                                                       ble_adv_int_max=int(self.max_adv_int) / 0.625)
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address,
                                             ble_conn_interval_min=(int(self.min_conn_int) / 1.25),
                                             ble_conn_interval_max=(int(self.max_conn_int) / 1.25),
                                             ble_conn_latency=0,
                                             ble_supervision_timeout=3000,
                                             timeout=120,
                                             async_timeout=120)
        time.sleep(self.stability_check_time)
        logger().info("Check connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 9, "DUT is not connected to BLE"
        logger().info(f"Connection is stable after 5mins")
        logger().info("Disconnecting Dut")
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()

    def scan_types(self):
        self.ble_sniffer.interfaces.sniffer.init_sniffer()
        self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        assert len(self.ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
        ble_client1 = self.ble_clients[1]
        ble_client2 = self.ble_clients[0]
        logger().info("Initiate ble service in DUT")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=0, set_smp=1)
        assert self.ble_dut_address, "failed to initiate ble in dut"
        self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=self.ble_dut_address)
        ble_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=self.ble_dut_address)
        assert ble_client_address1, f"ble initialization failed in remote device"
        if self.scan_type == 1:
            logger().info(f"Start scanning with active scan type: {self.scan_type}...")
        else:
            logger().info(f"Start scanning with passive scan type: {self.scan_type}...")

        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address1,
                                                         ble_scan_type=self.scan_type,
                                                         ble_address_type=self.scan_addr_type, timeout=100)
        time.sleep(10)
        logger().info(" **** START ADVERTISING FROM DUT **** ")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_dir_addr=self.ble_dut_address,
                                                            ble_addr_type=self.adv_addr_type,
                                                            own_addr_type=self.own_addr_type)
        logger().info("enabling the power save modes ")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(self.stability_check_time)
        logger().info("Checking scanning and advertising  status of DUT")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 3, "DUT BLE device is not in scanning or advertising"
        logger().info(" **** START SCANNING DUT FROM REMOTE DEVICE 2 **** ")
        ble_client_address = ble_client2.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address)
        assert ble_client_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 2"
        sw = Stopwatch()
        previously_found_devices = {}
        device_found = 0
        while sw.elapsed_sec < 30:
            found_devices = ble_client2.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices
            if (
                    self.ble_dut_address in found_devices
                    and found_devices[self.ble_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = 1
        assert device_found, f"device is not available"
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        scan_result = ""
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data
        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address1) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {ble_client_address1}")
        logger().info(f"Performed scanning and advertised dut for 5mins")

        ble_dut_address_hex = re.split(":", self.ble_dut_address)
        ble_client_address_hex = re.split(":", ble_client_address1)
        ble_client_address2_hex = re.split(":", ble_client_address)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in ble_client_address_hex:
            slave_address = slave_address + hex_data_part
        slave_address2 = "0x"
        for hex_data_part in ble_client_address2_hex:
            slave_address2 = slave_address2 + hex_data_part

        self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address, slave_address2])

        self.ble_sniffer.interfaces.sniffer.stop_capture()
        captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(20)
        exported_csv_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", self.layer_name)
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        assert sniffer_data_df is not None
    def check_device_state_on_dut(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def check_device_state_on_rasp(self):
        logger().info(f"***********{self.ble_clients}")
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
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
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        for i in range(0, iter_count):
            ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, bt_dut_address=bt_dut_address,
                                       ble_adv_connection=True, adv_and_scan=True)
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_client_address = sl_collections.ble_connection(wifi_dut=wifi_dut, ble_client=ble_client2,
                                                               ble_dut_address=ble_obj.bt_dut_address,
                                                               mode="master")
            time.sleep(60)
            ble_obj.check_device_state_on_dut()
            ble_obj.check_device_state_on_rasp()
            ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, bt_dut_address=bt_dut_address,
                                       ble_adv_connection=True)
            ble_obj.check_device_state_on_rasp()
            ble_client1.interfaces.bluetooth.disconnect(ble_obj.bt_dut_address)
            time.sleep(3)
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(5)
            ble_client1.interfaces.bluetooth.remove_device(bt_dut_address)
            ble_client2.interfaces.bluetooth.remove_device(bt_dut_address)
            ble_client1.interfaces.bluetooth.close()
            ble_client2.interfaces.bluetooth.close()
            time.sleep(10)
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
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1,  bt_dut_address=bt_dut_address, ble_adv="ble_adv_powersave",
                                   ble_adv_connection=False, adv_and_scan=True)
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
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address)
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
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address, "failed to initiate ble in dut"
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, bt_dut_address=bt_dut_address, ble_adv="ble_adv_powersave",
                                   ble_adv_connection=False, adv_and_scan=True)
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
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_ble_connection_C663247(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
       2.Start the ble in dut
       3.Scan and advertise on dut
       4. Advertise on dut with 20ms interval
       5.Initiate a connection with dut
       6.Check stability for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients,ble_sniffer=ble_sniffer,
                                  min_adv_int=20, max_adv_int=20, min_conn_int=200, max_conn_int=200)
        ble_obj.scan_advertse_on_dut()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_ble_connection_C663248(wifi_dut, ble_clients,ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
         2.Start the ble in dut
         3.Scan and advertise on dut
         4. Advertise on dut with 16384ms interval
         5.Initiate a connection with dut
         6.Check stability for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients,ble_sniffer=ble_sniffer,
                                  min_adv_int=10240, max_adv_int=10240, min_conn_int=200, max_conn_int=200)
        ble_obj.scan_advertse_on_dut()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_active_scanning_with_random_address_advertising_with_random_address_C663235(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
           2.Start the ble in dut
           3.Scan and advertise on dut
           4.Enable the active scan on dut
           5.Scan with random address & Advertise with random address
           6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer, scan_type=1, scan_addr_type=1, adv_addr_type=1, own_addr_type=1, layer_name="LE ADV", capture_filename="frontline_capture_C663235")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info("stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_active_scanning_with_public_address_advertising_with_random_address_C663236(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the active scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer, scan_type=1, scan_addr_type=0,
                                   adv_addr_type=1, own_addr_type=1, layer_name="LE ADV", capture_filename="frontline_capture_C663236")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info("stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_active_scanning_with_random_address_advertising_with_public_address_C663237(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the active scan on dut
              5.Scan with random address & Advertise with public address
              6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer, scan_type=1, scan_addr_type=1,
                                   adv_addr_type=0, own_addr_type=0,layer_name="LE ADV", capture_filename="frontline_capture_C663237")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info("stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scanning_with_random_address_advertising_with_random_address_C663238(wifi_dut, ble_clients, ble_sniffer,sl_collections):
    """1.Initilize the dut in (0,13) opermode
           2.Start the ble in dut
           3.Scan and advertise on dut
           4.Enable the passive scan on dut
           5.Scan with random address & Advertise with random address
           6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer, scan_type=0, scan_addr_type=1, adv_addr_type=1, own_addr_type=1,layer_name="LE ADV", capture_filename="frontline_capture_C663238")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info("stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scanning_with_public_address_advertising_with_random_address_C663239(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer, scan_type=0, scan_addr_type=0,
                                   adv_addr_type=1, own_addr_type=1, layer_name="LE ADV", capture_filename="frontline_capture_C663239")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info("stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info(f"***************Testcase passed successfully***************")

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scanning_with_random_address_advertising_with_public_address_C663240(wifi_dut, ble_clients, ble_sniffer, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with random address & Advertise with public address
              6.Check scanning & advertising for 5mins"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_clients, ble_sniffer=ble_sniffer,scan_type=0, scan_addr_type=1,
                                   adv_addr_type=0, own_addr_type=0,layer_name="LE ADV", capture_filename="frontline_capture_C663240")
        ble_obj.scan_types()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_dual_role_connection_using_conn_interval_100_200_ms_C663245(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_master=True, bt_dut_address=bt_dut_address, ble_conn_interval_min=100, ble_conn_interval_max=100)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(10)

        ble_obj2 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client2, dual_role_dut_as_slave=True,  bt_dut_address=bt_dut_address, ble_conn_interval_min=200, ble_conn_interval_max=200, connection_update=True)
        ble_obj2.start()
        ble_obj2.wait_for_exit()

        time.sleep(600)

        ble_obj1.check_device_state_on_rasp()
        ble_obj2.check_device_state_on_rasp()
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client1,
                                   ble_client_address=ble_obj1.ble_client_address,
                                   ble_dut_address=bt_dut_address)


@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_dual_role_connection_using_conn_interval_500_1280_ms_C663246(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_master=True, bt_dut_address=bt_dut_address, ble_conn_interval_min=500, ble_conn_interval_max=500)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(10)

        ble_obj2 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client2, dual_role_dut_as_slave=True,  bt_dut_address=bt_dut_address, ble_conn_interval_min=1280, ble_conn_interval_max=1280, connection_update=True)
        ble_obj2.start()
        ble_obj2.wait_for_exit()

        time.sleep(600)

        ble_obj1.check_device_state_on_rasp()
        ble_obj2.check_device_state_on_rasp()
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client1,
                                   ble_client_address=ble_obj1.ble_client_address,
                                   ble_dut_address=bt_dut_address)

@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_ble_scanning_5ms_DUT_connected_as_peripheral_C663249(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_slave=True,
                                     bt_dut_address=bt_dut_address, ble_scan_interval=5, ble_scan_window=2.5, ble_scan=True)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(600)

        ble_obj1.check_device_state_on_rasp()
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client1,
                                   ble_client_address=ble_obj1.ble_client_address,
                                   ble_dut_address=bt_dut_address)

@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_ble_scanning_10240ms_DUT_connected_as_peripheral_C663250(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_slave=True,
                                    bt_dut_address=bt_dut_address, ble_scan_interval=10240, ble_scan_window=5000,ble_scan=True)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(600)

        ble_obj1.check_device_state_on_rasp()
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client1,
                                   ble_client_address=ble_obj1.ble_client_address,
                                   ble_dut_address=bt_dut_address)

@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_BLE_central_connection_with_random_addr_peripheral_connection_with_public_addr_C663244(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address_random = "11:33:33:33:33:11"
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_master=True, bt_dut_address=bt_dut_address)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(10)

        ble_obj2 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client2, dual_role_dut_as_slave=True, bt_dut_address=bt_dut_address_random, random_addr_on_dut=True)
        ble_obj2.start()
        ble_obj2.wait_for_exit()

        time.sleep(600)

        ble_obj1.check_device_state_on_rasp()
        status = ble_client2.interfaces.bluetooth.get_connection_status(bt_dut_address_random)
        logger().info(f"Connection status in remote device '{ble_client2.name}' is:{status}")
        assert status, f"Remote device '{ble_client2.name}' is not connected to DUT"
        logger().info("disconnecting from first raspi")
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        logger().info("disconnecting from secondary raspi")
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address_random)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_BLE_central_connection_with_public_addr_peripheral_connection_with_random_addr_C663243(wifi_dut, ble_clients, sl_collections):
    """1.Initilize the dut in (0,13) opermode
              2.Start the ble in dut
              3.Scan and advertise on dut
              4.Enable the passive scan on dut
              5.Scan with public address & Advertise with random address
              6.Check scanning & advertising for 5mins"""

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("Initiate ble service in DUT")
        bt_dut_address_random = "11:33:33:33:33:11"
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"

        ble_obj1 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client1, dual_role_dut_as_master=True, bt_dut_address=bt_dut_address, random_addr_on_dut=True)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        time.sleep(10)

        ble_obj2 = BleFunctionality(wifi_dut=wifi_dut, ble_clients=ble_client2, dual_role_dut_as_slave=True, bt_dut_address=bt_dut_address)
        ble_obj2.start()
        ble_obj2.wait_for_exit()

        time.sleep(600)
        #
        status = ble_client1.interfaces.bluetooth.get_connection_status("11:33:33:33:33:11")
        logger().info(f"Connection status in remote device '{ble_client1.name}' is:{status}")
        assert status, f"Remote device '{ble_client1.name}' is not connected to DUT"
        ble_obj2.check_device_state_on_rasp()
        logger().info("Disconnecting the bt host....")
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address_random)
        logger().info("disconnecting from secondary raspi")
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address)


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
