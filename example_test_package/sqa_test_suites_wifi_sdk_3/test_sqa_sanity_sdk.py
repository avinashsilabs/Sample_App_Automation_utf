import time
import pytest
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
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes

)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth import BLEDeviceState



def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set Region ,scan ,connect, data transfer
        
    Author: Swathi.Chinthala

"""
# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, test_type=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, region=None, switch=None):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=self.protocol, device_ip=self.device_ip,
                                        host_ip=host_ip, timeout=60, traffic_type="TX")

    def sniffer_validation_join(self):
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=self.power_save)

    def disconnect(self):
        logger().info("disconnecting to ap.....")
        self.wifi_dut.interfaces.wifi.leave()

    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=self.power_save,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3, ping_after_power_save=True,
                                                                     ping_count=self.ping_count)
            self.device_ip = self.dut_addr['device_ip']
            self.dut_mac_address = self.dut_addr['dut_mac_address']
            logger().info(f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")


    def run(self):

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic()

        if self.test_type == "ping":
            self.join_to_ap()
            logger().info("Initiating ping from Raspi to DUT to check stability")
            status = ping(self.device_ip, 30)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"



# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, ble_scan_type=1,
                 ble_pairing=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert self.ble_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None
        self.ble_client.interfaces.bluetooth.close()

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()
        self.ble_client.interfaces.bluetooth.close()

    def ble_disconnect(self, disconnect_from="remote"):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()

    def set_power_save(self):
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

    def run(self):

        if self.ble_test_type == "slave":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.ble_dut_address,
                                                                         mode="slave", ble_pairing=self.ble_pairing)

        if self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.ble_dut_address,
                                                                         mode="master", ble_pairing=self.ble_pairing)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_firmware_version_C34753(wifi_dut, sl_collections):
    try:
        expected_version = parse_version()
        if expected_version is None:
            pytest.skip("No firmware version for 9116x in manifest, skipping test_version")
        logger().info(f"Expected Firmware version: {expected_version}")
        result = wifi_dut.interfaces.wifi.version().strip("\n")
        logger().info(f"Actual Firmware version: {result}")
        assert result == expected_version, "Expected Firmware version and Actual firmware version are not matching"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "worldwide",
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'Asia'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable",  "disassociated"])
def test_wifi_sdk_join_WORLD_2_4_C34788(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                        protocol, sl_collections, utf_constants, request, sniffer_filter):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.Worldwide)

        for count in range(0, iteration):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe",
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 12, "region": 'Europe'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable",  "disassociated"])
def test_wifi_sdk_join_EU_2_4_C34786(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                     protocol, request, utf_constants, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.Europe)
        for count in range(0, iteration):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "us",
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable",  "disassociated"])
def test_wifi_sdk_join_US_2_4_C34785(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                     protocol, request, utf_constants, sl_collections, sniffer_filter):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.US)
        for count in range(0, iteration):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable",  "disassociated"])
def test_wifi_sdk_Connectivity_with_WPA2_security_AP_C34757(wifi_access_point, wifi_dut, wifi_sniffer, net_perf_client,
                                                            protocol,
                                                            request, utf_constants, sl_collections,
                                                            sniffer_filter, wifi_client):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.US)
        for count in range(0, iteration):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                   #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_wifi_sdk_ble_slave_C34770(wifi_access_point, wifi_dut,
                                   request, utf_constants, sl_collections, ble_client):
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        for count in range(0, iteration):
            ble_obj.start()
            ble_obj.wait_for_exit()
            logger().info(f"Applying power save mode")
            ble_obj.set_power_save()
            logger().info("checking connection stability for 60secs")
            time.sleep(60)
            ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                       #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_wifi_sdk_ble_master_C34771(wifi_access_point, wifi_dut,
                                   request, utf_constants, sl_collections, ble_client):
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master")
        for count in range(0, iteration):
            ble_obj.start()
            ble_obj.wait_for_exit()
            logger().info(f"Applying power save mode")
            ble_obj.set_power_save()
            logger().info("checking connection stability for 60secs")
            time.sleep(60)
            ble_obj.ble_disconnect(disconnect_from="dut")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                       #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan"])
def test_wifi_sdk_ble_dual_role_C34774(wifi_access_point, wifi_dut,
                                   request, utf_constants, sl_collections, ble_clients):
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        ble_clients_address = []
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_clients[0], sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_clients_address1 = ble_obj.ble_client_address
        ble_clients_address.append(ble_clients_address1)
        ble_obj.set_power_save()
        ble_clients_address2 = sl_collections.ble_connection(wifi_dut=wifi_dut,
                                                             ble_client=ble_clients[1],
                                                             ble_dut_address=ble_obj.ble_dut_address,
                                                             mode="master")
        ble_clients_address.append(ble_clients_address2)
        logger().info("checking connection stability for 60secs")
        time.sleep(60)
        for i in range(0, len(ble_clients)):
            status = ble_clients[i].interfaces.bluetooth.get_connection_status(ble_obj.ble_dut_address)
            logger().info(f"Connection status in remote device '{ble_clients[0].name}' is:{status}")
            assert status, f"Remote device '{ble_clients[i].name}' is not connected to DUT"
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_clients_address[i])
            ble_clients[i].interfaces.bluetooth.close()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                       #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    },
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_connectivity_ping_sta_ble_C34778(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client,
                                                   sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Join the access point and enable the dhcp
               4. Enable wlan and bt power save mode in dut after the connection
               5. Advertise BLE DUT
               6. Scan from remote BLE device and connect to DUT and ping from remote device to DUT
               7. Disconnect from DUT to AP
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SANITY_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.wifi_clients(["raspi_wifi"])
def test_wifi_sdk_apmode_wpa2_aes_34765(wifi_sniffer, wifi_dut, request,
                                        wifi_clients, sl_collections, utf_constants, sniffer_filter):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        security = "WPA2"
        ssid = "SANITY_AP"
        passphrase = "12345678"
        channel = 11
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients, channel=channel, ssid=ssid,
                                                                  security=security, password=passphrase, dtim_count=1,
                                                                  beacon_interval=100, ping_count=ping_count,
                                                                  no_of_clients=1, leave=True,
                                                                  enable_data_rate=False)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=dut_addr_dict['rasp_mac_address'])
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "Concurent_ap",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_sta',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.wifi_clients(["raspi_wifi"])
def test_wifi_sdk_concurrent_mode_sta_ap_C34756(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter,
                                                request, utf_constants, sl_collections):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        security = "WPA2"
        ssid = "Concurent_ap"
        passphrase = "Automation@123"
        channel = 11
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        dut_addr = None
        for count in range(0, iter_count):

            dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           power_save=False,
                                                           ping_after_power_save=True, retry_count=3,
                                                           associated=wifi_dut.interfaces.wifi.associated)
            if count == 0:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                          channel=channel, ssid=ssid,
                                                                          security=security,
                                                                          password=passphrase,
                                                                          dtim_count=1,
                                                                          beacon_interval=100,
                                                                          ping_count=ping_count,
                                                                          no_of_clients=1,
                                                                          leave=True)
            wifi_dut.interfaces.wifi.leave()
            logger().info("Stop sniffer finally")

        wifi_clients[0].interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {ap_mac_address}")

        if dut_addr:
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'],
                                                   ap_mac_address, sniffer_filter, power_save=False)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()










