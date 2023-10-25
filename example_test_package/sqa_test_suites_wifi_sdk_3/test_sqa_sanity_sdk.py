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
    Si91xModuleType
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping


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
    def run(self):

        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

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
        if self.test_type == "iperf":
            logger().info("Running data transfer")
            self.run_traffic()

        logger().info("disconnecting to ap.....")
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("stopping the sniffer capture")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=self.power_save)
        logger().info("sniffer validation is successful")



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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_join_WORLD_2_4_C34788(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                        protocol, sl_collections, utf_constants, request, sniffer_filter):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        wifi_thread = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.Worldwide)

        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_join_EU_2_4_C34786(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                     protocol, request, utf_constants, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        wifi_thread = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.Europe)
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_join_US_2_4_C34785(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client,
                                     protocol, request, utf_constants, sl_collections, sniffer_filter):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        wifi_thread = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.US)
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_Connectivity_with_WPA2_security_AP_C34757(wifi_access_point, wifi_dut, wifi_sniffer, net_perf_client,
                                                            protocol,
                                                            request, utf_constants, sl_collections,
                                                            sniffer_filter, wifi_client):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "iperf"
        wifi_thread = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                     protocol=protocol, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     region=Si91xRegionCode.US)
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



