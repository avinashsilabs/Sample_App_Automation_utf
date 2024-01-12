import time
import pytest
from utf.utf_config import UtfConfig
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


"""Test Author = Jyothi Nagireddy
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(Raspberry)
        4. Initiate ping from the wifi client
        5. Disconnect the wifi client
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4 - 2 and more                                                           
        3. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

class ApModeClientConnections(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, wifi_sniffer,
                 sl_collections, utf_constants,  net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 dtim_period=None, beacon=None, traffic_type=None, leave=True, enable_data_rate=False):
        self.wifi_dut = wifi_dut
        self.wifi_clients = wifi_clients
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.utf_constants = utf_constants
        self.capture_filename = capture_filename
        self.testcase_no = testcase_no
        self.dtim_period = dtim_period
        self.beacon = beacon
        self.traffic_type = traffic_type
        self.leave = leave
        self.enable_data_rate = enable_data_rate

    def run(self):
        if self.testcase_no == 19454 or 19432:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 4
        if self.testcase_no == 19465:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

        if self.testcase_no == 19484:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 2

        if self.testcase_no == 19456:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "13"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 4

        if self.testcase_no == 19444:
            self.ssid = "SILABS_AP_C19444"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.beacon_interval = "100"
            self.channel = "11"
            self.dtim_count = self.dtim_period
            self.no_of_clients = 1
        if self.testcase_no == 19443:
            self.ssid = "SILABS_AP_C19443"
            self.security = "WPA2"
            self.password = "12345678"
            self.dtim_count = "1"
            self.beacon_interval = self.beacon
            self.channel = "11"
            self.no_of_clients = 1
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                       channel=self.channel, ssid=self.ssid,
                                                                       security=self.security, password=self.password,
                                                                       dtim_count=self.dtim_count,
                                                                       beacon_interval=self.beacon_interval,
                                                                       ping_count=ping_count,
                                                                       no_of_clients=self.no_of_clients,
                                                                       leave=self.leave,
                                                                       enable_data_rate=self.enable_data_rate)
        if self.traffic_type == "Tx":
            logger().info(f"***** starting iperf ******")
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr_dict['client_ip'], device_ip=self.dut_addr_dict['dut_ip'],
                                                                 protocol=self.protocol)
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** send traffic  ******")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                           local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                           local_ip=self.dut_addr_dict['dut_ip'],
                                           remote_ip=self.dut_addr_dict['client_ip'],
                                           remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                           size=1460, ttl=30, throughput_type=1, qos=0, async_socket=1)
            logger().info(f"***** get and print throughput ******")
            tp = self.net_perf_client.interfaces.net_perf.process_output()
            assert tp, "failed to get throughput..."
            logger().info("data transfer is successful")
            time.sleep(5)
        if self.traffic_type == "Rx":
            if self.protocol == "UDP":
                transfer_type = 2
                protocol = 17
                size = 1470
                throughput_type = 4
                bandwidth = "68M"
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.dut_addr_dict['client_ip'],
                                                                     device_ip=self.dut_addr_dict['dut_ip'],
                                                                     protocol=self.protocol, bandwidth=bandwidth)
            else:
                transfer_type = 1
                protocol = 6
                size = 1460
                throughput_type = 3
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.dut_addr_dict['client_ip'],
                                                                     device_ip=self.dut_addr_dict['dut_ip'],
                                                                     protocol=self.protocol)

            self.net_perf_client.interfaces.net_perf.start()

            logger().info("receiving data from Host")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                local_ip=self.dut_addr_dict['dut_ip'],
                                                remote_ip=self.dut_addr_dict['client_ip'],
                                                remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                size=size, ttl=30, throughput_type=throughput_type, qos=0)

            logger().info("data received is successful")
            time.sleep(3)
        logger().info("Stop sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": "us"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
def test_wifi_sdk_ap_mode_tx_rules_us_region_c19454(wifi_dut, wifi_clients, wifi_sniffer,
                                                   sl_collections, wifi_client, utf_constants, sniffer_filter):
    """ Verify Ap mode connection when region selected is US and region
        parameters are defined by user"""
    try:
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19454",
                                             testcase_no=19454)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], radio_ch=ap_dut_obj.channel,
            filter_name="beacon_ap_mode_us_region")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region US in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
         "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": "11",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
def test_wifi_sdk_dutap_multiclient_connect_disconnect_c19432(wifi_sniffer, wifi_dut, wifi_clients,
                                                              sl_collections, utf_constants,
                                                              sniffer_filter):
    """AP functionality, If many clients are connected & disconnected multiple times"""
    try:
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19432",
                                             testcase_no=19432)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(4):
            sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                 dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                 rasp_mac_address=wifi_clients[i].interfaces.wifi.get_mac_address())

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19444",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("dtim_count", [1, 2, 3, 6, 10])
def test_wifi_sdk_various_dtim_intervals_c19444(wifi_sniffer, wifi_dut, wifi_clients,
                                                utf_constants, sl_collections,
                                                sniffer_filter, dtim_count):
    """Verify DTIM intervals by configuring different DTIM intervals(1,2,3,6,10)"""
    try:
        file_name = f'test_DTIM_{dtim_count}_C19444'
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename=file_name, dtim_period=dtim_count,
                                             testcase_no=19444)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], dtim_period=dtim_count,
            filter_name="beacon_ap_mode_dtim_period")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find beacon_ap_mode_dtim_period packet in sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        "security": "WPA2", "ssid": "SILABS_AP_C19443", "passphrase": "12345678", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19443",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("beacon", [100, 200, 600, 1000])
def test_wifi_sdk_dutap_diff_beacon_intervals_c19443(wifi_sniffer, wifi_dut, beacon,
                                                     wifi_clients, sl_collections, utf_constants, sniffer_filter):
    """Verify beacon intervals by configuring different beacon intervals(100,200,600,1000)"""
    try:
        file_name = f'test_beacon_interval_{beacon}_C19443'
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename=file_name, beacon=beacon,
                                             testcase_no=19443)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                         wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                         radio_ch=ap_dut_obj.channel,
                         beacon=beacon, filter_name="beacon_ap_mode_dtim_interval")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find beacon_ap_mode_dtim_interval packet in sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123",
        "beacon": 100,
        "channel": "11",
        "region": 1,
        "region_code": "us"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
def test_wifi_sdk_max_stas_connect_and_ping_c19430_c19442(wifi_sniffer,  wifi_dut,
                                                          wifi_clients, sl_collections, utf_constants,  sniffer_filter):
    """AP Sequence with many STAS connected"""
    try:
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19442",
                                             testcase_no=19432)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'
        for asso_id in range(4):
            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], association_id=asso_id+1,
                filter_name='apmode_association_id')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
                f"unable to find apmode_association_id_{asso_id+1}"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "beacon": 100,
        "channel": 14,
        "region": 1,
        "region_code": "us"

    },
)
@pytest.mark.parametrize("channel", [14])
def test_wifi_sdk_dutap_usregion_unsupported_channel_c19458(wifi_dut, wifi_sniffer, channel, sl_collections):
    try:
        logger().info("********* configuring static ip to DUT *********")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.168", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.168")
        with pytest.raises(WlanError) as exc_info:
            logger().info(" ********** Starting DUT as an AP with region as US and channel as 14 ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            logger().info(f"error code received:{exc_info.value.error_code}")
        assert exc_info.value.error_code == 0x1000A, "Did not receive the desired error code from DUT, failing the test"
        logger().info("Found the desired error code 0x1000A, marking the test case passed")

    except:
        logger().info(f"Expected error code -->0x1000A")

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100, "channel": 11,
        "region": 1,
        "region_code": "us"
     }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@1234",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_apmode_connectivity_with_wrong_psk_cli_c19437(wifi_sniffer, sniffer_filter,
                                                                utf_constants, wifi_dut, wifi_clients, sl_collections):
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants,
                                             testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name="disassociation")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find disassociation packet in sniffer'
    except:
        logger().info(f"connectivity fails as PSK is given wrong -->Expected")
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,
        "channel": 13, "region": 1,
        "region_code": "japan",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["set_default_region"])
def test_wifi_sdk_ap_mode_tx_rules_jp_region_c19456(wifi_dut, sniffer_filter,
                                                    wifi_sniffer,
                                                    wifi_clients, sl_collections, utf_constants):
    """Verify whether DUT is obeying transmission rules(Transmitting with only given power as per channel) according
       to the inputs given in the set region ap api when region selected is JP and region parameters are
       defined by the user"""
    try:
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants,
                                             capture_filename="test_C19456",
                                             testcase_no=19456)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], radio_ch=ap_dut_obj.channel,
            filter_name="beacon_ap_mode_jp_region")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region JP in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100, "channel": "13",
        "region": 1,
        "region_code": "europe",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["set_default_region"])
def test_wifi_sdk_ap_mode_tx_rules_eu_region_c19455(wifi_dut, wifi_sniffer,
                                                    wifi_clients, sl_collections, utf_constants, sniffer_filter):
    """Verify whether DUT is obeying transmission rules(Transmitting with only given power as per channel) according to
    the inputs given in the set region ap api when region selected is EU and region parameters are defined by user"""
    try:
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19455",
                                             testcase_no=19456)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], radio_ch=ap_dut_obj.channel,
            filter_name="beacon_ap_mode_eu_region")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region EU in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_C19447", "passphrase": "12345678", "dtim": 4,
        "region_code_ap": "US ",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19447",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps-NA")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("beacon", [100, 200, 300])
def test_wifi_sdk_dutap_tcp_tx_rx_c19447(wifi_sniffer, wifi_access_point, net_perf_client, wifi_dut, wifi_client,
                                         wifi_clients, protocol, channel, beacon, utf_constants, sl_collections):
    """Data transfer TX and RX by enabling HT CAPs in AP mode"""
    ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                         utf_constants, capture_filename="test_C19432", dtim_count=None,
                                         testcase_no=19432)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    # iperf code
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  HT_IE in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                        filter_name="beacon_interval")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find  beacon interval in Sniffer'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_C19436", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19436",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps support-NA")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_wifi_sdk_dutap_verify_beacon_format_c19436(wifi_sniffer, wifi_dut, channel, wifi_access_point,
                                                    utf_constants, sl_collections, wifi_clients):
    """Verify beacon format sent by APUT"""
    beacon = 100
    ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                         utf_constants, capture_filename="test_C19432", dtim_count=None,
                                         testcase_no=19432)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.set_htcaps()
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon frame in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon_ap_mode_dtim_interval")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        f'Unable to find dtim interval in Sniffer'
    packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
        'Unable to find  HT_IE in Sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_C19446", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "dtim": 4,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19446",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps support")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_dut_apmode_11n_htcaps_support_c19446(wifi_sniffer, wifi_dut, wifi_access_point, channel, protocol,
                                                       sl_collections, wifi_clients, utf_constants):
    """HT CAP Functionality ,High through put capabilities in AP mode"""
    logger().info(" ********** Starting DUT as an AP ********* ")
    # wifi_dut.interfaces.wifi.set_htcaps()
    ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                          utf_constants, capture_filename="test_C19432", dtim_count=None,
                                          testcase_no=19432)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon frame in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=
                                                                        ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find HT_IE in Sniffer'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'external_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_dut_soft_reset_sta_to_ap_c19449(wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                  wifi_access_point,
                                                  utf_constants, sl_collections, sniffer_filter):
    """Soft Reset functionality when dUT moving from STA mode to AP mode"""
    try:
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_softreset_statoap_C19449')
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       retry_count=3, ping_after_power_save=True,
                                                       ping_count=ping_count)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'],
                                               ap_bssid, sniffer_filter,
                                               power_save=False)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=dut_addr['dut_mac_address'],
            ra_addr=ap_bssid,
            filter_name='data_packets')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: Unable to find data_packets in sniffer'
        logger().info("Initiating deinit")
        wifi_dut.interfaces.wifi.deinit()
        logger().info("Initiating init to change DUT STA mode to AP Mode ")
        wifi_dut.interfaces.wifi.set_wifi_config(oper_mode=6, coex_mode=13)
        wifi_dut.interfaces.wifi.init(mode="ap", config_required=False)
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19449",
                                             testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,
        'channel': 11,
        "region": 1,
        "region_code": "us",
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'external_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_dut_ap_mode_soft_reset_ap_to_sta_c19450(wifi_sniffer, wifi_dut, wifi_clients,  channel,
                                                          wifi_access_point, utf_constants, sl_collections, sniffer_filter
                                                          ):
    """Soft Reset functionality when DEVUT moving from AP mode to STA mode"""
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants, capture_filename="test_C19450",
                                             testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            ra_addr=ap_dut_obj.dut_addr_dict['rasp_mac_address'],
            filter_name='data_packets')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: Unable to find data_packets in sniffer'
        logger().info("Initiating de init")
        wifi_dut.interfaces.wifi.deinit()
        logger().info("Initiating init to change DUT AP mode to STA Mode ")
        wifi_dut.interfaces.wifi.set_wifi_config(oper_mode=0, coex_mode=13)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19450_dut_sta')
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       retry_count=3, ping_after_power_save=True,
                                                       ping_count=ping_count)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'],
                                               ap_bssid, sniffer_filter,
                                               power_save=False)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=dut_addr['dut_mac_address'],
            ra_addr=ap_bssid,
            filter_name='data_packets')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: Unable to find data_packets in sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



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
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_dutap_fixed_data_rate_c19441(wifi_sniffer, wifi_dut,
                                               wifi_clients, sl_collections, utf_constants, sniffer_filter,
                                               net_perf_client, protocol):
    """Verify fixed data rate (54mbps) in Apmode"""
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants,  net_perf_client=net_perf_client, protocol=protocol, capture_filename="test_c19441",
                                             testcase_no=19465, traffic_type="Tx", enable_data_rate=True, leave=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], da_addr=ap_dut_obj.dut_addr_dict['rasp_mac_address'],
            radio_ch=ap_dut_obj.channel,
            filter_name='mgmt_data_rates_data_rate_54mbps_apmode')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find any packets for Data/Qos/Null packet for 54 Mbps data rates'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
