import re
import time
import test_apmode_sdk as ap
from threading import Thread
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers



"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4.Disconnect dut and connect again
    Author: Jyothi Nagireddy
"""

def logger():
    return get_logger(__name__)


class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=None, protocol=None, testcase_no = None, capture_filename = None,  traffic_type=None,leave=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase_no = testcase_no
        self.capture_filename = capture_filename
        self.traffic_type = traffic_type
        self.leave = leave
        if self.testcase_no == 19312:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1
        if self.testcase_no == 19318:
            self.ssid = "SILABS_AP_MODE"
            self.security = "OPEN"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

    def run(self):
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
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            dtim_count=self.dtim_count,
                                                                            beacon_interval=self.beacon_interval,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave
                                                                            )

        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut= self.wifi_dut,
                                                       wifi_access_point=self.wifi_access_point,
                                                       power_save=False,
                                                       ping_after_power_save=True, retry_count=3,
                                                       associated=self.wifi_dut.interfaces.wifi.associated
                                                       )
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")
        if self.traffic_type == "Tx":
            logger().info(f"***** starting iperf ******")
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr_dict['client_ip'],
                                                                 device_ip=self.dut_addr_dict['dut_ip'],
                                                                 protocol=self.protocol)
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** send traffic  ******")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                local_ip=self.dut_addr_dict['dut_ip'],
                                                remote_ip=self.dut_addr_dict['client_ip'],
                                                remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                size=1460, ttl=30, throughput_type=1, qos=0)
            logger().info(f"***** get and print throughput ******")
            tp = self.net_perf_client.interfaces.net_perf.process_output()
            assert tp, "failed to get throughput..."
            logger().info("data transfer is successful")
        logger().info("Stop sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()

    def sta_ap_connection(self):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")
        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                            wifi_access_point=self.wifi_access_point,
                                                            power_save=False,
                                                            ping_after_power_save=True, retry_count=3,
                                                            associated=self.wifi_dut.interfaces.wifi.associated
                                                            )
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=self.channel, ssid=self.ssid,
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            dtim_count=self.dtim_count,
                                                                            beacon_interval=self.beacon_interval,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave)

        if self.traffic_type == "Tx":
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                       protocol=self.protocol, device_ip=self.dut_addr_dict['dut_ip'],
                                       host_ip=self.dut_addr_dict['client_ip'], timeout=40, traffic_type="TX")

        logger().info("Stop sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()

    def datatransfer_tx(self):
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr['client_ip'],
                                                             device_ip=self.dut_addr['device_ip'],
                                                             protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.dut_addr['device_ip'],
                                            remote_ip=self.dut_addr_dict['client_ip'],
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=30, throughput_type=1, qos=0)
        logger().info(f"***** get and print throughput ******")
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        logger().info("data transfer is successful")
        time.sleep(5)
    def concurrent_sniffer_validation(self):
        # packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        #     sa_addr=self.dut_addr_dict['dut_mac_address'],
        #     filter_name='beacon')
        # assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        #     'Unable to find  beacon in Sniffer'
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                    self.dut_addr['dut_mac_address'],
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=False)
    def ap_sta_disconnection(self):
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()
        self.wifi_dut.interfaces.wifi.leave()




pytestmark = [
  pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
  ]


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
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_sta_ap_c19312(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, protocol, net_perf_client):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=net_perf_client, protocol=protocol,testcase_no=19312, capture_filename="test_c19312", traffic_type="Tx")
        conc_obj.sta_ap_connection()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.ap_sta_disconnection()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19313(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in AP and STA connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=net_perf_client, protocol=protocol, testcase_no=19312,
                                    capture_filename="test_c19313")
        conc_obj.start()
        conc_obj.wait_for_exit()
        status = ping(conc_obj.dut_addr_dict['dut_ip'], 10)
        assert status == 1, "failed to ping to client"
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.init_server(host_ip=conc_obj.dut_addr_dict['client_ip'],
                                                             device_ip=conc_obj.dut_addr_dict['dut_ip'],
                                                             protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=conc_obj.dut_addr_dict['dut_ip'],
                                            remote_ip=conc_obj.dut_addr_dict['client_ip'],
                                            remote_port=net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=60, throughput_type=1, qos=0)
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        logger().info("data transfer is successful")
        time.sleep(5)
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
def test_wifi_sdk_device_as_ap_and_sta_c19314(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour  disconnecting the 3rd AP connection by enabling concurrent mode
        To Verify dut reconnection after disconnection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19314")
        conc_obj.start()
        conc_obj.wait_for_exit()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
            logger().info(f"reconnecting  to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
def test_wifi_sdk_device_as_ap_and_sta_c19315(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                   utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour by disconnecting the connected STA  by enabling concurrent mode
        To Verify dut reconnection after disconnection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19315")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("Disconnecting DUT station from 3rd party AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            power_save=False,
                                            ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated
                                            )
        wifi_dut.interfaces.wifi.leave()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "cipher": 'AES', "channel": 11})
def test_wifi_sdk_device_as_ap_and_sta_c19319(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour when we use the WPA2-AES security in STA and AP connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19319")
        conc_obj.start()
        conc_obj.wait_for_exit()
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19320(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    """Data transfer between WSC AP and connected STA and between WSC STA and connected AP"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, net_perf_client=net_perf_client, protocol=protocol,
                                    testcase_no=19318,
                                    capture_filename="test_c19320")
        conc_obj.ap_sta_connection()
        conc_obj.datatransfer_tx()


        # sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
        #                            protocol=protocol, device_ip=conc_obj.dut_addr_dict['dut_ip'],
        #                            host_ip=conc_obj.dut_addr_dict['client_ip'], timeout=30, traffic_type="TX")
        # sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
        #                                 protocol=protocol, device_ip=conc_obj.dut_addr['device_ip'],
        #                                 host_ip=conc_obj.dut_addr_dict['client_ip'], timeout=40, traffic_type="TX")
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
def test_wifi_sdk_device_as_ap_and_sta_c19324(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                     utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in Ap and STA connection by enabling concurrent mode"""
    """To Verify the dut behaviour after multiple disconnection and connection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point,
                                    testcase_no=19312,
                                    capture_filename="test_c19324")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("connect and disconnect for multiple times")
        for count in range(1, 4):
            wifi_dut.interfaces.wifi.leave()
            sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                wifi_access_point=wifi_access_point,
                                                power_save=False,
                                                ping_after_power_save=True, retry_count=3,
                                                associated=wifi_dut.interfaces.wifi.associated
                                                )
            logger().info(f'connected and disconnected for {count}nd time')
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()


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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "OPEN", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
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
def test_wifi_sdk_device_as_ap_and_sta_c19317(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                     utf_constants, sniffer_filter, switch):
    """ To Verify Dut rejoin Behaviour in  Ap and STA connection by enabling concurrent mode"""
    try:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=10,
                                                                      scan_interval=4,
                                                                      beacon_missed_count=40,
                                                                      first_time_retry_enable=0)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point,
                                    testcase_no=19312,
                                    capture_filename="test_c19317")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("\n\nTurning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=150)
        logger().info("Successfully powered off AP")
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        since_time = time.perf_counter_ns()
        while sw.elapsed_sec <= 500:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_msg = 1
            if rejoin_msg:
                break
        assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 500 seconds"
        logger().info("Rejoin Error Received from DUT")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("\n\nAgain turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        logger().info("Successfully powered on AP")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "OPEN", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)

@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "OPEN",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19318(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode in different security modes"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19313", traffic_type="Tx")
        conc_obj.start()
        conc_obj.wait_for_exit()
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
