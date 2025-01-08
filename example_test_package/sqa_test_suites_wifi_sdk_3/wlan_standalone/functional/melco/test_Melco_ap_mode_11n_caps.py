import time
import pytest
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from random import randint
import random
import string
from utf.utf_config import UtfConfig
import re
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI



def logger():
    return get_logger(__name__)
class AP11nParamsEnabled(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, wifi_sniffer,
                 sl_collections, utf_constants,  net_perf_client=None, protocol=None,
                 testcase_no=None, capture_filename=None, dtim_period=None, beacon=None,
                 traffic_type=None, leave=True, enable_data_rate=False,
                 sniffer_stop=False, htcaps_enable=None, ssid=None, security = None,
                 password=None, dtim_count=None, beacon_interval=None,
                 channel=None, no_of_clients=None, ht_caps=None,
                 ipv6_addr_type="global",wifi_client=None, wifi_access_point=None,beacon_stop=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.wifi_access_point = wifi_access_point
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
        self.sniffer_stop = sniffer_stop
        self.htcaps_enable = htcaps_enable
        self.ssid = ssid
        self.security = security
        self.password = password
        self.dtim_count= dtim_count
        self.beacon_interval = beacon_interval
        self.channel = channel
        self.no_of_clients = no_of_clients
        self.ht_caps = ht_caps
        self.ipv6_addr_type=ipv6_addr_type
        self.beacon_stop = beacon_stop


    def sniffer_capture_start(self,channel=11, capture_filename="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def ping_async(self, ip_addr):

        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(20)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def raspi_sta_assoc_to_dut_ap(self):
        for i in range(0, self.no_of_clients):
            self.dut_add_dict={}
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.raspi_mac = self.dut_add_dict['rasp_mac_address']
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
                    time.sleep(10)
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {self.ping_count} {self.dut_add_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")


    def dut_aput_mac_addr_in_ap_alone_mode(self):
        dut_ap_mac_addr = self.dut_addr_dict["dut_mac_address"]
        logger().info(f" the dut_ap_mac_addr in ap alone mode {dut_ap_mac_addr}")
        return dut_ap_mac_addr

    def dut_sta_mac_addr_in_concur_mode(self):
        dut_sta_mac_addr = self.info_attr["dut_mac_address"]
        logger().info(f"The STA Mac address is {dut_sta_mac_addr}")
        return dut_sta_mac_addr

    def raspi_mac_addres(self):
        raspi_mac_addr = self.dut_addr_dict["rasp_mac_address"]
        logger().info(f"Printing the rapsi mac address is {raspi_mac_addr}")
        return raspi_mac_addr

    def check_no_beacons_from_aput(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            filter_name="beacon")
        logger().info(f"printing check_no_beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    def check_beacons_from_aput(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            filter_name="beacon")
        logger().info(f"printing checking beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    def aput_beacon_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr = self.dut_aput_mac_addr_in_ap_alone_mode(),
            filter_name="beacon_HT_info")
        logger().info(f"Validating the 11n HT Parameter in Beacons from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def aput_prb_rsp_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr = self.dut_aput_mac_addr_in_ap_alone_mode(),
            ra_addr = self.raspi_mac_addres(),
            filter_name="probe_res_ht_info")
        logger().info(f"Validating the 11n HT Parameter in Probe Response from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def aput_assoc_rsp_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr = self.dut_aput_mac_addr_in_ap_alone_mode(),
            ra_addr = self.raspi_mac_addres(),
            filter_name="asso_res_ht_info")
        logger().info(f"Validating the 11n HT Parameter in Association Response from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def staut_assoc_req_11ax_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr = self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="assoc_request_he_element")
        logger().info(f"Checking HE  params in Asssoc Request Frame {packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def sniffer_check(self):
        self.aput_beacon_11n_params_check()
        self.aput_prb_rsp_11n_params_check()
        self.aput_assoc_rsp_11n_params_check()
        if self.testcase_no in [557314, 557316]:
            self.staut_assoc_req_11ax_params_check()

    def aput_start(self):
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")

        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                       channel=11, ssid="917_AP",
                                                                       security="wpa2", password="12345678",
                                                                       dtim_count=3,
                                                                       beacon_interval=100,
                                                                       ht_caps=1,
                                                                       ping_count=ping_count,
                                                                       no_of_clients=1,
                                                                       leave=self.leave,
                                                                       enable_data_rate=self.enable_data_rate,
                                                                       beacon_stop = self.beacon_stop
                                                                       )

        logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")

        # time.sleep(20)
        if self.testcase_no in [557309]:
            time.sleep(20)
            logger().info("stopping the sotap")
            # self.wifi_dut.interfaces.wifi.stop_ap()
            self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(20)
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")
            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                channel=11, ssid="917_AP",
                                                                                security="wpa2", password="12345678",
                                                                                dtim_count=3,
                                                                                beacon_interval=100,
                                                                                ht_caps=1,
                                                                                ping_count=ping_count,
                                                                                no_of_clients=1,
                                                                                leave=self.leave,
                                                                                enable_data_rate=self.enable_data_rate,)

            logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")


    def concurrent_sta(self):
        ping_count = self.utf_constants.get("ping_count")
        self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  ip_config_disable=False,
                                                                  ip_version='ipv6',
                                                                  power_save=False, retry_count=3,
                                                                  ping_before_power_save=False,
                                                                  ping_after_power_save=False,
                                                                  ipv6_type=self.ipv6_addr_type
                                                                  )
        logger().info(f"printing value of STA Interface info_attr {self.info_attr}")
        time.sleep(20)

        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=11, ssid="917_AP",
                                                                            security="wpa2", password="12345678",
                                                                            dtim_count=3,
                                                                            beacon_interval=100,
                                                                            ht_caps=1,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=1,
                                                                            leave=self.leave,
                                                                            enable_data_rate=self.enable_data_rate,
                                                                            beacon_stop = self.beacon_stop)

        logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")
        network_interface=self.wifi_client.interfaces.wifi.config["v6_interface"]
        logger().info(f"printing the newly added interface {network_interface}")
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type, network_interface=network_interface)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.ping_async(ip_addr=ip_addr)

        device_ip = self.info_attr['device_ip']
        logger().info(f"device_ip : {device_ip}")

        if self.ipv6_addr_type == "link":
            interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
            device_ip = f"{device_ip}%{interface}"
            status = ping(device_ip, 10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"









@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
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
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_TC557308(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter
                                                                      ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections,utf_constants=utf_constants,sniffer_filter=sniffer_filter,
                                        testcase_no=557308,channel=11, capture_filename="TC557308_Sniffer")
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
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
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_with_swap_stop_restart_TC557309(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter
                                                                      ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections,
                                        utf_constants=utf_constants, sniffer_filter=sniffer_filter,
                                        testcase_no=557309, channel=11, capture_filename="TC557309_Sniffer")

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
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
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def \
        test_wifi_sdk_check_3rd_party_sta_conn_disconn_with11n_params_TC557312(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter
                                                                      ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections,utf_constants=utf_constants,
                                        testcase_no=557312, sniffer_filter=sniffer_filter,channel=11,
                                        capture_filename="TC557312_Sniffer",no_of_clients=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        time.sleep(20)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,


    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "channel" : 11,
                               "standard": 'gnbax'}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_in_concurrent_Mode_TC557313(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                                         sl_collections, wifi_clients, utf_constants,
                                                                                         wifi_client,sniffer_filter):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
                                        wifi_sniffer = wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants= utf_constants,  wifi_client=wifi_client,
                                        testcase_no=557313,sniffer_filter=sniffer_filter,channel=11,
                                        capture_filename="TC557313_pcap",ipv6_addr_type="link")
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,


    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "channel" : 11,
                               "standard": 'gnbax'}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rdparty_sta_conn_with_11n_params_DUT_STA_with_11ax_disabled_TC557314(wifi_access_point,
                                                                                              wifi_dut, wifi_sniffer, sl_collections,
                                                                                              wifi_clients, utf_constants,
                                                                                              wifi_client,sniffer_filter):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
                                        capture_filename="TC557314_pcap",
                                        wifi_sniffer = wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants= utf_constants,  wifi_client=wifi_client,
                                        testcase_no=557314, channel = 11,sniffer_filter=sniffer_filter,ipv6_addr_type="link",beacon_stop=0)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,


    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "channel" : 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_AP",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_beacon_Stop_with11n_mode_with_3rd_party_Sta_Conn_Disconn_TC557316(wifi_access_point, wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,
                                                                      wifi_client):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
                                        wifi_sniffer = wifi_sniffer, sl_collections=sl_collections,sniffer_filter=sniffer_filter,
                                        utf_constants= utf_constants,  wifi_client=wifi_client,
                                        testcase_no=557316,channel=8,capture_filename="TC557316_pcap",beacon_stop=1)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        time.sleep(10)
        ap_dut_obj.sniffer_capture_start()
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_no_beacons_from_aput()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()