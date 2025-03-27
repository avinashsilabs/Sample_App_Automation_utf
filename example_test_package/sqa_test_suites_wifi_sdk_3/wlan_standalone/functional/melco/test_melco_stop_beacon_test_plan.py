from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap,
    Si91xCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants



def logger():
    return get_logger(__name__)


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="global",
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60, wifi_clients = None,
                 utf_constants = None, dtim_period = None, enable_data_rate = None, ht_caps =None,
                 ssid=None, security = None, password=None, beacon_interval=None,nw_interface=None,
                 channel=None, dtim_count=None, no_of_clients=None, beacon_stop = None,psk=None,
                 ap_mac_address =None, discon_client=None,capture_filename=None,dut_add_dict=None,
                 sniffer_filter=None,capture_filename_next=None, rasp_mac_address=None,raspi_mac=None):
        super().__init__()
        self.psk = psk
        self.nw_interface = nw_interface
        self.sniffer_filter=sniffer_filter
        self.wifi_clients = wifi_clients
        self.wifi_sniffer = wifi_sniffer
        self.utf_constants = utf_constants
        self.capture_filename=capture_filename
        self.enable_data_rate= enable_data_rate
        self.capture_filename_next=capture_filename_next
        self.dtim_period = dtim_period
        self.ht_caps = ht_caps
        self.ssid=ssid
        self.security=security
        self.password=password
        self.dtim_count=dtim_count
        self.beacon_interval=beacon_interval
        self.channel=channel
        self.no_of_clients=no_of_clients
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.dut_add_dict = dut_add_dict
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        # self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        # logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.remote_ip = None
        self.beacon_stop = beacon_stop
        self.ap_mac_address = ap_mac_address
        self.discon_client = discon_client
        self.rasp_mac_address=rasp_mac_address
        self.raspi_mac=raspi_mac

    def wc_network_interface(self):
        self.nw_interface = self.wifi_client.interfaces.wifi.config["interface"]
        logger().info(f"network interface from inside the function is {self.nw_interface}")
        return self.nw_interface
    def sniffer_capture_start(self, capture_filename="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def sniffer_capture_next_start(self, capture_filename_next="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename_next} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename_next}.pcap")
        time.sleep(3)

    def dut_ap_enable(self):
        ping_count = self.utf_constants.get("ping_count")

        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.psk,
                                               channel=self.channel,
                                               dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval,
                                               ht_caps=self.ht_caps, beacon_stop=self.beacon_stop)


    def dut_ap_mac_address(self):
        if self.test_id in [557377, 557378, 557379, 557380, 557381, 557382, 557383, 557384]:
            self.ap_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(2)
        else:
            self.ap_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"mac address of aput is {self.ap_mac_address}")
        return self.ap_mac_address


    def raspi_sta_assoc_to_dut_ap(self):
        for i in range(0, self.no_of_clients):
            self.dut_add_dict={}
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(5):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.raspi_mac = self.dut_add_dict['rasp_mac_address']
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
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



    def ping_async(self, ip_addr):

        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(20)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def raspi_disassoc_to_ap(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()



    def dut_sta_wifi_connection(self):
        try:
            self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                      wifi_access_point=self.wifi_access_point,
                                                                      associated=self.wifi_dut.interfaces.wifi.associated,
                                                                      power_save=False, retry_count=3,
                                                                      ping_before_power_save=False,
                                                                      ping_after_power_save=False,
                                                                      )
            ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=3,
                                                                    ip_version="ipv6")
            logger().info(f"printing device ip {ip_config[1]}")
            self.nw_interface = self.wifi_client.interfaces.wifi.config["interface"]
            logger().info(f"printing the network interface value inside dut_sta_wifi_connection function {self.nw_interface}")
            remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(network_interface=self.nw_interface,version=6, addr_type="link")
            logger().info(f"remote_ip: {remote_ip}")
            tar_addr = ipaddress.ip_address(remote_ip)
            logger().info(f"printing the interface value {self.nw_interface}")
            ip_addr = f"{tar_addr}%{self.nw_interface}"
            logger().info(f"ip address final format for ping is {ip_addr}")
            self.ping_async(ip_addr=tar_addr)
        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def check_deauth_frame_number(self, packet_filter2=None):
        logger().info(f"prinint the AP mac address inside disassoc frame {self.ap_mac_address}")
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            filter_name="deauthentication")
        self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                packet_filter2=packet_filter2)

        # self.wifi_sniffer.interfaces.capture.collecting_frame_number(packet_filter1 = packet_filter1
        #     )

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        first_line = filter_file.readline().replace('\n', '')

        logger().info(f"\n\n***** Deauth frame number is hits = {first_line}\n\n")

        # logger().info(f"prining the raw value frame_number {(frame_number)}")
        # logger().info(f"printing the type of frame number is  {type(frame_number)}")
        return first_line


    def check_no_beacons_from_aput(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_ap_mac_address(),
            filter_name="beacon")
        logger().info(f"printing check_no_beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    def check_beacons_from_aput(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_ap_mac_address(),
            filter_name="beacon")
        logger().info(f"printing check_beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_dut_ap_beacons_after_enabling_aput_beacon_stop_tc557371(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter, wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_clients=wifi_clients, wifi_client=wifi_client,
                                        sl_collections=sl_collections,utf_constants=utf_constants,sniffer_filter=sniffer_filter,
                                        test_id=557371,channel=8,beacon_stop=1,no_of_clients=1, ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
         }
)
def test_wifi_sdk_verify_beacon_stop_after_3rd_party_sta_connect_tc557372(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_client,
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients,
                                        test_id=557372,sniffer_filter=sniffer_filter, beacon_stop=1, channel=8, wifi_client=wifi_client,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_ap_enable()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
         }
)
def test_wifi_sdk_verify_beacon_stop_after_3rd_party_sta_disconnect_tc557373(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients,
                                        test_id=557373,sniffer_filter=sniffer_filter,beacon_stop=1,
                                        capture_filename="tc_id557373", channel=8,wifi_client=wifi_client,
                                        capture_filename_next="tc_id557373_after_disconn",ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_ap_enable()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        time.sleep(10)
        beacon_stop_ap_sta.raspi_disassoc_to_ap()
        beacon_stop_ap_sta.sniffer_capture_next_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
         }
)
def test_wifi_sdk_verify_beacon_resume_after_3rd_party_sta_reconnect_tc557374(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients, channel=8, wifi_client=wifi_client,
                                        test_id=557374,sniffer_filter=sniffer_filter,beacon_stop=1,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_ap_enable()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        time.sleep(10)
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        beacon_stop_ap_sta.raspi_disassoc_to_ap()
        beacon_stop_ap_sta.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
    }
)
def test_wifi_sdk_verify_beacon_stop_with_one_client_disconnection_in_multiclient_conn_tc557375(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=2, wifi_clients=wifi_clients,wifi_client=wifi_client,
                                        test_id=557375,sniffer_filter=sniffer_filter,beacon_stop=1, channel=8,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557375_ap_alone_capture")
        beacon_stop_ap_sta.dut_ap_enable()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557375_after_sta_connection")
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557375_after_one_sta_disconnection")
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
    }
)
def test_wifi_sdk_verify_beacon_stop_with_all_clients_disconnection_in_multiclient_conn_tc557376(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients,utf_constants,sniffer_filter,wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=2, wifi_clients=wifi_clients,wifi_client=wifi_client,
                                        test_id=557376,sniffer_filter=sniffer_filter,beacon_stop=1,  channel=8,
                                        capture_filename="tc557376_ap_alone_capture",ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557376_ap_alone_capture")
        beacon_stop_ap_sta.dut_ap_enable()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557376_sta_conn_capture")
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        beacon_stop_ap_sta.sniffer_capture_start(capture_filename="tc557376_after_all_clients_capture")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_beacon_stop_with_in_concurrent_mode_with_dut_wlan_conn_tc557377(wifi_client, wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_access_point
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients,
                                        test_id=557377,sniffer_filter=sniffer_filter,beacon_stop=1, channel=8,
                                        wifi_access_point=wifi_access_point,wifi_client=wifi_client,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               }
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "1",}
)
def test_wifi_sdk_verify_beacon_stop_with_in_concurrent_mode_with_dut_sta_disconn_tc557378(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_access_point,
                                                                      wifi_client):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients,
                                        test_id=557378,sniffer_filter=sniffer_filter,beacon_stop=1, channel=8,
                                        wifi_client=wifi_client, wifi_access_point=wifi_access_point,capture_filename="TC557378_capture",ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        wifi_dut.interfaces.wifi.leave()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,


    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "1",}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_verify_beacon_stop_with_in_concurrent_mode_with_dut_sta_conn_disconn_tc557379(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_access_point, wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients, channel=8,
                                        test_id=557379,sniffer_filter=sniffer_filter, capture_filename="tc_557379_sniffer_capture",
                                        wifi_client=wifi_client, beacon_stop=1,wifi_access_point=wifi_access_point,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()
        for i in range(0, 5):
            logger().info(f"iteration value is {i}")
            beacon_stop_ap_sta.sniffer_capture_start()
            beacon_stop_ap_sta.dut_sta_wifi_connection()
            time.sleep(5)
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
            wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(10)
            beacon_stop_ap_sta.check_no_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_3rd_party_sta_assoc_with_beacon_stop_enabled_with_sta_conn_tc557380(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,wifi_access_point,wifi_client
                                                                      ):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants, no_of_clients=1, wifi_clients=wifi_clients, channel=8,
                                        test_id=557380,sniffer_filter=sniffer_filter, capture_filename="tc_557380_sniffer_capture",
                                        wifi_access_point=wifi_access_point,wifi_client=wifi_client, beacon_stop=1,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_beacon_stop_with_3rd_party_sta_diconn_with_staut_conn_tc557381(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,
                                                                      wifi_access_point,wifi_client):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients, channel=8,
                                        test_id=557381,sniffer_filter=sniffer_filter, capture_filename="tc_557381_sniffer_capture",
                                        wifi_client=wifi_client, wifi_access_point=wifi_access_point, beacon_stop=1,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        time.sleep(2)
        beacon_stop_ap_sta.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_beacon_stop_with_3rd_party_sta_conn_with_staut_reconn_tc557382(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,
                                                                      wifi_access_point,wifi_client):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=1, wifi_clients=wifi_clients,channel=8,
                                        test_id=557382,sniffer_filter=sniffer_filter,capture_filename="tc_557382_sniffer_capture",
                                        wifi_client=wifi_client, wifi_access_point=wifi_access_point, beacon_stop=1,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        time.sleep(2)
        beacon_stop_ap_sta.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1:{
               "security": "WPA2",
               "ssid": "917_Melco_ap",
               "passphrase": "12345678",
               "channel": 8,
               "country": "US"
           }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_beacon_stop_staut_conn_with_one_3rd_party_sta_disconn_tc557383(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants,sniffer_filter,
                                                                      wifi_access_point, wifi_client):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants,no_of_clients=2, wifi_clients=wifi_clients, channel=8,
                                        test_id=557383,sniffer_filter=sniffer_filter, capture_filename="tc_557383_sniffer_capture",
                                        wifi_client=wifi_client, wifi_access_point=wifi_access_point, beacon_stop=1,ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        beacon_stop_ap_sta.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()

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
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
                         | Si91xTCPIPFeatureBitMap.DHCPv4Client
                         | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                         | Si91xTCPIPFeatureBitMap.DHCPv6Server
                         | Si91xTCPIPFeatureBitMap.DHCPv6Client
                         | Si91xTCPIPFeatureBitMap.IPv6Mode
                         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 8,
                "country": "US"
               },
           1:{
               "security": "WPA2",
               "ssid": "917_Melco_ap",
               "passphrase": "12345678",
               "channel": 8,
               "country": "US"
           }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "ipv6_state": "0",}
)
def test_wifi_sdk_verify_beacon_stop_staut_conn_with_all_3rd_party_sta_disconn_tc557384(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients,utf_constants,sniffer_filter,
                                                                      wifi_client, wifi_access_point):
    try:
        beacon_stop_ap_sta = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants=utf_constants, no_of_clients=2, wifi_clients=wifi_clients,
                                        test_id=557384,sniffer_filter=sniffer_filter, channel=8, beacon_stop=1,
                                        wifi_client=wifi_client,wifi_access_point=wifi_access_point,
                                        capture_filename="tc_557384_sniffer_capture",ssid = "917_Melco_ap",
                                        security = "WPA2", psk = "12345678")
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.dut_sta_wifi_connection()
        time.sleep(10)
        beacon_stop_ap_sta.dut_ap_enable()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        beacon_stop_ap_sta.check_no_beacons_from_aput()
        beacon_stop_ap_sta.sniffer_capture_start()
        beacon_stop_ap_sta.raspi_sta_assoc_to_dut_ap()
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_beacons_from_aput()
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        beacon_stop_ap_sta.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_stop_ap_sta.check_no_beacons_from_aput()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()