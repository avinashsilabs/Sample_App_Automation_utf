import time
import pytest
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils import print_dict


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Author: 
      - SVN / Saurabh Sharma
"""

def logger():
    return get_logger(__name__)
class AP11nParamsEnabled(ThreadBase):
    dut_add_dict = {}
    def __init__(self, wifi_dut=None, wifi_clients=None, wifi_sniffer=None, sl_collections=None, utf_constants=None,
                 net_perf_client=None,
                 protocol=None, testcase_no=None, capture_filename=None, dtim_period=None, beacon=None,
                 traffic_type=None, leave=True, enable_data_rate=False, sniffer_stop=False, htcaps_enable=None,
                 ssid=None, security = None, password=None, dtim_count=None, beacon_interval=None, channel=None,
                 no_of_clients=1, ht_caps=None,psk=None, ipv6_addr_type="global",wifi_client=None,
                 wifi_access_point=None,beacon_stop=None, sniffer_filter=None, net_perf_server=None):
        super().__init__()
        self.psk = psk
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
        self.net_perf_server = net_perf_server

    def sniffer_capture_start(self):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def dut_aput_mac_addr_in_ap_alone_mode(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")
        return dut_mac_address


    def dut_sta_mac_addr_in_concur_mode(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")
        return dut_mac_address

    def raspi_mac_addres(self):
        raspi_mac_addr = self.wifi_clients.interfaces.wifi.get_mac_address()
        logger().info(f"The Raspi Mac address is {raspi_mac_addr}")
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
            ra_addr = self.dut_add_dict['rasp_mac_address'],
            filter_name="probe_res_ht_info")
        logger().info(f"Validating the 11n HT Parameter in Probe Response from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def aput_assoc_rsp_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr = self.dut_aput_mac_addr_in_ap_alone_mode(),
            ra_addr = self.dut_add_dict['rasp_mac_address'], filter_name="asso_res_ht_info")
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

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            filter_name="radio_mcs_index_7")
        logger().info(
            f"Validating the 11n mcs parameter {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']


    def dut_ap_enable(self):
        ping_count = self.utf_constants.get("ping_count")
        try:
            self.sl_collections.configure_dut_in_static_ip(
                self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                static_gateway="192.168.100.76")

            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.psk,
                                                   channel=self.channel, dtim_beacon_count=self.dtim_count,
                                                   beacon_interval=self.beacon_interval, ht_caps=self.ht_caps,
                                                   beacon_stop=self.beacon_stop)
        except Exception as Ex:
            logger().info(f"Exception Block")
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def raspi_sta_assoc_to_dut_ap(self):
        for i in range(0, self.no_of_clients):
            ping_count = self.utf_constants.get("ping_count")
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
                    raspi_mac = self.dut_add_dict['rasp_mac_address']
                    logger().info(f"raspberry mac address: {raspi_mac}")
                    self.dut_add_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {self.dut_add_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {self.dut_add_dict['dut_ip']}")
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

        return self.dut_add_dict

    def aput_start(self):
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")
        self.dut_ap_enable()
        self.raspi_sta_assoc_to_dut_ap()


    def concurrent_sta_mode(self):
        self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
            associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
            ping_after_power_save=False)

        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version='ipv6')
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
        self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"DUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                      f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

    def check_ping_status_ipv6(self, ping_count=10):
        """
        Ping the given IP address.
        """
        interface = self.wifi_client.interfaces.wifi.config["interface"]
        ping_link_local_addr = f"{self.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
        status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=ping_count, retry_count=3)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def client_disconnect(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()
    def dut_leave_ap(self):
        self.wifi_dut.interfaces.wifi.leave()

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def data_rate(self):
        logger().info("********** enabling data rate *********")
        self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="72.2Mbps", interface="ap")

    def run_traffic_between_two_clients(
            self, net_perf_server, net_perf_client, server_ip, client_ip, protocol, iperf_time=30):

        logger().info(f"***** Starting Iperf Server on {net_perf_server.name} *****")
        net_perf_server.interfaces.net_perf.init_server(protocol=protocol, host_ip=client_ip,
                                                        device_ip=server_ip, time_out=iperf_time)
        net_perf_server.interfaces.net_perf.start()
        server_port = net_perf_server.interfaces.net_perf.server_port
        time.sleep(5)

        logger().info(f"**** Starting Iperf Client on {net_perf_client.name} ****")
        net_perf_client.interfaces.net_perf.init_client(host_ip=server_ip, device_ip=client_ip,
                                                        protocol=protocol, time_out=iperf_time)

        client_port = net_perf_client.interfaces.net_perf.client_port
        args = net_perf_client.interfaces.net_perf.executable_arguments
        args[args.index(str(client_port))] = str(server_port)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(iperf_time + 5)
        logger().info("Printing Throughput")
        tp = net_perf_server.interfaces.net_perf.process_output()
        assert tp is not None
        self.print_throughput(tp)

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US",
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_TC557308(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants,sniffer_filter):

    """Verify the 3rd party STA connectivity to APUT with 11N Paramters Enabled"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            utf_constants=utf_constants,sniffer_filter=sniffer_filter, testcase_no=557308,channel=11,
            capture_filename="TC557308_Sniffer", beacon_stop=0, ssid="917_Melco_ap", no_of_clients= 1, security="WPA2",
            psk="12345678", ht_caps=1)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_with_swap_stop_restart_TC557309(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants,sniffer_filter):

    """Verify the 3rd party Association to APUT Before and After AP Start and Stop Feature with 11N Parameters Enabled"""

    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections,ht_caps=1,
                                        utf_constants=utf_constants, sniffer_filter=sniffer_filter,
                                        testcase_no=557309, channel=11, capture_filename="TC557309_Sniffer",
                                        ssid="917_Melco_ap", no_of_clients= 1, security="WPA2", psk="12345678")

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(5)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_conn_disconn_with11n_params_TC557312(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants,sniffer_filter):

    """Verify the 11n Parameters with 3rd party STA disconnection and reconnection scenario"""

    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections,utf_constants=utf_constants,
                                        testcase_no=557312, sniffer_filter=sniffer_filter,channel=11,
                                        capture_filename="TC557312_Sniffer",no_of_clients=1,
                                        ssid="917_Melco_ap", security="WPA2", psk="12345678",ht_caps=1,)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        time.sleep(20)
        ap_dut_obj.sniffer_capture_start()
        time.sleep(10)
        ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config("wifi_access_point", wifi={'connection_type': 'STATIC_IPV6',
                'wan_ipv6_address': "2401:4900:1cb3:3444:3223:3324:1235:1bca",
                'wan_ipv6_gateway': "2401:4900:1cb3:3444::1",
                'wan_prefix_length': 64,
                'ipv6_state': "1", #0= "stateless" 1="stateful"
                'lan_ipv6_address': "2401:3500:133c:1341:1134:2541:13cd:1134",
                'lan_prefix_length': 64,
                'lan_ipv6_prefix': "2401:3500:133c:1341::",
                'lan_ip_pool_start': "1000",
                'lan_ip_pool_end': "2000",
                'lan_lease_time': 86400, "use_ipv6_web": True, "channel": 11, "standard": 'gnbax'})
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rd_party_sta_assoc_with_11n_enabled_in_concurrent_Mode_TC557313(
        wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, wifi_client,
        sniffer_filter):

    """Verify the 3rd party STA Connectivity to APUT with 11n Parameters enabled in Concurrent Mode when STAUT
    connected to 3rd party AP"""

    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
                                        wifi_sniffer = wifi_sniffer, sl_collections=sl_collections,
                                        utf_constants= utf_constants,  wifi_client=wifi_client,
                                        testcase_no=557313,sniffer_filter=sniffer_filter,channel=11,
                                        capture_filename="TC557313_pcap",ipv6_addr_type="link", no_of_clients=1,
                                        ssid="917_Melco_ap", security="WPA2", psk="12345678",ht_caps=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta_mode()
        ap_dut_obj.check_ping_status_ipv6()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,


    },
)
@pytest.mark.config("wifi_access_point", wifi={'connection_type': 'STATIC_IPV6',
                'wan_ipv6_address': "2401:4900:1cb3:3444:3223:3324:1235:1bca",
                'wan_ipv6_gateway': "2401:4900:1cb3:3444::1",
                'wan_prefix_length': 64,
                'ipv6_state': "1", #0= "stateless" 1="stateful"
                'lan_ipv6_address': "2401:3500:133c:1341:1134:2541:13cd:1134",
                'lan_prefix_length': 64,
                'lan_ipv6_prefix': "2401:3500:133c:1341::",
                'lan_ip_pool_start': "1000",
                'lan_ip_pool_end': "2000",
                'lan_lease_time': 86400, "use_ipv6_web": True, "channel": 11, "standard": 'gnbax'}
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rdparty_sta_conn_with_11n_params_DUT_STA_with_11ax_disabled_TC557314(
        wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, wifi_client,
        sniffer_filter):

    """Verify the 3rd party STA Connectivity to 11n APUT in Concurrent mode with 11ax Paramters disabled for STAUT
    Interface to 3rd party AP"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
            capture_filename="TC557314_pcap", wifi_sniffer = wifi_sniffer, sl_collections=sl_collections,
            utf_constants= utf_constants,  wifi_client=wifi_client, testcase_no=557314, channel = 11,
            sniffer_filter=sniffer_filter, no_of_clients=1, ipv6_addr_type="link",beacon_stop=0, ssid="917_Melco_ap",
            security="WPA2", psk="12345678", ht_caps=1)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta_mode()
        ap_dut_obj.check_ping_status_ipv6()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config("wifi_access_point", wifi={'connection_type': 'STATIC_IPV6',
                'wan_ipv6_address': "2401:4900:1cb3:3444:3223:3324:1235:1bca",
                'wan_ipv6_gateway': "2401:4900:1cb3:3444::1",
                'wan_prefix_length': 64,
                'ipv6_state': "1", #0= "stateless" 1="stateful"
                'lan_ipv6_address': "2401:3500:133c:1341:1134:2541:13cd:1134",
                'lan_prefix_length': 64,
                'lan_ipv6_prefix': "2401:3500:133c:1341::",
                'lan_ip_pool_start': "1000",
                'lan_ip_pool_end': "2000",
                'lan_lease_time': 86400, "use_ipv6_web": True, "channel": 11, "standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_3rdparty_sta_reconn_with_11n_params_DUT_STA_with_11ax_disabled_tc557315(
        wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, wifi_client,
        sniffer_filter):

    """Verifyt the 3rd party STA Reconnection to 11n APUT in concurrent Mode with STAUT doing Ping to AP Backend
    Link Local Address"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
            capture_filename="TC557315_pcap", no_of_clients= 1, wifi_sniffer = wifi_sniffer,
            sl_collections=sl_collections, utf_constants= utf_constants,  wifi_client=wifi_client, testcase_no=557315,
            channel = 11,sniffer_filter=sniffer_filter, beacon_stop=0, ssid="917_Melco_ap", security="WPA2",
            psk="12345678", ht_caps=1)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta_mode()
        ap_dut_obj.check_ping_status_ipv6()
        ap_dut_obj.aput_start()
        ap_dut_obj.client_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        time.sleep(10)
        ap_dut_obj.sniffer_capture_start()
        time.sleep(10)
        ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly ,
        "features": Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config("wifi_access_point", wifi={'connection_type': 'STATIC_IPV6',
                'wan_ipv6_address': "2401:4900:1cb3:3444:3223:3324:1235:1bca",
                'wan_ipv6_gateway': "2401:4900:1cb3:3444::1",
                'wan_prefix_length': 64,
                'ipv6_state': "1", #0= "stateless" 1="stateful"
                'lan_ipv6_address': "2401:3500:133c:1341:1134:2541:13cd:1134",
                'lan_prefix_length': 64,
                'lan_ipv6_prefix': "2401:3500:133c:1341::",
                'lan_ip_pool_start': "1000",
                'lan_ip_pool_end': "2000",
                'lan_lease_time': 86400, "use_ipv6_web": True, "channel": 11, "standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "917_Melco_ap",
                "passphrase": "12345678",
                "channel": 11,
                "country": "US"
               }
         }
)
def test_wifi_sdk_check_11n_params_in_aput_beacon_in_concurrent_mode_tc557316(
        wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, wifi_client,
        sniffer_filter):

    """Verify the 11n Paramters in APUT Beacon with AP Start and Stop feature in Concurren Mode with STAUT Connection
     and Disconnection in a loop"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, wifi_clients=wifi_clients,
            capture_filename="TC557316_pcap", no_of_clients=1, wifi_sniffer = wifi_sniffer,
            sl_collections=sl_collections, utf_constants= utf_constants, wifi_client=wifi_client, testcase_no=557316,
            channel = 11,sniffer_filter=sniffer_filter, beacon_stop=0, ssid="917_Melco_ap",  security="WPA2",
            psk="12345678", ht_caps=1)

        ap_dut_obj.sniffer_capture_start()
        for count in range(2):
            if count == 0:
                ap_dut_obj.concurrent_sta_mode()
                ap_dut_obj.check_ping_status_ipv6()
                ap_dut_obj.aput_start()
                ap_dut_obj.dut_leave_ap()
            else:
                ap_dut_obj.concurrent_sta_mode()
                ap_dut_obj.client_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_check_aggregation_during_traffic_bet_two_clients_apmode_TC557310(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, sniffer_filter, net_perf_client,
        net_perf_server, protocol):

    """Verify the WLAN Aggregation while running the Data traffic between two 3rd party STA's in AP Mode"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            utf_constants=utf_constants,sniffer_filter=sniffer_filter, channel=11,
            capture_filename="TC557308_Sniffer", beacon_stop=0, ssid="917_Melco_ap", no_of_clients= 2, security="WPA2",
            psk="12345678", ht_caps=1, net_perf_client=net_perf_client, net_perf_server=net_perf_server,
            protocol=protocol)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.no_of_clients = 2
        ap_dut_obj.dut_ap_enable()
        dut_add_dict = ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        client_ip = dut_add_dict['client1_ip']
        server_ip = dut_add_dict['client2_ip']
        ap_dut_obj.run_traffic_between_two_clients(
            net_perf_server, net_perf_client, server_ip, client_ip, protocol, iperf_time=60)
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_check_data_rate_and_ping_traffic_bet_two_clients_apmode_TC557311(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, sniffer_filter, net_perf_client,
        net_perf_server, protocol):

    """Verify the 11n Data rate with Ping traffic on IPv4 and IPv6 between 3rd party STA's with 11n Parameters enabled"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            utf_constants=utf_constants,sniffer_filter=sniffer_filter, channel=11,
            capture_filename="TC557308_Sniffer", beacon_stop=0, ssid="917_Melco_ap", no_of_clients= 2, security="WPA2",
            psk="12345678", ht_caps=1, net_perf_client=net_perf_client, net_perf_server=net_perf_server,
            protocol=protocol)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.no_of_clients = 2
        ap_dut_obj.dut_ap_enable()
        ap_dut_obj.data_rate()
        dut_add_dict = ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        client_ip = dut_add_dict['client1_ip']
        server_ip = dut_add_dict['client2_ip']
        ap_dut_obj.run_traffic_between_two_clients(
            net_perf_server, net_perf_client, server_ip, client_ip, protocol, iperf_time=60)
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        ap_dut_obj.sniffer_validation()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "917_Melco_ap",
            "passphrase": "12345678",
            "channel": 11,
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={'connection_type': 'STATIC_IPV6',
                'wan_ipv6_address': "2401:4900:1cb3:3444:3223:3324:1235:1bca",
                'wan_ipv6_gateway': "2401:4900:1cb3:3444::1",
                'wan_prefix_length': 64,
                'ipv6_state': "1", #0= "stateless" 1="stateful"
                'lan_ipv6_address': "2401:3500:133c:1341:1134:2541:13cd:1134",
                'lan_prefix_length': 64,
                'lan_ipv6_prefix': "2401:3500:133c:1341::",
                'lan_ip_pool_start': "1000",
                'lan_ip_pool_end': "2000",
                'lan_lease_time': 86400, "use_ipv6_web": True, "channel": 11, "standard": 'gnbax', "security": "WPA2",
                "passphrase": "12345678"})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_check_data_rate_and_aggregation_traffic_bet_two_clients_conmode_TC557317(
        wifi_dut, wifi_sniffer, sl_collections, wifi_clients, utf_constants, sniffer_filter, net_perf_client,
        net_perf_server, protocol, wifi_access_point, wifi_client):

    """Verify the 11n Data rates and Aggregation between two 3rd party STA's in Concurrent Mode when STAUT is doing
    the Ping traffic from DUT to AP Backend Machine"""

    try:
        ap_dut_obj = AP11nParamsEnabled(
            wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            utf_constants=utf_constants,sniffer_filter=sniffer_filter, channel=11, wifi_access_point=wifi_access_point,
            capture_filename="TC557308_Sniffer", beacon_stop=0, ssid="917_Melco_ap", no_of_clients= 2, security="WPA2",
            psk="12345678", ht_caps=1, net_perf_client=net_perf_client, net_perf_server=net_perf_server,
            protocol=protocol, wifi_client=wifi_client)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.no_of_clients = 2
        ap_dut_obj.concurrent_sta_mode()
        ap_dut_obj.check_ping_status_ipv6()
        ap_dut_obj.dut_ap_enable()
        ap_dut_obj.data_rate()
        dut_add_dict = ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        client_ip = dut_add_dict['client1_ip']
        server_ip = dut_add_dict['client2_ip']
        ap_dut_obj.run_traffic_between_two_clients(
            net_perf_server, net_perf_client, server_ip, client_ip, protocol, iperf_time=60)
        ap_dut_obj.client_disconnect()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.sniffer_check()
        ap_dut_obj.sniffer_validation()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()