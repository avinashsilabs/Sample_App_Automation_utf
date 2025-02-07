import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utf_config import UtfConfig
import time
import re
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils import print_dict


webpage = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" 
content="width=device-width, initial-scale=1.0"><title>Login Page</title><style>body {font-family: Arial, 
sans-serif;margin: 0;padding: 0;display: flex;justify-content: center;align-items: center;height: 
100vh;background-color: #f0f0f0;}#connect-form {text-align: center;padding: 20px;border: 1px solid 
#ccc;border-radius: 8px;background-color: #fff;}input[type="text"],input[type="password"] {width: 100%;padding: 
10px;margin: 10px 0;border-radius: 5px;border: 1px solid #ccc;box-sizing: border-box;}input[type="submit"] {width: 
100%;padding: 10px;margin: 10px 0;border: none;border-radius: 5px;background-color: #007bff;color: #fff;cursor: 
pointer;}input[type="submit"]:hover {background-color: #0056b3;}#heading {margin-bottom: 20px;width: 100%;}select[
name="security-type"] {width: 100%;padding: 10px;margin: 10px 0;border-radius: 5px;border: 1px solid #ccc;box-sizing: 
border-box;}.form-row {display: flex;justify-content: space-between;align-items: center;margin: 10px 0;}.form-row 
label {width: 100px;text-align: right;margin-right: 10px;white-space: nowrap;}.form-row input,.form-row select {flex: 
2;}</style></head><body><div id="connect-form"><h3 id="heading">Silicon Labs</h3><form id="connect-form" 
action="/connect" method="post"><div class="form-row"><label for="ssid">SSID:</label><input type="text" id="ssid" 
name="ssid" placeholder="SSID" required></div><div class="form-row"><label for="password">Password:</label><input 
type="text" id="password" name="password" placeholder="Password" required></div><div class="form-row"><label 
for="security-type">Security Type:</label><select id="security-type" name="security-type"><option 
value="WPA">WPA</option><option value="WPA2">WPA2</option><option value="WPA3">WPA3</option><option value="Mixed 
Mode">Mixed Mode</option></select></div><input type="submit" 
value="Connect"></form></div><script>document.getElementById('connect-form').addEventListener('submit', 
function (event) {event.preventDefault();var xhr = new XMLHttpRequest();xhr.open('POST', '/connect', 
true);xhr.setRequestHeader('Content-Type', 'application/json');var id = document.getElementsByName('ssid')[
0].value;var password = document.getElementsByName('password')[0].value;var securityType = document.getElementById(
'security-type').value;console.log('SSID: ' + id);console.log('Password: ' + password);console.log('Security Type: ' 
+ securityType);var data = {id: id,password: password,securityType: securityType};xhr.send(JSON.stringify(
data));});</script></body></html>'''

def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. soc
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Test Steps:

        1. Configure the DUT in STA/AP mode and connect to the specified AP.
        2. Association of Third party AP's
        3. Configure the IPv4/IPv6 addresses.
        4. Ping to the specified IPv4/IPv6 address.
        5. Validate the Sniffer Checks.

     Author: 
      - Saurabh Sharma 
"""


class WifiThread(ThreadBase):
    dut_add_dict = {}
    ip_dict = {}
    default_interface = None

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            switch=None,
            utf_constants=None,
            testcase=None,
            net_perf_client=None,
            protocol=None,
            traffic_type=None,
            ip_version="ipv4",
            wifi_clients=None,
            leave=False,
            enable_data_rate=False,
            version=4,
            ip_config_disable=False,
            tcp_ip_bypass=False,
            ping_type=None,
            net_perf_server=None,
            timeout=60,
            http_client=None,
            wiseconnect_web=None

    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.switch = switch
        self.utf_constants = utf_constants
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.ip_version = ip_version
        self.wifi_clients = wifi_clients
        self.ssid = "sharma123"
        self.security = "WPA2"
        self.password = "thisistestnetwork"
        self.channel = 8
        self.dtim_count = 3
        self.beacon_interval = 100
        self.beacon_stop = 0
        self.no_of_clients = 1
        self.htcaps_enable = 1
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.version = version
        self.ping_type = ping_type
        self.remote_ip = None
        self.ip_config_disable = ip_config_disable
        self.tcp_ip_bypass = tcp_ip_bypass
        self.net_perf_server = net_perf_server
        self.timeout = timeout
        self.http_client = http_client
        self.wiseconnect_web = wiseconnect_web

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [690736, 690737, 700498, 693699, 693678, 693702, 693700, 693695]:
            WifiThread.dut_add_dict = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
                tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

            ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                    ip_version="ipv6")
            assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
            WifiThread.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
            WifiThread.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]

            logger().info(f"DUT MAC ADDRESS :  {WifiThread.dut_add_dict['dut_mac_address']}\n"
                          f"DUT IPV4 ADDRESS : {WifiThread.dut_add_dict['device_ip']}\nDUT IPV6 GLOBAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_global']}\n"
                          f"DUT IPV6 LINK LOCAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_link']}\n")

            self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
            logger().info(f".... Remote device link address :{self.remote_ip} ....")

        if self.test_type == 693672:
            self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                               expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)

    def ap_mode_with_ipv4(self, scan_ssid=0):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel, dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval, beacon_stop=self.beacon_stop)
        if self.test_type in [690737, 693700]:
            logger().info(".... stop the sniffer ....")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.check_no_beacon()
            logger().info("... configuring the Sniffer with the channel ...")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture()

        if self.test_type in [693695]:
            self.http_server_function()

        self.wifi_dut.interfaces.wifi.get_channel_info(interface='ap')
        for i in range(0, self.no_of_clients):
            connected = False
            WifiThread.default_interface = self.wifi_clients[i].interfaces.wifi.config['interface']
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=scan_ssid)
            time.sleep(5)
            WifiThread.ip_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {WifiThread.ip_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    WifiThread.ip_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {WifiThread.ip_dict['rasp_mac_address']}")
                    WifiThread.ip_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {WifiThread.ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {WifiThread.ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return WifiThread.ip_dict

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

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

    def traffic_run(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
            device_ip=WifiThread.dut_add_dict['dut_sta_ipv6_link'], host_ip=self.remote_ip, timeout=self.timeout,
            ip_version=self.version, buffer_size_tcp=1380)

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

    def raspi_client_leave(self):
        self.wifi_dut.interfaces.wifi.disconnect_ap_client(
            client_mac=WifiThread.ip_dict['rasp_mac_address'], deauth_option="deauth_client_unspecified")

    def check_no_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating no beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2, negative_test=True)['packet_count']
        assert not snif_pkt_count, "found beacon packet in sniffer"

    def check_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "No beacon found in sniffer"



    def sniffer_validation(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        if self.test_type in [690734, 690736, 690737]:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac_address, filter_name="deauthentication")

            logger().info(f"***** Validating de-authentication packet ******")
            snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
            assert snif_pkt_count, "Unable to find de-authentication packet in sniffer"

        if self.test_type == 693697:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                da_addr=dut_mac_address, filter_name="disassociation")

            logger().info(f"***** Validating disassociation packet ******")
            snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
            assert snif_pkt_count, "Unable to find disassociation packet in sniffer"

    def static_ipv6_assign_with_fs(self):
        WifiThread.dut_add_dict = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
            associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
            ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
            tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

        ip_config = self.wifi_dut.interfaces.wifi.start_ip(
            timeout=30, ip_version=self.ip_version, static_ipv6_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            ipv6_gw_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

        assert ip_config, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        WifiThread.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
        WifiThread.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]

        logger().info(f"DUT IPV6 GLOBAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_global']}\n"
                      f"DUT IPV6 LINK LOCAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_link']}\n")

    def http_server_function(self):
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()

    def http_server_access_webpage(self):
        url = f"http://{WifiThread.ip_dict['dut_ip']}/login"
        result = self.http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

    def http_server_deinit_stop(self):
        self.wifi_dut.interfaces.wifi.http_server_deinit()
        self.wifi_dut.interfaces.wifi.http_server_stop()



class ping(WifiThread):

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            utf_constants=None,
            wifi_clients=None,
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.utf_constants = utf_constants
        self.wifi_clients = wifi_clients

    def run(self):

        """ Ping the given IP address """
        if self.test_type == 690736:
            ping_global_local_addr = f"{WifiThread.dut_add_dict['dut_sta_ipv6_global']}"
            logger().info(f".... Pinging the Global Address {ping_global_local_addr} ....")
            status = self.sl_collections.ping(device_ip=ping_global_local_addr, ping_count=self.ping_count,
                                              retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type in [690737, 700498, 693699, 693678, 693702, 693695]:
            ping_link_local_addr = f"{WifiThread.dut_add_dict['dut_sta_ipv6_link']}%{WifiThread.default_interface}"
            status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=self.ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            self.wifi_client.interfaces.wifi.config['interface'] = WifiThread.default_interface

class wifi_leave(ThreadBase):

    def __init__(
            self,
            wifi_dut=None
    ):
        super().__init__()
        # Define all the parameters
        self.wifi_dut = wifi_dut

    def run(self):
        logger().info("....Leaving AP from DUT....")
        self.wifi_dut.interfaces.wifi.leave()


class iperf_udp_tx(WifiThread):
    def __init__(self, wifi_dut=None, net_perf_client=None, wifi_client=None, protocol=None, wifi_access_point=None,
                 wifi_sniffer=None, sl_collections=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter

    def run(self):
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
        logger().info(f".... Remote device link address :{remote_ip} ....")

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
            device_ip=WifiThread.dut_add_dict['dut_sta_ipv6_link'], host_ip=remote_ip, timeout=60, traffic_type="TX",
            buffer_size_tcp=1380, buffer_size_udp=1380, ip_version=6)

class iperf_udp_rx(WifiThread):
    def __init__(self, wifi_dut=None, net_perf_client=None, wifi_client=None, protocol=None, wifi_access_point=None,
                 wifi_sniffer=None, sl_collections=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter


    def run(self):
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
        logger().info(f".... Remote device link address :{remote_ip} ....")

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
            device_ip=WifiThread.dut_add_dict['dut_sta_ipv6_link'], host_ip=remote_ip, timeout=60, traffic_type="RX",
            buffer_size_tcp=1380, buffer_size_udp=1380, ip_version=6)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_interface_c690734(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Disconnect the 3rd party STA From APUT in AP Alone Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690734)

        wifi_obj.beacon_stop = 1
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.raspi_client_leave()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.HiddenSSID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_check_ssid_parameter_after_disconn_from_apmode_c690735(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Check SSID Parameter in Beacons after disconnecting the 3rd party STA from APUT with Hidden SSID Parameter is
    enabled in opermode"""

    try:
        packet_filter2 = "IEEE 802.11 Wireless Management"
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690735)

        wifi_obj.ap_mode_with_ipv4(scan_ssid=1)
        wifi_obj.wifi_client_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter1 = f'(wlan.addr == {dut_mac_address} and wlan.ssid == "") && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1, packet_filter2=packet_filter2), "not found beacon from DUT "

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        hidden_ssid_check = re.findall(r"(Tag:\s*SSID\s+parameter\s+set: \s*.*)", content)
        logger().info(f"Hidden SSID Check: {hidden_ssid_check}")
        hidden_ssid = 0
        if 'Tag: SSID parameter set: Wildcard SSID' in hidden_ssid_check:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid, "Hidden SSID not found in sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_pinging_stamode_c690736(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """In Concurrent Mode, Disconnect the 3rd party STA connected to AP When STAUT is pinging from 3rd party AP
    Backend machine"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690736)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=690736)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(10)
        wifi_obj.raspi_client_leave()
        ping_obj.wait_for_exit()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_pinging_stamode_c690737(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """In Concurrent Mode, Check beacon stop after disconnecting the 3rd party STA From APUT while pinging the STAUT
    from AP Backend machine."""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690737)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=690737)

        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        ping_obj.start()
        time.sleep(10)
        wifi_obj.raspi_client_leave()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        ping_obj.wait_for_exit()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture()

        wifi_obj.check_no_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_sta_with_wpa3_c700498(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the 3rd party STA Disconnection to APUT when the STA is connected with 3rd party AP with WPA3 Security"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=700498)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=700498)
        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(5)
        wifi_obj.raspi_client_leave()
        ping_obj.wait_for_exit()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_interface_c693697(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Disconnect the 3rd party STA From APUT in AP Alone Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=693697)

        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.wifi_client_leave()
        time.sleep(10)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_sta_from_aput_when_pinging_stamode_link_addr_c693699(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """In Concurrent Mode, Disconnect the 3rd party STA connected to AP When STAUT is pinging from 3rd party
    AP Backend machine"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=693699)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=693699)

        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(10)
        wifi_obj.raspi_client_leave()
        ping_obj.wait_for_exit()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
        1: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_stamode_when_runn_traffic_between_connected_apmode_clients_c693678(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, net_perf_client, net_perf_server, protocol):
    """In Concurrent Mode, Disconnect the STA from 3rd party AP while doing the Data traffic between 3rd party STA
    Connected to APUT"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=693678,
                              net_perf_client=net_perf_client, net_perf_server=net_perf_server, protocol=protocol)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=693678)

        wifi_leave_obj = wifi_leave(wifi_dut=wifi_dut)

        wifi_obj.no_of_clients = 2
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ip_dict = wifi_obj.ap_mode_with_ipv4()
        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']
        ping_obj.start()
        ping_obj.wait_for_exit()
        wifi_obj.run_traffic_between_two_clients(
            net_perf_server, net_perf_client, server_ip, client_ip, protocol, iperf_time=60)
        time.sleep(15)
        wifi_leave_obj.start()
        wifi_leave_obj.wait_for_exit()
        wifi_obj.wifi_client_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
def test_wifi_sdk_staut_and_aput_conn_diss_c693702(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """long test runs for STA connect/disconnect and AP connect/disconnect with clients"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=693702)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=693702)

        wifi_leave_obj = wifi_leave(wifi_dut=wifi_dut)
        wifi_obj.beacon_stop = 1
        for count in range(3):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.ap_mode_with_ipv4()
            ping_obj.start()
            ping_obj.wait_for_exit()
            wifi_leave_obj.start()
            wifi_leave_obj.wait_for_exit()
            wifi_obj.raspi_client_leave()
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_pinging_stamode_c693700(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, net_perf_client, protocol):
    """In Concurrent Mode, Check beacon stop after disconnecting the 3rd party STA From APUT while pinging the STAUT
    from AP Backend machine."""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', version=6,
                              protocol=protocol, net_perf_client=net_perf_client, test_type=693700)

        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        wifi_obj.traffic_run()
        wifi_obj.raspi_client_leave()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()


        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture()

        wifi_obj.check_no_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip(reason="Need to check de-init API")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_check_ping_during_http_server_deinit_c693695(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, http_client, wiseconnect_web):
    """In concurrent Mode while doing ping from 3rd party AP Backend Machine DUT, Check whether HTTP Server is able to
    Initialize after successful de-init"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4',
                              http_client=http_client, wiseconnect_web=wiseconnect_web, test_type=693695)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=693695)

        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        for count in range(1):
            wifi_obj.ap_mode_with_ipv4()
            ping_obj.start()
            wifi_obj.http_server_access_webpage()
            ping_obj.wait_for_exit()
            wifi_obj.http_server_deinit_stop()
            wifi_dut.interfaces.wifi.sl_net_deinit(mode='ap')
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip(reason="IPERF UDP Rx is failing with timeout issues")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 3, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "8",
        },
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_during_udp_tx_rx_c693540(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, net_perf_client, protocol):
    """In Concurrent Mode, Check the 3rd party STA Connect and disconnect to APUT during UDP Tx and Rx using Melco
    Application"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv6', version=6,
                              protocol=protocol, net_perf_client=net_perf_client, tcp_ip_bypass=True, test_type=693540)
        iut = iperf_udp_tx(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            sniffer_filter=sniffer_filter)
        iux = iperf_udp_rx(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
            sniffer_filter=sniffer_filter)

        wifi_obj.beacon_stop = 1
        wifi_obj.static_ipv6_assign_with_fs()
        iut.start()
        iut.wait_for_exit()
        iux.start()
        iux.wait_for_exit()
        for count in range(2):
            wifi_obj.ap_mode_with_ipv4()
            wifi_obj.raspi_client_leave()
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip(reason="The below test case requires shield box or shield room setup")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
def test_wifi_sdk_scan_with_no_ap_present_c693672(
        wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, wifi_client):
    """Scan in STA Mode with No AP Presented"""

    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              wifi_client=wifi_client, sl_collections=sl_collections, test_type=693672)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_access_point.interfaces.wifi.start_ap()