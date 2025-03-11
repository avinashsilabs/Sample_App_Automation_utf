import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utf_config import UtfConfig
import time, re
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. DUT(Soc917)
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


class WifiThread(ThreadBase):
    dut_addr = None

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
            region=None,
            switch=None,
            timeout=60,
            utf_constants=None,
            testcase=None,
            net_perf_client=None,
            protocol=None,
            traffic_type=None,
            ip_version="ipv4",
            wifi_clients=None,
            htcaps_enable=None,
            leave=True,
            enable_data_rate=False,
            version=4,
            ip_config_disable=False,
            tcp_ip_bypass=False,
            ipv6_addr_type="global"
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
        self.region = region
        self.switch = switch
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.timeout = timeout
        self.utf_constants = utf_constants
        self.testcase = testcase
        self.dut_addr = None
        self.host_ip = None
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.ip_version = ip_version
        self.dut_addr_dict = None
        self.wifi_clients = wifi_clients
        self.ssid = "sharma123"
        self.security = "WPA2"
        self.password = "thisistestnetwork"
        self.channel = 11
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.htcaps_enable = 1
        self.htcaps_enable = htcaps_enable
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.version = version
        self.dut_add_dict = {}
        self.static_ipv6 = None
        self.remote_ip = None
        self.ip_config_disable = ip_config_disable
        self.tcp_ip_bypass = tcp_ip_bypass
        self.ipv6_addr_type = ipv6_addr_type

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [557419, 557420, 557427, 557421, 563960]:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
                tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

            if self.test_type == 557419:
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f".... Remote device ip :{self.host_ip} ....")

            if self.test_type in [557420]:
                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                        ip_version=self.ip_version)
                assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
                self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
                self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
                logger().info(f"DUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                              f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

                self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
                logger().info(f".... Remote device link address :{self.remote_ip} ....")

    def check_ping_status_ipv6(self, ping_count=10):
        """
        Ping the given IP address.
        """
        interface = self.wifi_client.interfaces.wifi.config["interface"]
        ping_link_local_addr = f"{self.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
        status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=ping_count, retry_count=3)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def check_ping_status_ipv4(self, ping_count=10):
        self.sl_collections.ping(device_ip=self.dut_addr['device_ip'], ping_count=ping_count, retry_count=3)

    def traffic_run(self):
        if self.test_type == 557419:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.dut_addr["device_ip"], host_ip=self.host_ip, timeout=self.timeout,
                ip_version=self.version)

        if self.test_type in [557420, 557421, 557427, 563960]:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.dut_add_dict['dut_sta_ipv6_link'], host_ip=self.remote_ip, timeout=self.timeout,
                ip_version=self.version, buffer_size_tcp=1380)

    def check_sta_first_and_ap_second_ipv4(self):
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
            associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
            ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)

        self.ap_mode_with_ipv4()

    def check_ap_mode_first_and_sta_second_ipv4(self):
        self.ap_mode_with_ipv4(leave=False)
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
            associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
            ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)
        self.wifi_client_leave()

    def ap_mode_with_ipv4(self, leave=True):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel, dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)

        for i in range(0, self.no_of_clients):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
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
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
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
        if leave:
            self.wifi_client_leave()

    def static_ipv6_assign_with_fs(self):
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(
            timeout=30, ip_version=self.ip_version, static_ipv6_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            ipv6_gw_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

        logger().info(f"********* IP **********: {ip_config}")
        self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
        logger().info(f".... Remote device link address :{self.remote_ip} ....")

    def static_ipv6_assign(self):
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(
            timeout=30, ip_version=self.ip_version, static_ipv6_address='2401:3522:2231:1341::221',
            ipv6_gw_address='2401:3522:2231:1341::221')

        logger().info(f"********* IP **********: {ip_config}")
        self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
        logger().info(f".... Remote device link address :{self.remote_ip} ....")

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

    def wlan_leave(self):
        try:
            logger().info("....Leaving the WLAN network....")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name="ns_all_fs")

        logger().info(f"***** Validating neighbour solicitation messages from STAUT ******")
        snif_pkt_count = \
            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, negative_test=True)[
                'packet_count']
        assert not snif_pkt_count, "Unable to find neighbour solicitation messages in sniffer which is expected"


class ConcurrentMode:
    dut_sta_ip = None
    dut_add_dict = {}

    def __init__(self):
        self.dut_ap_ip = None
        self.clients_connected = False
        self.credentials = None
        self.default_interface = None

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        if self.clients_connected:
            logger().info(f"Disconnecting clients from DUT-AP before associating to DUT-AP")
            wifi_clients.interfaces.wifi.leave()
            self.clients_connected = False
        for i in range(0, 1):
            if not self.default_interface:
                self.default_interface = wifi_clients.interfaces.wifi.config['interface']
            wifi_clients.interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA:'{wifi_clients.name}' is joining to DUT-AP")
            wifi_clients.interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA:'{wifi_clients.name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients.name}' to DUT")
                    ip_dict[f'client_ip'] = wifi_clients.interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {ip_dict[f'client_ip']}")
                    rc, stdout, stderr = wifi_clients.interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA is disconnected from DUT-AP"
        self.clients_connected = True
        return ip_dict

    def join_to_ap(self, wifi_dut, sl_collections, ssid, passphrase, security, ping_count=30, test_case=None,
                   default_channel=False, new_channel=False, wifi_client=None):

        if test_case in [557429, 557430]:
            if default_channel:
                join_status = False
                for count in range(3):
                    try:
                        logger().info(
                            f"DUT Joining to 3rd party AP using credentials --> {ssid}:{passphrase}:{security}")
                        wifi_dut.interfaces.wifi.join(ssid=ssid, passphrase=passphrase, security=security, channel=11,
                                                      timeout=60)
                        join_status = True
                        break
                    except Exception as error:
                        logger().info(f"Joining to AP failed:{error}, retry_count...{count}")
                        time.sleep(10)
                assert join_status, "Failed to join to 3rd party AP"

            if new_channel:
                join_status = False
                for count in range(3):
                    try:
                        logger().info(
                            f"DUT Joining to 3rd party AP using credentials --> {ssid}:{passphrase}:{security}")
                        wifi_dut.interfaces.wifi.join(ssid=ssid, passphrase=passphrase, security=security, channel=6,
                                                      timeout=60)
                        join_status = True
                        break
                    except Exception as error:
                        logger().info(f"Joining to AP failed:{error}, retry_count...{count}")
                        time.sleep(10)
                assert join_status, "Failed to join to 3rd party AP"

        if test_case == 557429:
            ip_config = sl_collections.configure_ip(wifi_dut, retry_count=3, timeout=120)[-1]
            ConcurrentMode.dut_sta_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            time.sleep(5)

            logger().info("Pinging to DUT")
            status = sl_collections.ping(device_ip=ConcurrentMode.dut_sta_ip, ping_count=ping_count, retry_count=3)
            assert status, "Failed to ping to DUT"

        if test_case == 557430:
            ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1,
                                                               ip_version="ipv6")
            assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
            ConcurrentMode.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
            ConcurrentMode.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
            logger().info(f"\nDUT IPV6 GLOBAL ADDRESS : {ConcurrentMode.dut_add_dict['dut_sta_ipv6_global']}\n"
                          f"DUT IPV6 LINK LOCAL ADDRESS : {ConcurrentMode.dut_add_dict['dut_sta_ipv6_link']}\n")

            ping_link_local_addr = f"{ConcurrentMode.dut_add_dict['dut_sta_ipv6_link']}%{self.default_interface}"
            status = sl_collections.ping(device_ip=ping_link_local_addr, ping_count=ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            wifi_client.interfaces.wifi.config['interface'] = self.default_interface

    def http_server_provisioning(
            self, sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=None, user_channel=None):

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, psk=psk,
                                          channel=ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        dut_as_ap_ip = self.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        self.credentials = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert self.credentials, "Unable to fetch 3rd party AP details from DUT"
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        time.sleep(5)

        if user_channel:
            self.join_to_ap(wifi_dut, sl_collections, self.credentials[1], self.credentials[2],
                            self.credentials[3].lower(), test_case=test_case, default_channel=True, wifi_client=wifi_client)
        else:
            self.join_to_ap(wifi_dut, sl_collections, self.credentials[1], self.credentials[2],
                            self.credentials[3].lower(), test_case=test_case, new_channel=True, wifi_client=wifi_client)

        wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(
            ssid=ssid, security=security, psk=psk, channel=channel, dtim_beacon_count="1", beacon_interval="100")
        wifi_dut.interfaces.wifi.get_channel_info(interface="ap")

        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        dut_as_ap_ip = self.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        return dut_as_ap_ip


class AccessDUTAPage(ThreadBase):
    def __init__(self, http_client, dut_as_ap_ip):
        self.http_client = http_client
        self.dut_as_ap_ip = dut_as_ap_ip

    def run(self):
        for i in range(4):
            url = f'http://{self.dut_as_ap_ip}/login'
            result = self.http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_sta_interface_c557419(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only IPv4 Assignment to STAUT interfaces in STAUT in concurrent Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', test_type=557419)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.check_ping_status_ipv4(ping_count=60)
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

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
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123",
                          "ipv6_state": "1"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv6_assign_sta_interface_c557420(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only Stateful DHCPv6 IPv6 assignment to STATUT interface in concurrent Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, tcp_ip_bypass=True,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557420, version=6)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.check_ping_status_ipv6(ping_count=60)
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

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
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "ipv6_state": "1",
                          "connection_type": "disabled", "use_ipv6_web": True})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_static_ipv6_assign_sta_interface_c557421(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only static IPv6 assignment to STATUT interface in STAUT Alone Mode (Disable IPv6 on 3rd party AP)"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, tcp_ip_bypass=True,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557421, version=6)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.static_ipv6_assign()
        wifi_obj.check_ping_status_ipv6(ping_count=60)
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

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
        "coex_mode": Si91xCoexMode.WLANOnly,
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
            "channel": 11,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_sta_first_c557424(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the Ping functionality of AP and STA in when Assigned with IPv4 address alone in Concurrent Mode
    (STA_First)"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557424)

        wifi_obj.check_sta_first_and_ap_second_ipv4()
        wifi_obj.check_ping_status_ipv4(ping_count=60)
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
        "coex_mode": Si91xCoexMode.WLANOnly,
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
            "channel": 11,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_apmode_first_c557425(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the Ping functionality of AP and STA in IPv4 address alone in Concurrent Mode (AP_First)"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557425)

        wifi_obj.check_ap_mode_first_and_sta_second_ipv4()
        wifi_obj.check_ping_status_ipv4(ping_count=60)
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
        "coex_mode": Si91xCoexMode.WLANOnly,
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
            "channel": "11",
        },
    }
)
def test_wifi_sdk_ipv4_assign_apmode_interface_c557422(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify only IPv4 Assignment to APUT interface in APUT alone Mode"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557422)

        wifi_obj.ap_mode_with_ipv4()
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
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client,
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
            "channel": 11,
        },
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "123456789", "ssid": "sharma1234", "ipv6_state": "0",
                          "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv6_stamode_ipv4_apmode_c557427(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol, wifi_clients):
    """Verify the Ping functionality of AP in IPv4 and STAUT in Static IPv6 in concurrent Mode(STA First)"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, tcp_ip_bypass=True,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557427, version=6,
                              wifi_clients=wifi_clients)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.static_ipv6_assign()
        wifi_obj.check_ping_status_ipv6(ping_count=60)
        wifi_obj.ap_mode_with_ipv4(leave=False)
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()
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
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "123456789", "ssid": "sharma1234", "ipv6_state": "0"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_static_ipv6_assign_sta_interface_with_fs_c563960(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Check the ICMPv6 NS Messages when the STA Static IPv6 address is configured with all f's"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, test_type=563960,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client, version=6,
                              tcp_ip_bypass=True, ip_config_disable=False, traffic_type='TX', ip_version='ipv6')

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.static_ipv6_assign_with_fs()
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()
        wifi_obj.sniffer_validation()

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
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
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
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
def test_melco_sdk_ipv4_assign_stamode_and_channel_change_c557429(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check the IPv4 assignment to STAUT interface in Melco Home AP Channel Change scenarios
    """
    try:
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557429, user_channel=True)

        logger().info("changing to new STA channel")
        wifi_access_point.interfaces.wifi.start_ap(channel=ap_channel)
        time.sleep(30)
        sw = Stopwatch()
        end_time = 120
        logger().info("waiting for disconnect event from DUT STA")
        rejoin_failed = False
        while sw.elapsed_sec < end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_failed = True
                    break
            if rejoin_failed:
                logger().info("Rejoin failed event received from DUT STA")
                break
        assert rejoin_failed, "Rejoin failed event not received from DUT STA"
        logger().info("DUT STA disconnected from 3rd party AP")
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        logger().info("Scanning all channels")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557429, user_channel=False)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
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
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
def test_melco_sdk_ipv6_assign_stamode_and_channel_change_c557430(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check the IPv6 assignment to STAUT interface in Melco Home AP Channel Change scenarios
    """
    try:
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557430, user_channel=True)

        logger().info("changing to new STA channel")
        wifi_access_point.interfaces.wifi.start_ap(channel=ap_channel)
        time.sleep(30)
        sw = Stopwatch()
        end_time = 120
        logger().info("waiting for disconnect event from DUT STA")
        rejoin_failed = False
        while sw.elapsed_sec < end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_failed = True
                    break
            if rejoin_failed:
                logger().info("Rejoin failed event received from DUT STA")
                break
        assert rejoin_failed, "Rejoin failed event not received from DUT STA"
        logger().info("DUT STA disconnected from 3rd party AP")
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        logger().info("Scanning all channels")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557430, user_channel=False)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
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
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 11,
    }
)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
def test_melco_sdk_ipv4_assign_stamode_and_psk_change_c557431(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check the IPv4 assignment to STAUT interface in Melco Home AP PSK Change scenarios
    """
    try:
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557429, user_channel=True)

        logger().info("changing to new PSK")
        wifi_access_point.interfaces.wifi.start_ap(passphrase="fdfeywerwhkhgskd")
        time.sleep(30)
        sw = Stopwatch()
        end_time = 120
        logger().info("waiting for disconnect event from DUT STA")
        rejoin_failed = False
        while sw.elapsed_sec < end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_failed = True
                    break
            if rejoin_failed:
                logger().info("Rejoin failed event received from DUT STA")
                break
        assert rejoin_failed, "Rejoin failed event not received from DUT STA"
        logger().info("DUT STA disconnected from 3rd party AP")
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        logger().info("Scanning all channels")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        wifi_dut.interfaces.wifi.join(ssid=con_obj.credentials[1], passphrase=con_obj.credentials[2],
                                      security=con_obj.credentials[3].lower(),
                                      timeout=60, expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("*** error 0x10008 SL_STATUS_SI91X_DEAUTHENTICATION is expected ****")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557429, user_channel=True)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
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
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 11,
    }
)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
def test_melco_sdk_ipv6_assign_stamode_and_psk_change_c557432(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check the IPv6 assignment to STAUT interface in Melco Home AP PSK Change scenarios
    """
    try:
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557430, user_channel=True)

        logger().info("changing to new PSK")
        wifi_access_point.interfaces.wifi.start_ap(passphrase="fdfeywerwhkhgskd")
        time.sleep(30)
        sw = Stopwatch()
        end_time = 120
        logger().info("waiting for disconnect event from DUT STA")
        rejoin_failed = False
        while sw.elapsed_sec < end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_failed = True
                    break
            if rejoin_failed:
                logger().info("Rejoin failed event received from DUT STA")
                break
        assert rejoin_failed, "Rejoin failed event not received from DUT STA"
        logger().info("DUT STA disconnected from 3rd party AP")
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        logger().info("Scanning all channels")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        wifi_dut.interfaces.wifi.join(ssid=con_obj.credentials[1], passphrase=con_obj.credentials[2],
                                      security=con_obj.credentials[3].lower(),
                                      timeout=60, expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("*** error 0x10008 SL_STATUS_SI91X_DEAUTHENTICATION is expected ****")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123", test_case=557430, user_channel=True)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
