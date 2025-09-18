import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap, Si91xWebSocketParms
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utf_config import UtfConfig
import time
import re
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils import print_dict
from typing import Union
import random, string

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

def text_generator(size=1000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


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
            wiseconnect_web=None,
            ws_handler=None,
            http_server=None

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
        self.ws_handler = ws_handler
        self.http_server = http_server

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [148566, 148567, 148568]:
            WifiThread.dut_add_dict = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
                tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            self.ws_handler = WebsocketEventHandler()
            self.http_server.interfaces.http.set_fn_on_websocket_client_connected(
                self.ws_handler.on_ws_client_connected)
            self.http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
                self.ws_handler.on_ws_client_disconnected)
            self.http_server.interfaces.http.set_fn_on_websocket_message_received(
                self.ws_handler.on_ws_message_received)

            logger().info(f"DUT MAC ADDRESS :  {WifiThread.dut_add_dict['dut_mac_address']}\n"
                          f"DUT IPV4 ADDRESS : {WifiThread.dut_add_dict['device_ip']}")

            self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=4, addr_type="global")
            logger().info(f".... Remote device link address :{self.remote_ip} ....")

    def ap_mode_with_ipv4(self, scan_ssid=0):
        if self.test_type in [148566, 148567, 148568]:
            ping_count = self.utf_constants.get("ping_count")
            self.wifi_dut.interfaces.wifi.start_ip(
                static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
                ip_version='ipv4')
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                                   channel=self.channel, dtim_beacon_count=self.dtim_count,
                                                   beacon_interval=self.beacon_interval, beacon_stop=self.beacon_stop)

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
                        logger().info(
                            f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
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

    def websocket_functionality(self):
        host_name = "example.com"
        resource_name = "/websocket"

        if self.test_type in [148566]:
            self.wifi_dut.interfaces.wifi.websocket_init(
                self.http_server.interfaces.http, host_name, resource_name, 80, 5001)
        if self.test_type in [148567, 148568]:
            self.wifi_dut.interfaces.wifi.websocket_init(
                self.http_server.interfaces.http, host_name, resource_name, 443, 5001, enable_tls=1)

        self.wifi_dut.interfaces.wifi.websocket_connect()
        time.sleep(0.1)

        assert self.ws_handler.client_connected

        if self.test_type in [148568]:
            data = text_generator(size=1362)
            address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
            self.wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)

            self.wifi_dut.interfaces.wifi.websocket_send(
                opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                higher_data_len=1, address=address)
            self.wifi_dut.interfaces.wifi.memory_free(address)
            time.sleep(2)

        if self.test_type in [148566, 148567]:
            self.wifi_dut.interfaces.wifi.websocket_send(
                opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                higher_data_len=0)

        time.sleep(2)
        logger().info(f"data received on websocket server ->{self.ws_handler.message_received}")

        self.wifi_dut.interfaces.wifi.websocket_close()
        self.wifi_dut.interfaces.wifi.websocket_deinit()

    def connection_leave(self):
        logger().info("....Leaving AP from DUT....")
        self.wifi_dut.interfaces.wifi.leave()

    def ap_mode_conn_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()


class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        # logger().info(f"what is the message getting received 1 ")
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        # logger().info(f"what is the message getting received 2")
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


def wifi_dut_marker(ext_custom_bit=0, thread_count=1, tcp_feat_bit=0, ext_tcp_feat_bit=0, feat_bit=0, ca_cert=None,
                    client_cert=None, client_key=None):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | feat_bit,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | tcp_feat_bit,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | ext_tcp_feat_bit,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert
    if client_key:
        config["client_key"] = client_key
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_websocket_default_buffer_size_c148566(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, http_server):
    """Websocket with default buffer size in concurrent Mode"""

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
                              http_server=http_server, test_type=148566)

        wifi_obj.no_of_clients = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.websocket_functionality()
        wifi_obj.ap_mode_conn_leave()
        wifi_obj.connection_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_websocket_ssl_default_buffer_size_c148567(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, http_server):
    """Websocket over SSL with default buffer size"""

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
                              http_server=http_server, test_type=148567)

        wifi_obj.no_of_clients = 2
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.websocket_functionality()
        wifi_obj.ap_mode_conn_leave()
        wifi_obj.connection_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_websocket_ssl_max_buffer_size_c148568(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients, http_server):
    """Websocket over SSL with MAX buffer size"""

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
                              http_server=http_server, test_type=148568)

        wifi_obj.no_of_clients = 2
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.websocket_functionality()
        wifi_obj.ap_mode_conn_leave()
        wifi_obj.connection_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
