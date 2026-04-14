import re
import time
import random
import string
from random import randint
import pytest as pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xMqttQos,
    Si91xModuleType,
    Si91xJoinFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Si91xInterface,
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.interfaces.iperf.iperf_constants import IperfConstants
import ipaddress
import random
from test_melco_ipv6_ipv4_sdk import WLanConThread


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
    Author: Swathi.Chinthala
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


def logger():
    return get_logger(__name__)



def random_ipv6_addr(subnet):
    network = ipaddress.ip_network(subnet)
    max_value = int(network.network_address) + network.num_addresses - 1
    random_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), max_value))
    return str(random_ip)




class AccessDUTAPage(ThreadBase):
    def __init__(self, http_client, dut_as_ap_ip, count=5):
        self.http_client = http_client
        self.dut_as_ap_ip = dut_as_ap_ip
        self.count = count

    def run(self):
        for i in range(self.count):
            url = f'http://{self.dut_as_ap_ip}/login'
            result = self.http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")



class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4, async_socket=0, bandwidth="60M",
                 addr_type="global", link_interface=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip
        self.async_socket = async_socket
        self.bandwidth = bandwidth
        self.addr_type = addr_type
        self.link_interface = link_interface


    def run_traffic(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=self.async_socket,
            bandwidth=self.bandwidth,
            ipv6_addr_type=self.addr_type,
            link_interface=self.link_interface
        )

    def run(self):
        self.run_traffic()



class ConcurrentMode:
    def __init__(self):
        self.dut_ap_ip = None
        self.clients_connected = False
        self.ip_dict = {}

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        self.ip_dict = {}
        connected = False
        if self.clients_connected:
            logger().info(f"Disconnecting clients from DUT-AP before associating to DUT-AP")
            for client in wifi_clients:
                client.interfaces.wifi.leave()
            self.clients_connected = False
        for i in range(len(wifi_clients)):
            wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                self.ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                self.ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {self.ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    self.ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {self.ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {self.ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        self.clients_connected = True
        return self.ip_dict


    def join_to_ap(self, wifi_dut, sl_collections, ssid, passphrase, security, ping_count=30):

        join_status = False
        for count in range(3):
            try:
                logger().info(f"DUT Joining to 3rd party AP using credentials --> {ssid}:{passphrase}:{security}")
                wifi_dut.interfaces.wifi.join(ssid=ssid, passphrase=passphrase, security=security,
                                              timeout=60)
                join_status = True
                break
            except Exception as error:
                logger().info(f"Joining to AP failed:{error}, retry_count...{count}")
                time.sleep(10)
        assert join_status, "Failed to join to 3rd party AP"
        ip_config = sl_collections.configure_ip(wifi_dut, retry_count=3, timeout=120)[-1]
        self.dut_sta_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(5)
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version="ipv6")
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        self.dut_sta_ipv6_global = ip_config[1]
        self.dut_sta_ipv6_link = ip_config[0]
        logger().info("Pinging to DUT")
        status = sl_collections.ping(device_ip=self.dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"
        return self.dut_sta_ip

    def enable_aput(self, sl_collections, wifi_dut, ssid, security, psk, ap_channel):

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, psk=psk,
                                          channel=ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")

    def http_server_provisioning(self, sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                 webpage, ap_channel, wifi_access_point, ssid="TEST_C557337",
                                 security="WPA2", psk="Automation@123"):
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
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.http_server_deinit()
        # wifi_dut.interfaces.wifi.stop_ap()
        # logger().info("Initialising DUT after the reset....")
        # wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        # wifi_dut.interfaces.wifi.init()
        # wifi_dut.interfaces.wifi.initialize_thread()
        # wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        time.sleep(5)
        dut_sta_ip = self.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, psk=psk,
                                          channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        dut_as_ap_ip = self.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        return dut_sta_ip, dut_as_ap_ip


class SocketSendData(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, sock):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.sock = sock

    def run(self):
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_data = "a".join(random.choices(string.ascii_uppercase + string.digits, k=90))
            logger().info(f"TCP_RX - Remote peer sending data --> {tx_data}")
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.remote_socket.interfaces.socket.send_data_tcp(tx_data, True)
            time.sleep(1)
            rx_data = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=self.sock, timeout=60)
            assert tx_data == rx_data, (f"buffer length sent by remote peer and received on the "
                                        f"socket id {self.sock} opened in the DUT is not matched")
            logger().info("Data sent by remote peer and received at DUT is matching\n")



def wifi_dut_marker(ext_custom_bit=0, thread_count=1, tcp_feat_bit=0, ext_tcp_feat_bit=0,
                    feat_bit=0, ca_cert=None, stack_len=4096):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": stack_len, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | feat_bit,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | tcp_feat_bit,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | ext_tcp_feat_bit,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)



@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557337",
        "passphrase": "Automation@123",
        "channel": 6,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4860")
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
@pytest.mark.test_src_map_id('C689863')
def test_melco_sdk_APUT_chanel_change_1_6_US_C689863(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                     wifi_sniffer, sniffer_filter, wifi_access_point,
                                                     request):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        # change the supported channels to 1-6 in US domain in AP mode raised testagent jira for support WIFI_BT_UTFHELP-4860

        con_obj.enable_aput(sl_collections, wifi_dut, ssid="TEST_689863",
                            security="WPA2", psk="Automation@123", ap_channel=0)

        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        assert int(channel) <= 6, "AP should start in channel 1-6"

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.\
            get_sniffer_filter(wlan_addr=dut_ap_mac_address,
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557337",
        "passphrase": "Automation@123",
        "channel": 6,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4860")
@pytest.mark.test_src_map_id('C689864')
def test_melco_sdk_APUT_chanel_change_1_13_JP_C689864(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                     wifi_sniffer, sniffer_filter, wifi_access_point,
                                                     request):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        # change the supported channels to 1-3 in JP domain in AP mode raised testagent jira for support WIFI_BT_UTFHELP-4860

        con_obj.enable_aput(sl_collections, wifi_dut, ssid="TEST_689864",
                            security="WPA2", psk="Automation@123", ap_channel=0)

        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        assert int(channel) <= 6, "AP should start in channel 1-13"

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.\
            get_sniffer_filter(wlan_addr=dut_ap_mac_address,
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557337",
        "passphrase": "Automation@123",
        "channel": 6,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4860")
@pytest.mark.test_src_map_id('C689865')
def test_melco_sdk_APUT_chanel_change_1_6_US_Con_C689865(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                     wifi_sniffer, sniffer_filter, wifi_access_point,
                                                     request):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        # change the supported channels to 1-3 in JP domain in AP mode raised testagent jira for support WIFI_BT_UTFHELP-4860

        con_obj.enable_aput(sl_collections, wifi_dut, ssid="TEST_689865",
                            security="WPA2", psk="Automation@123", ap_channel=0)

        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        assert int(channel) <= 6, "AP should start in channel 1-6"

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.\
            get_sniffer_filter(wlan_addr=dut_ap_mac_address,
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557337",
        "passphrase": "Automation@123",
        "channel": 6,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4860")
@pytest.mark.test_src_map_id('TC3808775170')
def test_melco_sdk_APUT_chanel_change_1_13_JP_C689866_Con(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                     wifi_sniffer, sniffer_filter, wifi_access_point,
                                                     request):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        # change the supported channels to 1-3 in JP domain in AP mode raised testagent jira for support WIFI_BT_UTFHELP-4860

        con_obj.enable_aput(sl_collections, wifi_dut, ssid="TEST_689866",
                            security="WPA2", psk="Automation@123", ap_channel=0)

        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        assert int(channel) <= 6, "AP should start in channel 1-13"

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.\
            get_sniffer_filter(wlan_addr=dut_ap_mac_address,
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557337",
        "passphrase": "Automation@123",
        "channel": 6,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4860")
@pytest.mark.test_src_map_id('C693703')
def test_melco_sdk_APUT_14_chanel_limit_1_13_JP_C693703(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                     wifi_sniffer, sniffer_filter, wifi_access_point,
                                                     request):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        # change the supported channels to 1-13 in JP domain in AP mode raised testagent jira for support WIFI_BT_UTFHELP-4860

        con_obj.enable_aput(sl_collections, wifi_dut, ssid="TEST_693703",
                            security="WPA2", psk="Automation@123", ap_channel=14)


        # channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="ap")
        # assert int(channel) <= 6, "AP should start in channel 1-13"

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.\
            get_sniffer_filter(wlan_addr=dut_ap_mac_address,
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.test_src_map_id('C693670')
def test_melco_sdk_STA_scan_AP_OFF_C693670(sl_collections, wifi_dut, wifi_client,
                                           wifi_sniffer, sniffer_filter, wifi_access_point,
                                           request):

    try:
        logger().info("This testcase should be run in shieldbox")
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        logger().info("Initiating wlan scan")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        logger().info("Turn OFF AP")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(50)

        logger().info("Initiating wlan scan")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                      expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)

        logger().info("Found no APs in the scan results as expected")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_access_point.interfaces.wifi.start_ap()




@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
@pytest.mark.test_src_map_id('C693671')
def test_melco_sdk_STA_scan_AP_channel_C693671(sl_collections, wifi_dut, wifi_client,
                                           wifi_sniffer, sniffer_filter, wifi_access_point,
                                           request):

    try:
        logger().info("This testcase should be run in shieldbox")
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        # wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel, ssid=None)
        logger().info("Initiating wlan scan")
        # enables the scan in dut on channel
        scan_status, scan_results = sl_collections.scan(wifi_dut, scan_status=False, retry_count=3,
                                                             channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"scan results : {scan_results}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)






@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C693676",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.test_src_map_id('C693676')
def test_melco_sdk_Concurrent_STA_scan_when_no_ap_C693676(sl_collections, wifi_dut, wifi_client, channel,
                                       wifi_sniffer,
                                       sniffer_filter,
                                       http_client, request, wifi_access_point):

    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        wifi_access_point.interfaces.wifi.stop_ap()
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C693676", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, expected_status=[SLStatus.SL_STATUS_SI91X_NO_AP_FOUND])

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C693693",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.test_src_map_id('C693693')
def test_melco_sdk_APUT_HTTP_after_ap_deinit_C693693(sl_collections, wifi_dut, wifi_client, channel,
                                       wifi_sniffer,
                                       sniffer_filter,
                                       http_client, request, utf_constants):

    try:

        iter_count = utf_constants.get("iter_count")
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        for count in range(iter_count):

            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                      static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C693693", security="WPA2", psk="Automation@123",
                                              channel=channel,
                                              dtim_beacon_count="1", beacon_interval="100")
            time.sleep(30)
            wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6,
                                                      send_large_data=1, data=webpage)
            wifi_dut.interfaces.wifi.http_server_start()
            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")

            wifi_dut.interfaces.wifi.http_server_deinit()
            wifi_dut.interfaces.wifi.http_server_stop()

            wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
            time.sleep(5)
            wifi_dut.interfaces.wifi.sl_net_init(mode="ap")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C693694",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.test_src_map_id('C693694')
def test_melco_sdk_APUT_HTTP_after_ap_slnet_down_C693694(sl_collections, wifi_dut, wifi_client,
                                                         channel,
                                                         wifi_sniffer,
                                                         sniffer_filter,
                                                         http_client, request, utf_constants):
    try:

        iter_count = utf_constants.get("iter_count")
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        logger().info(f"This testcase will execute for  {iter_count} iterations as per harness configuration")

        for count in range(iter_count):

            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C693694", security="WPA2", psk="Automation@123", channel=channel,
                                              dtim_beacon_count="1", beacon_interval="100")
            time.sleep(30)
            wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
            wifi_dut.interfaces.wifi.http_server_start()
            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")

            wifi_dut.interfaces.wifi.http_server_deinit()
            wifi_dut.interfaces.wifi.http_server_stop()
            wifi_dut.interfaces.wifi.sl_net_down(mode="ap")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker(thread_count=3, stack_len=3072)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C690738')
def test_wifi_melco_sdk_con_UDP_txrx_ap_con_discon_C690738(wifi_dut, wifi_access_point,
                                                           wifi_sniffer,
                                                           sl_collections,
                                                           request,
                                                           sniffer_filter,
                                                           utf_constants,
                                                           wifi_client, wifi_clients, net_perf_clients):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Run UDP tx and rx in 2 threads
        7. Connect and disconnect connected clients
        8. Make sure data transmission should not be interrupted
        9. Connect and disconnect connected clients should success

    """
    test_name = request.node.name
    try:
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 ipv6_addr_type="link",
                                 remote_type="raspi", static_ipv6="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                                 )
        wlan_obj.join_to_ap()
        wlan_obj.create_ap_connect_remote_clients()
        wifi_client.interfaces.wifi.config["interface"] = sta_interface
        wlan_obj.check_ping_from_remote_to_dut_sta()
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface
                             )
        rx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             bandwidth="0.1M",
                             addr_type="link",
                             link_interface=sta_interface
                             )

        tx_obj.start()
        time.sleep(5)
        rx_obj.start()
        time.sleep(10)
        wlan_obj.raspi_client_leave()
        tx_obj.wait_for_exit()
        rx_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, len(wifi_clients)):
            packet_filter1 = (
                sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=dut_ap_mac_address, filter_name="deauthentication"
                )
            )
            logger().info(f"Validating deauthentication frames")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter1
            )["packet_count"], "Sniffer: Unable to find deauthentication packets in sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



# @pytest.mark.config(
#     "wifi_client",
#     wifi={
#         "security": "WPA2",
#         "ssid": "TEST_C693682",
#         "passphrase": "Automation@123",
#         "channel": 11,
#         "interface": "wlan0",
#     }
# )
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C693682",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C693682",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C693682",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C693682",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.test_src_map_id('C693682')
def test_melco_sdk_Con_HTTP_server_4_clients_cred_C693682(sl_collections, wifi_dut, wifi_client, channel,
                                                          wifi_sniffer,
                                                          sniffer_filter,
                                                          http_client, request, utf_constants,
                                                          wifi_clients,
                                                          wifi_access_point):

    try:

        assert len(wifi_clients) >= 4, "Minimum 4 clients required"
        wifi_clients = wifi_clients[:4]
        iter_count = utf_constants.get("iter_count")
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C693682", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6,
                                                  send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        credentials = [wifi_access_point.interfaces.wifi.ssid, wifi_access_point.interfaces.wifi.security,
                       wifi_access_point.interfaces.wifi.passphrase]

        for index in range(len(wifi_clients)):
            wifi_clients[index].interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip,
                                                                  web_ui_port=80,
                                                                  ssid=credentials[0],
                                                                  security=credentials[1],
                                                                  passphrase=credentials[2])
            data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)

            logger().info(f"credenatils from webpage: {data}")
            con_obj.credentials = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
            logger().info(f"credenatils: {con_obj.credentials}")
            assert con_obj.credentials, "Unable to fetch 3rd party AP details from DUT"
        con_obj.join_to_ap(wifi_dut, sl_collections,
                           con_obj.credentials[1],
                           con_obj.credentials[2],
                           con_obj.credentials[3].lower())
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C693683",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C693683",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C693683",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C693683",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.test_src_map_id('C693683')
def test_melco_sdk_Con_HTTP_server_4_clients_cred_C693683(sl_collections, wifi_dut, wifi_client, channel,
                                                          wifi_sniffer,
                                                          sniffer_filter,
                                                          http_client, request, utf_constants,
                                                          wifi_clients,
                                                          wifi_access_point,
                                                          wiseconnect_web):

    try:
        assert len(wifi_clients) >= 4, "Minimum 4 clients required"
        wifi_clients = wifi_clients[:4]
        iter_count = utf_constants.get("iter_count")
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")
        dut_sta_ip, dut_as_ap_ip = con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_clients,
                                                                    wiseconnect_web,
                                                                    webpage, channel, wifi_access_point,
                                                                    ssid="TEST_C693683", security="WPA2",
                                                                    psk="Automation@123")
        credentials = [wifi_access_point.interfaces.wifi.ssid, wifi_access_point.interfaces.wifi.security,
                       wifi_access_point.interfaces.wifi.passphrase]

        for index in range(len(wifi_clients)):
            wifi_clients[index].interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip,
                                                                  web_ui_port=80,
                                                                  ssid=credentials[0],
                                                                  security=credentials[1],
                                                                  passphrase=credentials[2])
            data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)

            logger().info(f"credenatils from webpage: {data}")
            con_obj.credentials = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
            logger().info(f"credenatils: {con_obj.credentials}")
            assert con_obj.credentials, "Unable to fetch 3rd party AP details from DUT"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C693692",
        "passphrase": "Automation@123",
        "channel": 11,
        # "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.test_src_map_id('C693692')
def test_melco_sdk_Concurrent_STA_ping_APUT_up_down_C693692(sl_collections, wifi_dut, wifi_client, channel,
                                                            wifi_sniffer,
                                                            sniffer_filter,
                                                            http_client, request, wifi_access_point,
                                                            utf_constants):
    try:
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        ap_interface = wifi_client.interfaces.wifi.config["interface"]
        iter_count = utf_constants.get("iter_count")
        con_obj.join_to_ap(wifi_dut, sl_collections, wifi_access_point.interfaces.wifi.ssid,
                           wifi_access_point.interfaces.wifi.passphrase,
                           wifi_access_point.interfaces.wifi.security.name.lower(),
                           ping_count=30)
        ping_link_local_addr = f"{con_obj.dut_sta_ipv6_link}%{ap_interface}"

        iperf_thread = Thread(target=sl_collections.ping, args=(ping_link_local_addr, 100, 3))
        iperf_thread.start()

        for count in range(iter_count):

            con_obj.enable_aput(sl_collections, wifi_dut, "TEST_C693692", "WPA2",
                                "Automation@123", channel)
            con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut, ping_count=20)['dut_ip']
            wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
        iperf_thread.join()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.net_perf_clients(["raspi_iperf", "secondary_raspi_iperf"])
@pytest.mark.config(
    "net_perf_clients",
     net_perf={
        0: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
       1: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
        }
)
@wifi_dut_marker(thread_count=2, stack_len=4096)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C700496')
def test_wifi_melco_sdk_con_UDP_txrx_ap_con_http_webpage_C700496(wifi_dut, wifi_access_point,
                                                                 wifi_sniffer,
                                                                 sl_collections,
                                                                 request,
                                                                 sniffer_filter,
                                                                 utf_constants,
                                                                 wifi_client, wifi_clients,
                                                                 net_perf_clients,
                                                                 http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Connect the STA to 3rd party AP
        4. Set STATIC IPV6 CONFIG to STA Interface "FF:FF:FF:FF:FF:FF:FF:FF"
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Configure static ipv4 address to APUT and start APUT
        7. Run UDP tx and rx in 2 threads
        8. Run the HTTP Webpage refresh while running UDP Tx/Rx traffic
        9. Make sure data transmission should not be interrupted

    """
    test_name = request.node.name
    try:
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        con_obj = ConcurrentMode()
        wifi_clients = wifi_clients[:1]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)


        static_ipv6 = random_ipv6_addr("2401:3500:133c::/48")

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients, ipv6_addr_type="link",
                                 remote_type="raspi", static_ipv6=static_ipv6
                                 )
        wlan_obj.join_to_ap()
        wifi_client.interfaces.wifi.config["interface"] = sta_interface
        wlan_obj.check_ping_from_remote_to_dut_sta()
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="Concurent_AP", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100", beacon_stop=1)
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface
                             )
        rx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             bandwidth="0.1M",
                             addr_type="link",
                             link_interface=sta_interface
                             )
        tx_obj.start()
        time.sleep(5)
        rx_obj.start()
        time.sleep(5)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']

        url = f"http://{dut_as_ap_ip}/login"
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        tx_obj.wait_for_exit()
        rx_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.net_perf_clients(["raspi_iperf", "secondary_raspi_iperf"])
@pytest.mark.config(
    "net_perf_clients",
     net_perf={
        0: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
       1: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
        }
)
@wifi_dut_marker(thread_count=2, stack_len=4096)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C700497')
def test_wifi_melco_sdk_con_UDP_txrx_ap_con_http_webpage_refresh_C700497(wifi_dut, wifi_access_point,
                                                               wifi_sniffer,
                                                               sl_collections,
                                                               request,
                                                               sniffer_filter,
                                                               utf_constants,
                                                               wifi_client, wifi_clients,
                                                               net_perf_clients,
                                                               http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Connect the STA to 3rd party AP
        4. Set STATIC IPV6 CONFIG to STA Interface "FF:FF:FF:FF:FF:FF:FF:FF"
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Configure static ipv4 address to APUT and start APUT
        7. Run UDP tx and rx in 2 threads
        8. Run the HTTP Webpage refresh while running UDP Tx/Rx traffic
        9. Make sure data transmission should not be interrupted

    """
    test_name = request.node.name
    try:
        con_obj = ConcurrentMode()
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        static_ipv6 = random_ipv6_addr("2401:3500:133c::/48")

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 remote_type="raspi", static_ipv6=static_ipv6, ipv6_addr_type="link"
                                 )
        wlan_obj.join_to_ap()
        wifi_client.interfaces.wifi.config["interface"] = sta_interface
        wlan_obj.check_ping_from_remote_to_dut_sta()
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="Concurent_AP", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100", beacon_stop=1)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface
                             )
        rx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             bandwidth="0.1M",
                             addr_type="link",
                             link_interface=sta_interface
                             )
        tx_obj.start()
        time.sleep(5)
        rx_obj.start()
        time.sleep(5)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']
        t1 = AccessDUTAPage(http_client, dut_as_ap_ip)
        t1.start()
        t1.wait_for_exit()
        tx_obj.wait_for_exit()
        rx_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.net_perf_clients(["raspi_iperf", "secondary_raspi_iperf"])
@pytest.mark.config(
    "net_perf_clients",
     net_perf={
        0: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
       1: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
        }
)
@wifi_dut_marker(thread_count=2, stack_len=4096)
@pytest.mark.skip(reason="long duration")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C693701')
def test_wifi_melco_sdk_con_UDP_txrx_ap_con_http_webpage_C693701(wifi_dut, wifi_access_point,
                                                               wifi_sniffer,
                                                               sl_collections,
                                                               request,
                                                               sniffer_filter,
                                                               utf_constants,
                                                               wifi_client, wifi_clients,
                                                               net_perf_clients,
                                                               http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Connect the STA to 3rd party AP
        4. Set STATIC IPV6 CONFIG to STA Interface "FF:FF:FF:FF:FF:FF:FF:FF"
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Configure static ipv4 address to APUT and start APUT
        7. Run UDP tx and rx in 2 threads
        8. Run the HTTP Webpage refresh while running UDP Tx/Rx traffic for 12 HOurs
        9. Make sure data transmission should not be interrupted

    """
    test_name = request.node.name
    try:
        con_obj = ConcurrentMode()
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 remote_type="raspi",
                                 static_ipv6=random_ipv6_addr("2401:3500:133c::/48")
                                 )
        wlan_obj.join_to_ap()
        wlan_obj.check_ping_from_remote_to_dut_sta()
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="Concurent_AP", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface
                             )
        rx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             bandwidth="0.1M",
                             addr_type="link",
                             link_interface=sta_interface
                             )
        tx_obj.start()
        time.sleep(5)
        rx_obj.start()
        time.sleep(5)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']
        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")
        tx_obj.wait_for_exit()
        rx_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker(thread_count=3, stack_len=4096)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.test_src_map_id('C693696')
def test_wifi_melco_sdk_check_http_server_sl_net_init_denit_with_udp_tx_traffic_c693696(wifi_dut,
                                                           wifi_access_point,
                                                           wifi_sniffer,
                                                           sl_collections,
                                                           request,
                                                           sniffer_filter,
                                                           utf_constants,
                                                           wifi_client, wifi_clients, net_perf_client, http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Run UDP RX in one thread
        7.

    """
    test_name = request.node.name
    try:
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        wifi_clients = wifi_clients[:1]
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        con_obj = ConcurrentMode()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(webpage) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=data_address, size=len(webpage), write_content=webpage, timeout=1)

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 ipv6_addr_type="link",
                                 remote_type="raspi",
                                 )
        wlan_obj.join_to_ap()
        wifi_client.interfaces.wifi.config["interface"] = sta_interface
        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_client, timeout=300,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface,
                             bandwidth="0.1M"
                             )
        tx_obj.start()
        time.sleep(5)
        for count in range(iter_count):
            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                      static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="Concurent_AP", security="WPA2", psk="Automation@123",
                                              channel=11,
                                              dtim_beacon_count="1", beacon_interval="100")
            time.sleep(30)
            wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage,
                                                      data_address=data_address)
            wifi_dut.interfaces.wifi.http_server_start()
            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")

            wifi_dut.interfaces.wifi.http_server_deinit()
            wifi_dut.interfaces.wifi.http_server_stop()
            wifi_dut.interfaces.wifi.sl_net_down(mode="ap")

        tx_obj.wait_for_exit()
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        wifi_dut.interfaces.wifi.memory_free(data_address)
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()






@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.net_perf_clients(["raspi_iperf", "secondary_raspi_iperf"])
@pytest.mark.config(
    "net_perf_clients",
     net_perf={
        0: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
       1: {
        "type": 'iperf',
        "zip_results": 'Y',
        "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
        "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
        }
)
@wifi_dut_marker(thread_count=3, stack_len=4096)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C690711')
def test_wifi_melco_sdk_con_UDP_txrx_ap_http_webpage_C690711(wifi_dut, wifi_access_point,
                                                             wifi_sniffer,
                                                             sl_collections,
                                                             request,
                                                             sniffer_filter,
                                                             utf_constants,
                                                             wifi_client, wifi_clients,
                                                             net_perf_clients,
                                                             http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Connect the STA to 3rd party AP
        4. Set STATIC IPV6 CONFIG to STA Interface "FF:FF:FF:FF:FF:FF:FF:FF"
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Configure static ipv4 address to APUT and start APUT
        7. Run UDP tx and rx in 2 threads
        8. Run the HTTP Webpage refresh while running UDP Tx/Rx traffic
        9. Make sure data transmission should not be interrupted

    """
    test_name = request.node.name
    try:
        sta_interface = wifi_client.interfaces.wifi.config["interface"]
        con_obj = ConcurrentMode()
        wifi_clients = wifi_clients[:1]
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        static_ipv6 = random_ipv6_addr("2401:3500:133c::/48")
        data_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(webpage) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=data_address, size=len(webpage), write_content=webpage, timeout=1)

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients, ipv6_addr_type="link",
                                 remote_type="raspi", static_ipv6=static_ipv6
                                 )
        wlan_obj.join_to_ap()
        wifi_client.interfaces.wifi.config["interface"] = sta_interface
        wlan_obj.check_ping_from_remote_to_dut_sta()
        tx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             addr_type="link",
                             link_interface=sta_interface
                             )
        rx_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                             test_name=test_name, wifi_client=wifi_client,
                             traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=100,
                             device_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_link'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv6'],
                             ip_version=6,
                             async_socket=1,
                             bandwidth="0.1M",
                             addr_type="link",
                             link_interface=sta_interface
                             )
        tx_obj.start()
        time.sleep(5)
        rx_obj.start()
        time.sleep(5)
        for count in range(iter_count):
            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                      static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="Concurent_AP", security="WPA2", psk="Automation@123",
                                              channel=11,
                                              dtim_beacon_count="1", beacon_interval="100")
            time.sleep(30)
            wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage,
                                                      data_address=data_address)
            wifi_dut.interfaces.wifi.http_server_start()
            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")

            wifi_dut.interfaces.wifi.http_server_deinit()
            wifi_dut.interfaces.wifi.http_server_stop()
            wifi_dut.interfaces.wifi.sl_net_down(mode="ap")

        tx_obj.wait_for_exit()
        rx_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
















