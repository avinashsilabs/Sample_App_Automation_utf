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


class ConcurrentMode:
    def __init__(self):
        self.dut_ap_ip = None
        self.clients_connected = False

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        if self.clients_connected:
            logger().info(f"Disconnecting clients from DUT-AP before associating to DUT-AP")
            for client in wifi_clients:
                client.interfaces.wifi.leave()
            self.clients_connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        self.clients_connected = True
        return ip_dict

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


def wifi_dut_marker(ext_custom_bit=0, thread_count=1, tcp_feat_bit=0, ext_tcp_feat_bit=0, feat_bit=0, ca_cert=None):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 4096}},
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
@pytest.mark.skip(reason="Getting scan results when we power off AP in shield box")
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

        logger().info("Turn OFF AP")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(50)

        logger().info("Initiating wlan scan")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, expected_status=[SLStatus.SL_STATUS_SI91X_NO_AP_FOUND])

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

            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C693693", security="WPA2", psk="Automation@123", channel=channel,
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
def test_melco_sdk_APUT_HTTP_after_ap_slnet_down_C693694(sl_collections, wifi_dut, wifi_client, channel,
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



