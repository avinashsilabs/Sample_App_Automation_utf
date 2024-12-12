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
    Si91xInterface
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase


"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4. Disconnect dut and connect again
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

    @staticmethod
    def join_to_ap(wifi_dut, sl_collections, ssid, passphrase, security, ping_count=30):

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
        dut_sta_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(5)
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version="ipv6")
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        dut_sta_ipv6_global = ip_config[1]
        dut_sta_ipv6_link = ip_config[0]
        logger().info("Pinging to DUT")
        status = sl_collections.ping(device_ip=dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"
        return dut_sta_ip


    def http_server_provisioning(self, sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                 webpage, ap_channel, wifi_access_point, ssid="TEST_C557337",
                                 security="WPA2", psk="Automation@123"):
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, psk=psk,
                                          channel=ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = self.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.http_server_stop()

        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init()
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        # wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        # wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        time.sleep(5)
        dut_sta_ip = self.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        # wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, psk=psk,
                                          channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = self.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        return dut_sta_ip, dut_as_ap_ip


class ValidateSniffer:
    def __init__(self):
        self.sniffer_filter = None

    def sniffer_validation_beacon(self, wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel, expected_beacons=True):

        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        if expected_beacons:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find beacon frame from DUT in Sniffer'
            logger().info("Beacon frames found in sniffer when DUT is in AP mode")
        else:

            assert not wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, negative_test=True)[
                'packet_count'], \
                'found beacon frame  when stop ap enabled from DUT in Sniffer'
            logger().info("Beacon frame not found in sniffer when stop ap enabled from DUT")

    def sniffer_validation_11ax_disable(self, wifi_sniffer, sniffer_filter, wifi_access_point, dut_sta_mac_address):

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_sta_mac_address,
                                                                                        da_addr=ap_mac_address,
                                                                                        filter_name='probe_request_HE')
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_sta_mac_address,
                                                                                        da_addr=ap_mac_address,
                                                                                        filter_name='association_request_HE')
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(ta_addr=dut_sta_mac_address,
                                                                                        ra_addr=ap_mac_address,
                                                                                        filter_name='data_packets_HE')
        logger().info("Validating Probe Req with HE information")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
            'packet_count'], 'Unable to find Probe Req with HE capability in sniffer'

        logger().info("Validating Assoc Req with HE information")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3, negative_test=True)[
            'packet_count'], 'Unable to find Assoc Req  with HE capability in sniffer'

        logger().info("Validating data packet with PHY type as 11ax")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4, negative_test=True)[
            'packet_count'], 'Unable to find data packet with PHY type as 11ax in sniffer'



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
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
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
        "ssid": "TEST_C557318",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_C557318(sl_collections, wifi_dut, wifi_client, channel,
                                       wifi_sniffer,
                                       sniffer_filter,
                                       http_client, request):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557318", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address,
                                            channel, expected_beacons=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557319",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_stop_beacon_C557319(sl_collections, wifi_dut, wifi_client,
                                                   channel, wifi_sniffer,
                                                   sniffer_filter, http_client, request):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557319", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100", beacon_stop=1)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6,
                                                  send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        time.sleep(10)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                 expected_beacons=False)

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wifi_client[0].interfaces.wifi.leave()
        ut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C687978",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_connect_reconnec_C687978(sl_collections, wifi_dut, wifi_client,
                                                   channel, wifi_sniffer, utf_constants,
                                                   sniffer_filter, http_client, request):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C687978", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100", beacon_stop=1)
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        for count in range(0, iter_count):
            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")
            wifi_client[0].interfaces.wifi.leave()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557320",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_start_stop_ap_C557320(sl_collections, wifi_dut, wifi_client,
                                                     channel, wifi_sniffer,
                                                     sniffer_filter, http_client, request):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        for i in range(0, 2):

            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557320", security="WPA2", psk="Automation@123",
                                              channel=channel,
                                              dtim_beacon_count="1", beacon_interval="100")
            time.sleep(30)
            wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
            wifi_dut.interfaces.wifi.http_server_start()

            dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

            url = f'http://{dut_as_ap_ip}/login'
            result = http_client.interfaces.http.session.request('GET', url)
            assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
            logger().info(f"HTTP Response Content:\n{result.content}\n")

            wifi_dut.interfaces.wifi.stop_ap()
            logger().info("Initialising DUT after the reset....")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.wifi.init(load_certificate=False)
            wifi_dut.interfaces.wifi.initialize_thread()
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_client[0].interfaces.wifi.leave()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557321",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_conc_http_webpage_C557321(sl_collections, wifi_dut, wifi_client, channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557321", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557322",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_conc_STA_11ax_disable_C557322(sl_collections, wifi_dut, wifi_client, channel,
                                                             wifi_sniffer, sniffer_filter, wifi_access_point,
                                                             wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557322", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}, dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)
        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557323",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("ap_channel", [1])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_conc_http_webpage_C557323(sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="TEST_C557323", security="WPA2",
                                         psk="Automation@123")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address,
                                            wifi_access_point.interfaces.wifi.channel, expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557323",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_melco_channel_change_C557324(sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="TEST_C557324", security="WPA2",
                                         psk="Automation@123")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address,
                                            wifi_access_point.interfaces.wifi.channel,
                                            expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557325",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_melco_ap_power_cycle_C557325(sl_collections, wifi_dut, wifi_client, ap_channel,
                                                            wifi_sniffer,
                                                            sniffer_filter, wifi_access_point,
                                                            wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=ap_channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557325", security="WPA2", psk="Automation@123",
                                          channel=ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())

        wifi_access_point.interfaces.wifi.stop_ap()
        # wifi_dut.interfaces.wifi.http_server_deinit()
        logger().info("wait for disconnect event")
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init()
        # wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        time.sleep(5)
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        channel = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557325", security="WPA2", psk="Automation@123",
                                          channel=wifi_access_point.interfaces.channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        time.sleep(30)
        wifi_client[0].interfaces.wifi.channel = wifi_access_point.interfaces.channel
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557326",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_melco_psk_change_C557326(sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=ap_channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557326", security="WPA2", psk="Automation@123",
                                          channel=ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())

        wifi_access_point.interfaces.wifi.start_ap(passphrase="Automation@1234")
        # wifi_dut.interfaces.wifi.http_server_deinit()
        logger().info("wait for disconnect event")
        # wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init()
        # wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        time.sleep(5)
        con_obj.join_to_ap(wifi_dut, sl_collections, result[1], result[2], result[3].lower())
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        channel = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557326", security="WPA2", psk="Automation@123",
                                          channel=wifi_access_point.interfaces.channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        wifi_client[0].interfaces.wifi.channel = wifi_access_point.interfaces.channel
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                            expected_beacons=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557327",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("ap_channel", [1])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_AP_restart_C557327(sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web, request):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=ap_channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="TEST_C557327", security="WPA2",
                                         psk="Automation@123")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address,
                                            wifi_access_point.interfaces.wifi.channel,
                                            expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()





@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557330",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_incorrect_ssid_C557330(sl_collections, wifi_dut, wifi_client, channel,
                                                            sniffer_filter, wifi_access_point, wiseconnect_web,
                                                            wifi_sniffer):
    """
    Check the STAUT Connectivity to 3rd party AP With Incorrect SSID using HTTP Webpage credentials.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        capture_filename = "test_C557330"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557330", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid="Incorrect_SSID",
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        wifi_dut.interfaces.wifi.join(ssid=result[1], passphrase=result[2], security=result[3].lower(),
                                      expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
        logger().info(f"DUT sent error code '{hex(SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)}' for given incorrect SSID")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}, dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Probe Request Packet from the DUT in Sniffer")
        packet_filter1 = f'(wlan.addr == {dut_sta_mac_address} && wlan.fc.type_subtype == 0x0004 && wlan.ssid == "Incorrect_SSID")'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request packet from DUT in Sniffer'

        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557328",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_melco_sdk_HTTP_server_tcp_tx_C557328(sl_collections, wifi_dut, wifi_client, channel,
                                               remote_socket, sniffer_filter, wifi_access_point,
                                               wiseconnect_web, wifi_sniffer):
    """
    Verify the STA TCP Tx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        capture_filename = "TEST_C557328"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C557328", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()

        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"
        dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections, ssid=result[1], passphrase=result[2],
                                        security=result[3].lower())

        logger().info("Starting TCP server socket remotely")
        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port)
        server_ip = remote_socket.interfaces.socket.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
            wifi_dut.interfaces.wifi.bsdSocketSend(sock, tx_data)
            time.sleep(1)
            rx_data = remote_socket.interfaces.socket.recv_data_tcp(len(tx_data))
            logger().info(f"Data received at remote TCP socket is -> {rx_data}")
            assert tx_data == rx_data, "Data sent by DUT and received at server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557331",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_tcp_tx_C557331(sl_collections, wifi_dut, wifi_client, channel,
                                              remote_socket, sniffer_filter, wifi_access_point,
                                              wiseconnect_web, wifi_sniffer):
    """
    Verify the STA TCP Tx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        capture_filename = "TEST_C557331"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        dut_sta_ip, dut_as_ap_ip = con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, channel, wifi_access_point, ssid="TEST_C557331", security="WPA2",
                                         psk="Automation@123")
        logger().info("Starting TCP server socket remotely")
        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port)
        server_ip = remote_socket.interfaces.socket.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
            wifi_dut.interfaces.wifi.bsdSocketSend(sock, tx_data)
            time.sleep(1)
            rx_data = remote_socket.interfaces.socket.recv_data_tcp(len(tx_data))
            logger().info(f"Data received at remote TCP socket is -> {rx_data}")
            assert tx_data == rx_data, "Data sent by DUT and received at server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@wifi_dut_marker()
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C557332",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4742")
def test_melco_sdk_HTTP_server_tcp_rx_C557332(sl_collections, wifi_dut, wifi_client, channel,
                                              remote_socket, wifi_access_point, wiseconnect_web,
                                              wifi_sniffer, sniffer_filter, http_client):
    """
    Verify the STA TCP Rx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        sniff_obj = ValidateSniffer()
        capture_filename = "test_C557332"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        dut_sta_ip, dut_as_ap_ip = con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                                      webpage, channel, wifi_access_point, ssid="TEST_C557332",
                                                      security="WPA2",
                                                      psk="Automation@123")

        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port)
        server_ip = remote_socket.interfaces.socket.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        t1 = AccessDUTAPage(http_client, dut_as_ap_ip)
        t2 = SocketSendData(wifi_dut,remote_socket,sock)
        t2.start()
        time.sleep(5)
        t1.start()
        time.sleep(5)

        t1.wait_for_exit()
        t2.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        dut_sta_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=1)
        logger().info(f"dut_sta_mac_address: {dut_sta_mac_address}")

        wifi_client[0].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniff_obj.sniffer_validation_beacon(wifi_sniffer, sniffer_filter, dut_ap_mac_address, channel,
                                                  expected_beacons=True)

        sniff_obj.sniffer_validation_11ax_disable(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                        dut_sta_mac_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
#
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": Si91xOperatingMode.ConcurrentMode,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
#     }
# )
# @pytest.mark.config(
#     "wifi_client",
#     wifi={
#         "security": "WPA2",
#         "ssid": "TEST_C569445",
#         "passphrase": "Automation@123",
#         "channel": 11,
#         "interface": "wlan0",
#     }
# )
# @pytest.mark.parametrize("channel", [11])
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_rx_interface_c569445(sl_collections, wifi_dut, wifi_client, channel,
#                                                                             remote_socket, wifi_access_point, wiseconnect_web, wifi_sniffer, http_client):
# # def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_rx_interface_c569445(sl_collections, wifi_dut, wifi_client,
# #                                                                             channel, remote_socket, wifi_access_point,wiseconnect_web, http_client):
#     """
#     Verify the AP TCP Rx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
#     """
#     try:
#         wifi_client = [wifi_client]
#         con_obj = ConcurrentMode()
#         capture_filename = "test_c569445"
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#
#         sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
#                                                   static_gateway="192.168.100.76")
#         wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
#         time.sleep(10)
#         wifi_dut.interfaces.wifi.http_server_start()
#         logger().info(" ********** Starting DUT as an AP ********* ")
#         wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C569445", security="WPA2", psk="Automation@123", channel=channel,
#                                           dtim_beacon_count="1", beacon_interval="100")
#         time.sleep(30)
#         dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
#         wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
#                                                           ssid=wifi_access_point.interfaces.wifi.ssid,
#                                                           security=wifi_access_point.interfaces.wifi.security,
#                                                           passphrase=wifi_access_point.interfaces.wifi.passphrase)
#
#         time.sleep(5)
#         dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)
#
#         server_port = randint(5001, 5100)
#         local_port = randint(5001, 60000)
#         remote_socket.interfaces.socket.stop()
#         server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
#         remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port,server_ip=server_ip)
#         server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
#         logger().info(f"***** Server IP: {server_ip}")
#         logger().info(f"***** DUT STA IP: {dut_sta_ip}")
#         logger().info(f"***** DUT AS AP IP: {dut_as_ap_ip}")
#         sock = wifi_dut.interfaces.wifi.socket()
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_as_ap_ip, server_port=local_port, timeout=15)
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
#         time.sleep(3)
#
#         t1 = AccessDUTAPage(http_client, dut_as_ap_ip)
#         t2 = SocketSendData(wifi_dut,remote_socket,sock)
#         t2.start()
#         time.sleep(20)
#         t1.start()
#         time.sleep(5)
#
#         t1.wait_for_exit()
#         t2.wait_for_exit()
#
#         dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
#         logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
#
#         logger().info("Stop sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         wifi_dut.interfaces.wifi.stop_ap()
#
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": Si91xOperatingMode.ConcurrentMode,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
#     }
# )
# @pytest.mark.config(
#     "wifi_client",
#     wifi={
#         "security": "WPA2",
#         "ssid": "TEST_C569448",
#         "passphrase": "Automation@123",
#         "channel": 11,
#         "interface": "wlan0",
#     }
# )
# @pytest.mark.parametrize("channel", [11])
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_tx_c569448(sl_collections, wifi_dut, wifi_client, channel,
#                                                                   remote_socket, sniffer_filter, wifi_access_point,
#                                                                   wiseconnect_web, wifi_sniffer):
# # def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_tx_c569448(sl_collections, wifi_dut, wifi_client, channel,
# #                                                                   remote_socket, wifi_access_point, wiseconnect_web):
#
#     """
#     Verify the AP TCP Tx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
#     """
#     try:
#         wifi_client = [wifi_client]
#         con_obj = ConcurrentMode()
#         capture_filename = "test_c569448"
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#
#         sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
#                                                   static_gateway="192.168.100.76")
#         wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
#         wifi_dut.interfaces.wifi.http_server_start()
#         logger().info(" ********** Starting DUT as an AP ********* ")
#         wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C569448", security="WPA2", psk="Automation@123", channel=channel,
#                                           dtim_beacon_count="1", beacon_interval="100")
#         time.sleep(30)
#         dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
#
#         wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
#                                                           ssid=wifi_access_point.interfaces.wifi.ssid,
#                                                           security=wifi_access_point.interfaces.wifi.security,
#                                                           passphrase=wifi_access_point.interfaces.wifi.passphrase)
#         time.sleep(5)
#         dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)
#
#         server_port = randint(5001, 5100)
#         local_port = randint(5001, 60000)
#         remote_socket.interfaces.socket.stop()
#         server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
#         remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port,server_ip=server_ip)
#         # server_ip = remote_socket.interfaces.socket.server_ip
#         server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
#         logger().info(f"***** Server IP: {server_ip}")
#         logger().info(f"***** DUT STA IP: {dut_sta_ip}")
#         logger().info(f"***** DUT AS AP IP: {dut_as_ap_ip}")
#
#         sock = wifi_dut.interfaces.wifi.socket()
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_as_ap_ip, server_port=local_port, timeout=15)
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
#         time.sleep(3)
#
#         sw = Stopwatch()
#         while sw.elapsed_sec <= 30:
#             tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
#             logger().info(f"Sending AP_TCP_TX is -> {tx_data}")
#             wifi_dut.interfaces.wifi.bsdSocketSend(sock, tx_data)
#             time.sleep(1)
#             rx_data = remote_socket.interfaces.socket.recv_data_tcp(len(tx_data))
#             logger().info(f"Data received at remote TCP socket is -> {rx_data}")
#             assert tx_data == rx_data, "Data sent by DUT  and received at server is not matching"
#             logger().info("Data sent by DUT and received on server is matching\n")
#
#         dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
#         logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")
#
#         logger().info("Stop sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Checking for Beacons from the DUT as AP in Sniffer")
#         packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
#                                                                                         radio_ch=channel,
#                                                                                         filter_name="beacon_ap_mode_us_region")
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
#             'Unable to find beacon frame from DUT in Sniffer'
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         wifi_dut.interfaces.wifi.stop_ap()
