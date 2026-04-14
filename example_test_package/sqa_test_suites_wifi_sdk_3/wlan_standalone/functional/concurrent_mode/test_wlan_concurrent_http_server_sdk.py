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
    Si91xCertIdentifier
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
        4.Disconnect dut and connect again
    Author: CG Team
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
    def join_to_ap(wifi_dut, sl_collections, ping_count=30):
        data = wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        assert result, "Unable to fetch 3rd party AP details from DUT"

        join_status = False
        for count in range(3):
            try:
                logger().info(f"DUT Joining to 3rd party AP using credentials --> {result.group()}")
                wifi_dut.interfaces.wifi.join(ssid=result[1], passphrase=result[2], security=result[3].lower(),
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
        logger().info("Pinging to DUT")
        status = sl_collections.ping(device_ip=dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"
        return dut_sta_ip

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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547020",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C547020')
def test_wifi_sdk_verify_conc_http_server_c547020(sl_collections, wifi_dut, wifi_client, channel, wifi_sniffer,
                                                  sniffer_filter, http_client):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547020"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547020", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547021",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C547021')
def test_wifi_sdk_verify_conc_http_webpage_c547021(sl_collections, wifi_dut, wifi_client, channel, wifi_sniffer,
                                                   sniffer_filter, wifi_access_point, wiseconnect_web):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547021"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547021", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        con_obj.join_to_ap(wifi_dut, sl_collections)

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547022",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C547022')
def test_wifi_sdk_verify_conc_http_webpage_incorrect_ssid_c547022(sl_collections, wifi_dut, wifi_client, channel,
                                                                  sniffer_filter, wifi_access_point, wiseconnect_web,
                                                                  wifi_sniffer):
    """
    Check the STAUT Connectivity to 3rd party AP With Incorrect SSID using HTTP Webpage credentials.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547022"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547022", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
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

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Probe Request Packet from the DUT in Sniffer")
        packet_filter1 = f'(wlan.addr == {dut_sta_mac_address} && wlan.fc.type_subtype == 0x0004 && wlan.ssid == "Incorrect_SSID")'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request packet from DUT in Sniffer'

        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547023",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C547023')
def test_wifi_sdk_verify_conc_http_webpage_with_tcp_tx_c547023(sl_collections, wifi_dut, wifi_client, channel,
                                                               remote_socket, sniffer_filter, wifi_access_point,
                                                               wiseconnect_web, wifi_sniffer):
    """
    Verify the STA TCP Tx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547023"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547023", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)

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

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547024",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C547024')
def test_wifi_sdk_verify_conc_http_webpage_with_sta_tcp_rx_c547024(sl_collections, wifi_dut, wifi_client, channel,
                                                               remote_socket, wifi_access_point, wiseconnect_web, wifi_sniffer, http_client):

    """
    Verify the STA TCP Rx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547024"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        time.sleep(10)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547024", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        time.sleep(5)
        dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)

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

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C569445",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
@pytest.mark.test_src_map_id('C569445')
def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_rx_interface_c569445(sl_collections, wifi_dut, wifi_client, channel,
                                                                            remote_socket, wifi_access_point, wiseconnect_web, wifi_sniffer, http_client):
    """
    Verify the AP TCP Rx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c569445"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        time.sleep(10)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C569445", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)

        time.sleep(5)
        dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)

        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port,server_ip=server_ip)
        server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
        logger().info(f"***** Server IP: {server_ip}")
        logger().info(f"***** DUT STA IP: {dut_sta_ip}")
        logger().info(f"***** DUT AS AP IP: {dut_as_ap_ip}")
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_as_ap_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        t1 = AccessDUTAPage(http_client, dut_as_ap_ip)
        t2 = SocketSendData(wifi_dut,remote_socket,sock)
        t2.start()
        time.sleep(20)
        t1.start()
        time.sleep(5)

        t1.wait_for_exit()
        t2.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C569448",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C569448')
def test_wifi_sdk_verify_conc_http_webpage_with_ap_tcp_tx_c569448(sl_collections, wifi_dut, wifi_client, channel,
                                                                  remote_socket, sniffer_filter, wifi_access_point,
                                                                  wiseconnect_web, wifi_sniffer):

    """
    Verify the AP TCP Tx to 3rd party AP Backend machine with Credentials from HTTP Webpage.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c569448"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C569448", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          security=wifi_access_point.interfaces.wifi.security,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(5)
        dut_sta_ip = con_obj.join_to_ap(wifi_dut, sl_collections)

        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port,server_ip=server_ip)
        # server_ip = remote_socket.interfaces.socket.server_ip
        server_ip = wifi_client[0].interfaces.wifi.get_ip_address()
        logger().info(f"***** Server IP: {server_ip}")
        logger().info(f"***** DUT STA IP: {dut_sta_ip}")
        logger().info(f"***** DUT AS AP IP: {dut_as_ap_ip}")

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_as_ap_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
            logger().info(f"Sending AP_TCP_TX is -> {tx_data}")
            wifi_dut.interfaces.wifi.bsdSocketSend(sock, tx_data)
            time.sleep(1)
            rx_data = remote_socket.interfaces.socket.recv_data_tcp(len(tx_data))
            logger().info(f"Data received at remote TCP socket is -> {rx_data}")
            assert tx_data == rx_data, "Data sent by DUT  and received at server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C547025",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.check3
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('TC4543785969')
def test_wifi_sdk_verify_conc_http_server_c547025_with_stop_start_ap(sl_collections, wifi_dut, wifi_client, channel,
                                                                     wifi_sniffer,
                                                                     sniffer_filter, http_client):
    """
    Verify the HTTP Webpage on 3rd party STA which is connected to APUT and restart aput using stop and start.
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        capture_filename = "test_c547025"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547025", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"dut_ap_mac_address: {dut_ap_mac_address}")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Checking for Beacons from the DUT as AP in Sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=dut_ap_mac_address,
                                                                                        radio_ch=channel,
                                                                                        filter_name="beacon_ap_mode_us_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame from DUT in Sniffer'

        logger().info("Stopping http_server ")
        wifi_dut.interfaces.wifi.http_server_stop()
        time.sleep(2)

        logger().info("Stopping http_de_init ")
        wifi_dut.interfaces.wifi.http_server_deinit()
        time.sleep(10)

        logger().info("Stopping AP ")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(20)

        logger().info("Starting AP after stopping ")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        wifi_dut.interfaces.wifi.http_server_start()
        logger().info(" ********** ReStarting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C547025", security="WPA2", psk="Automation@123", channel=channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(60)
        dut_as_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_client, wifi_dut, ping_count=20)['dut_ip']
        time.sleep(20)

        url = f'http://{dut_as_ap_ip}/login'
        result = http_client.interfaces.http.session.request('GET', url)
        assert result.status_code == 200, f"Failed to get HTTP response from DUT as AP"
        logger().info(f"HTTP Response Content:\n{result.content}\n")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
