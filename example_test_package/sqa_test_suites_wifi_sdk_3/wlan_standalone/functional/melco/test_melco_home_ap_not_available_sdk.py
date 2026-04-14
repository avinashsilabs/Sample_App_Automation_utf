import re
import time
import random
import string
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
    Author: Saurabh Sharma
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
    dut_sta_ip = None
    dut_add_dict = {}

    def __init__(self):
        self.dut_ap_ip = None
        self.clients_connected = False
        self.credentials = None

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
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

    def join_to_ap(self, wifi_dut, wifi_access_point, sl_collections, ssid, passphrase, security, ping_count=30):

        join_status = False
        for count in range(3):
            try:
                logger().info(f"DUT Joining to 3rd party AP using credentials --> {ssid}:{passphrase}:{security}")
                wifi_dut.interfaces.wifi.join(ssid=ssid, passphrase=passphrase, security=security,
                                              channel=wifi_access_point.interfaces.wifi.channel, timeout=60)
                join_status = True
                break
            except Exception as error:
                logger().info(f"Joining to AP failed:{error}, retry_count...{count}")
                time.sleep(10)
        assert join_status, "Failed to join to 3rd party AP"
        ip_config = sl_collections.configure_ip(wifi_dut, retry_count=3, timeout=120)[-1]
        ConcurrentMode.dut_sta_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(5)
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1,
                                                           ip_version="ipv6")
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        ConcurrentMode.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
        ConcurrentMode.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"\nDUT IPV6 GLOBAL ADDRESS : {ConcurrentMode.dut_add_dict['dut_sta_ipv6_global']}\n"
                      f"DUT IPV6 LINK LOCAL ADDRESS : {ConcurrentMode.dut_add_dict['dut_sta_ipv6_link']}\n")

        logger().info("Pinging to DUT")
        status = sl_collections.ping(device_ip=ConcurrentMode.dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"

    def http_server_provisioning(self, sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                 webpage, ap_channel, wifi_access_point, ssid="sharma1234",
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

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")

        time.sleep(5)
        self.join_to_ap(wifi_dut, wifi_access_point, sl_collections, result[1], result[2], result[3].lower())

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
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.test_src_map_id('C557348')
def test_melco_sdk_scan_during_3rd_party_AP_off_c557348(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check whether DUT is able to perform the Scan for configurable iterations during unavailability of 3rd party AP in
    concurrent mode .
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="sharma1234", security="WPA2",
                                         psk="Automation@123")

        logger().info("Power OFF  3rd party AP")
        wifi_access_point.interfaces.wifi.stop_ap()
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

        for count in range(5):
            logger().info("Scanning all channels")
            wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel,
                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                          expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info(f"error code 0x10003 SL_STATUS_SI91X_NO_AP_FOUND is expected")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info("Power ON 3rd party AP")
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.test_src_map_id('C557349')
def test_melco_sdk_scan_and_apmode_reconn_during_3rd_party_AP_off_c557349(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check whether APUT is turning ON or not after STAUT fails to find the Required 3rd party AP
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="sharma1234", security="WPA2",
                                         psk="Automation@123")

        logger().info("Power OFF  3rd party AP")
        wifi_access_point.interfaces.wifi.stop_ap()
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

        for count in range(5):
            logger().info("Scanning all channels")
            wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel,
                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                          expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info(f"error code 0x10003 SL_STATUS_SI91X_NO_AP_FOUND is expected")

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

        wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(
            ssid="sharma1234", security="WPA2", psk="Automation@123", channel=8, dtim_beacon_count="1",
            beacon_interval="100")
        wifi_dut.interfaces.wifi.get_channel_info(interface="ap")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info("Power ON 3rd party AP")
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.test_src_map_id('C557350')
def test_melco_sdk_scan_and_staut_conn_new_channel_c557350(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check The STAUT connectivity to 3rd party AP through provisioning application in concurrent Mode
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        third_party_older_ap_channel = wifi_access_point.interfaces.wifi.channel

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="sharma1234", security="WPA2",
                                         psk="Automation@123")

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

        for count in range(5):
            logger().info("Scanning previous channel")
            wifi_dut.interfaces.wifi.scan(channel=third_party_older_ap_channel,
                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                          expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info(f"error code 0x10003 SL_STATUS_SI91X_NO_AP_FOUND is expected")

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123")

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
        "ssid": "sharma1234",
        "passphrase": "Automation@123",
        "channel": 6,
    }
)
@wifi_dut_marker()
@pytest.mark.parametrize("ap_channel", [6])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.test_src_map_id('C557351')
def test_melco_sdk_scan_and_aput_restart_same_channel_c557351(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, wiseconnect_web, request):
    """
    Check whether APUT is restarting or not on the same channel after connecting to 3rd party AP using Provisioning Mode
    """
    try:
        wifi_client = [wifi_client]
        con_obj = ConcurrentMode()
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        third_party_older_ap_channel = wifi_access_point.interfaces.wifi.channel

        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="ap")

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                         webpage, ap_channel, wifi_access_point, ssid="sharma1234", security="WPA2",
                                         psk="Automation@123")

        logger().info("Power OFF  3rd party AP")
        wifi_access_point.interfaces.wifi.stop_ap()
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

        for count in range(5):
            logger().info("Scanning previous channel")
            wifi_dut.interfaces.wifi.scan(channel=third_party_older_ap_channel,
                                          ssid=wifi_access_point.interfaces.wifi.ssid,
                                          expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info(f"error code 0x10003 SL_STATUS_SI91X_NO_AP_FOUND is expected")

        logger().info("starting new ap on same channel")
        wifi_access_point.interfaces.wifi.start_ap(channel=third_party_older_ap_channel)

        con_obj.http_server_provisioning(
            sl_collections, wifi_dut, wifi_client, wiseconnect_web, webpage, ap_channel, wifi_access_point,
            ssid="sharma1234", security="WPA2", psk="Automation@123")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
