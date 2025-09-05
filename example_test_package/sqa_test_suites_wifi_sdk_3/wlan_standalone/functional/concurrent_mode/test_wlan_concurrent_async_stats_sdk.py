import re
import uuid
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.ap_mode.test_apmode_sdk import FilterPacket
from datetime import datetime
import time
from typing import Dict
from random import randint
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.ap_mode import test_apmode_sdk as ap
from threading import Thread

from utf.interfaces.iperf.fixtures import net_perf_clients
from utf.interfaces.socket.fixtures import remote_socket
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xAwsQos
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import string
import random
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.cloud_connectivity.test_aws_iot_wifi_sqa_sdk import AwsConnection


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
    Author: Sakshi Agrawal
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

class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_clients, utf_constants, wifi_access_point,testcase_no = None, ht_caps=0, mode = "DUT", remote_socket=None, leave=False):
    # def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_clients=None, protocol=None, testcase_no = None, capture_filename = None,  ping=True, traffic_type=None, stop_sniffer=True, leave=False, ht_caps=0, remote_socket_factory=None):
        super().__init__()
        self.ap_mac_address = None
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.testcase_no = testcase_no
        self.no_of_clients = 1
        self.channel = "1"
        self.ssid = "SILABS_AP_MODE"
        self.security = "wpa2"
        self.password = "Automation@123"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.ht_caps = ht_caps
        self.mode = mode
        self.device_ip = None
        self.dut_ap_ip = None
        self.clients_connected = False
        self.credentials = None
        self.remote_socket = remote_socket
        self.leave = leave

    def get_latest_state_code(self):
        """Return a list of all state codes present in all filtered events."""
        events = self.wifi_dut.interfaces.wifi.get_async_events()

        filtered_events = [
            event
            for event in events
            if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
        ]
        if len(filtered_events) == 0:
            return ["No State Code"]

        state_codes = []
        for event in filtered_events:
            logger().info(f"Event ID: {event.event_type}, Event Data: {event.event_data}")
            matches = re.findall(r'state_code ::\s*(0x[0-9a-fA-F]+)', event.event_data)
            if matches:
                state_codes.extend(matches)
        if not state_codes:
            state_codes = ["No State Code"]
        logger().info(f"\n\n state_codes :: {state_codes} \n\n")
        return state_codes

    def tcp_server_single_socket(self, port=5001, keepalive_time=30, server_ip=None, data_length=1000):
        logger().info(f"\n Starting the Remote Socket Server \n")
        self.remote_socket.interfaces.socket.start_server(port=port)
        socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.device_ip, server_port=port, timeout=5,
            asynch=0)
        logger().info(f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=socket_id, option_name="SO_KEEPALIVE", option_val=keepalive_time
        )
        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=socket_id, server_ip=server_ip, server_port=port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )
        try:
            self.wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=socket_id, data=sent_data, higher_data_len=1
            )
            received_data = (
                self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
            )
            logger().info(f"\nReceived Data: {received_data}\n")
            assert (
                    sent_data == received_data
            ), f"Data mismatch in sent and received data"
        except Exception as e:
            logger().info(
                f"Socket Data Transfer Failed Within Duration"
            )
        time.sleep(keepalive_time * 1.3)
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.remote_socket.interfaces.socket.stop()

    @staticmethod
    def verify_state_code(state_code, expected):
        if state_code == expected:
            logger().info(f"Expected state code {expected} received.")
        else:
            raise AssertionError(f"Expected state code {expected} NOT received. Actual state code: {state_code}")

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
        dut_sta_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info("Pinging to DUT")
        status = sl_collections.ping(device_ip=dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"
        state_code = self.get_latest_state_code()[-1]
        self.verify_state_code(state_code, expected='0x80')
        return dut_sta_ip

    def http_server_provisioning(self, sl_collections, wifi_dut, wifi_client, wiseconnect_web,
                                 webpage, ap_channel, wifi_access_point, ssid="SILABS_AP_MODE",
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

        logger().info(f"credenatils from webpage: {data}")
        self.credentials = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        logger().info(f"credenatils: {self.credentials}")
        assert self.credentials, "Unable to fetch 3rd party AP details from DUT"
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.http_server_stop()
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        if self.testcase_no == 782504:
            wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

        wifi_dut.interfaces.wifi.sl_net_init(mode="client", timeout=20, stats_arg=1)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=1)
        dut_sta_ip = self.join_to_ap(wifi_dut, sl_collections, self.credentials[1],
                                     self.credentials[2], self.credentials[3].lower())

        wifi_dut.interfaces.wifi.sl_net_init(mode="ap", stats_arg=1)

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

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        if self.mode == "DUT":
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        power_save=False,
                                                                        ping_after_power_save=False, retry_count=3,
                                                                        associated=self.wifi_dut.interfaces.wifi.associated
                                                                    )
            self.device_ip = self.dut_addr['device_ip']

        if self.mode == "APUT":
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")

            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(
                self.wifi_dut, self.wifi_clients,
                channel=self.channel, ssid=self.ssid,
                security=self.security,
                password=self.password,
                dtim_count=self.dtim_count,
                beacon_interval=self.beacon_interval,
                ping_count=ping_count,
                no_of_clients=self.no_of_clients,
                leave=self.leave,
            )

        if self.mode == "APSTAUT":
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")

            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(
                self.wifi_dut, self.wifi_clients,
                channel=self.channel, ssid=self.ssid,
                security=self.security,
                password=self.password,
                dtim_count=self.dtim_count,
                beacon_interval=self.beacon_interval,
                ping_count=ping_count,
                no_of_clients=self.no_of_clients,
                leave=self.leave,
            )
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=False,
                                                                     ping_after_power_save=False, retry_count=3,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     )
            self.device_ip = self.dut_addr['device_ip']

    def ap_sta_disconnection(self):
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()
        self.wifi_dut.interfaces.wifi.leave()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
    },
)
def test_wifi_sdk_verify_state_code_in_STA_and_STAUT_c782494(wifi_access_point, wifi_dut, wifi_clients, utf_constants, sl_collections, request, wifi_sniffer):
    """ To Verify State Code in  STA and STAUT mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.deinit()
        wifi_dut.interfaces.wifi.config_modular_stats(1)
        wifi_dut.interfaces.wifi.init()
        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients, utf_constants=utf_constants, wifi_access_point=wifi_access_point, mode = "APUT")

        logger().info(f"***** Verify the state code when DUT is initialized in CLIENT mode *****")
        wifi_dut.interfaces.wifi.scan()
        state_code= conc_obj.get_latest_state_code()[-1]
        conc_obj.verify_state_code(state_code, expected = '0x0')

        logger().info(f"***** Verify the state code when DUT is initialized in Concurrent mode *****")
        wifi_dut.interfaces.wifi.deinit()
        wifi_dut.interfaces.wifi.set_wifi_config(oper_mode=Si91xOperatingMode.ConcurrentMode,
                                                 custom_features=Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost)
        wifi_dut.interfaces.wifi.init(config_required=False)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan()
        state_code= conc_obj.get_latest_state_code()[-1]
        conc_obj.verify_state_code(state_code, expected='0x0')

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.config_modular_stats(0)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 1,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_verify_state_code_in_APUT_c782495(wifi_access_point, wifi_dut, wifi_clients, utf_constants, sl_collections, request, wifi_sniffer):
    """ To Verify State Code in APUT mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.deinit()
        wifi_dut.interfaces.wifi.config_modular_stats(1)
        wifi_dut.interfaces.wifi.init()
        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients, utf_constants=utf_constants, wifi_access_point=wifi_access_point, mode = "APUT")
        conc_obj.start()
        conc_obj.wait_for_exit()

        state_code = conc_obj.get_latest_state_code()[-1]
        conc_obj.verify_state_code(state_code, expected = "No State Code")

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.config_modular_stats(0)
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |0,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    }
)
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', "passphrase": '12345678'})
def test_wifi_sdk_APUT_STAUT_Http_sever_enable_c782498(sl_collections, wifi_dut, wifi_client, channel, wifi_access_point, wiseconnect_web, utf_constants, request, wifi_sniffer):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode after state code 0x80.
    """
    try:
        wifi_clients = [wifi_client]
        con_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point)
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.set_wifi_config()
        wifi_dut.interfaces.wifi.sl_net_init(mode="ap", stats_arg=1)

        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_clients,
                                                                    wiseconnect_web,
                                                                    webpage, channel, wifi_access_point,
                                                                    ssid="SILABS_AP_MODE", security="WPA2",
                                                                    psk="Automation@123")
        wifi_clients[0].interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 1,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'SAKSHI-ASUS', "passphrase": 'Automation@123'})
def test_wifi_sdk_APUT_STAUT_data_transfer_C782501(wifi_access_point, wifi_dut, wifi_clients, utf_constants, sl_collections, remote_socket, request, wifi_sniffer):
    """ To Verify the data transfer when device is in STAUT mode after State Code 0x80 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.deinit()
        wifi_dut.interfaces.wifi.config_modular_stats(1)
        wifi_dut.interfaces.wifi.init()
        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients, utf_constants=utf_constants, wifi_access_point=wifi_access_point,
                                  mode = "APSTAUT", remote_socket=remote_socket)
        conc_obj.start()
        conc_obj.wait_for_exit()

        state_code = conc_obj.get_latest_state_code()[-1]
        conc_obj.verify_state_code(state_code, expected='0x80')
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        conc_obj.tcp_server_single_socket(server_ip=server_ip)
    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.close_sockets()
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | 0,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    }
)
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', "passphrase": '12345678'})
def test_wifi_sdk_STAUT_data_transfer_stop_Http_sever_c782502(sl_collections, wifi_dut, wifi_client, channel,
                                                       wifi_access_point, wiseconnect_web, utf_constants, remote_socket, request, wifi_sniffer):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode and Stop the HTTP server in DUT after state code 0x90.
    """
    try:
        wifi_clients = [wifi_client]
        con_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients,
                                   utf_constants=utf_constants, wifi_access_point=wifi_access_point, remote_socket=remote_socket)
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.set_wifi_config()
        wifi_dut.interfaces.wifi.sl_net_init(mode="ap", stats_arg=1)
        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_clients,
                                         wiseconnect_web,
                                         webpage, channel, wifi_access_point,
                                         ssid="SILABS_AP_MODE", security="WPA2",
                                         psk="Automation@123")
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        con_obj.tcp_server_single_socket(server_ip=server_ip)
        wifi_access_point.interfaces.wifi.disconnect_devices(mac_address=wifi_dut.interfaces.wifi.get_mac_address())
        time.sleep(10)
        state_codes = con_obj.get_latest_state_code()
        if '0x90' == state_codes[-2] and state_codes[-1] == '0x0':
            logger().info(
                f"\n ===================== DUT disconnected from 3rd party AP successfully and observed state codes {state_codes} ====================== \n")
        else:
            raise Exception(
                "State codes 0x90 and 0x0 not found in the list. Hence, failed to disconnect from 3rd party AP")

        logger().info("\n ===================Stopping the HTTP server in DUT======================= \n")
        wifi_dut.interfaces.wifi.http_server_deinit()
        wifi_dut.interfaces.wifi.http_server_stop()

        wifi_clients[0].interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.close_sockets()
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | 0,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    }
)
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', "passphrase": '12345678'})
def test_wifi_sdk_STAUT_data_transfer_stop_soft_ap_c782503(sl_collections, wifi_dut, wifi_client, channel,
                                                       wifi_access_point, wiseconnect_web, utf_constants, remote_socket, request, wifi_sniffer):
    """
    Check STAUT Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode and Stop the Soft AP in DUT after state code 0x90.
    """
    try:
        wifi_clients = [wifi_client]
        con_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients,
                                   utf_constants=utf_constants, wifi_access_point=wifi_access_point, remote_socket=remote_socket
                                   )
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.set_wifi_config()
        wifi_dut.interfaces.wifi.sl_net_init(mode="ap", stats_arg=1)
        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_clients,
                                         wiseconnect_web,
                                         webpage, channel, wifi_access_point,
                                         ssid="SILABS_AP_MODE", security="WPA2",
                                         psk="Automation@123")
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        con_obj.tcp_server_single_socket(server_ip=server_ip)
        wifi_access_point.interfaces.wifi.disconnect_devices(mac_address=wifi_dut.interfaces.wifi.get_mac_address())
        time.sleep(10)
        state_codes = con_obj.get_latest_state_code()
        if '0x90' == state_codes[-2] and state_codes[-1] == '0x0':
            logger().info(
                f"\n ===================== DUT disconnected from 3rd party AP successfully and observed state codes {state_codes} ====================== \n")
        else:
            raise Exception(
                "State codes 0x90 and 0x0 not found in the list. Hence, failed to disconnect from 3rd party AP")

        logger().info("\n =================== Stopping the APUT Interface ======================= \n")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_clients[0].interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.close_sockets()
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |0,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    }
)
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', "passphrase": '12345678'})
def test_wifi_sdk_STA_APUT_Http_sever_enable_c782504(sl_collections, wifi_dut, wifi_client, channel, wifi_access_point, wiseconnect_web, utf_constants, request, wifi_sniffer):
    """
    Check STA first and STAUT  Connectivity to 3rd party AP with Credentials from HTTP Server in concurrent Mode after state code 0x80.
    """
    try:
        wifi_clients = [wifi_client]
        con_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point, testcase_no="782504")
        test_name = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.set_wifi_config()
        wifi_dut.interfaces.wifi.sl_net_init(mode="client", timeout=20, stats_arg=1)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                            power_save=False, ping_after_power_save=False, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated)
        state_code = con_obj.get_latest_state_code()[-1]
        con_obj.verify_state_code(state_code, expected='0x80')

        wifi_dut.interfaces.wifi.sl_net_init(mode="ap", stats_arg=1)
        con_obj.http_server_provisioning(sl_collections, wifi_dut, wifi_clients,
                                                                    wiseconnect_web,
                                                                    webpage, channel, wifi_access_point,
                                                                    ssid="SILABS_AP_MODE", security="WPA2",
                                                                    psk="Automation@123")
        wifi_clients[0].interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
