import re
import uuid
from datetime import datetime
import time
from typing import Dict
from random import randint
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
    Si91xCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import string
import random

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

webpage1 = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" 
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


webpage2 = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" 
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
value="Open">Open</option><option value="wpa3_transition">wpa3_transition</option><option value=
"WPA2">WPA2</option></select></div><input type="submit" 
value="Connect"></form></div><script>document.getElementById('connect-form').addEventListener('submit', 
function (event) {event.preventDefault();var xhr = new XMLHttpRequest();xhr.open('POST', '/connect', 
true);xhr.setRequestHeader('Content-Type', 'application/json');var id = document.getElementsByName('ssid')[
0].value;var password = document.getElementsByName('password')[0].value;var securityType = document.getElementById(
'security-type').value;console.log('SSID: ' + id);console.log('Password: ' + password);console.log('Security Type: ' 
+ securityType);var data = {id: id,password: password,securityType: securityType};xhr.send(JSON.stringify(
data));});</script></body></html>'''

def logger():
    return get_logger(__name__)


class http_server_provisioning(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None, wiseconnect_web=None, ap_channel=None,wifi_access_point=None,sl_collections=None, APUT_ssid="SILABS_AP_MODE", APUT_security="WPA2",
                 APUT_psk="Automation@123", power_save=True, ping_after_power_save=True, testcase=None, webpage=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.wiseconnect_web = wiseconnect_web
        self.ap_channel = ap_channel
        self.wifi_access_point = wifi_access_point
        self.credentials = None
        self.ssid = APUT_ssid
        self.security=APUT_security
        self.psk=APUT_psk
        self.power_save = power_save
        self.ping_after_power_save = ping_after_power_save
        self.dut_sta_ip = None
        self.testcase = testcase
        self.webpage = webpage

    def join_to_ap(self, ssid, passphrase, security, ping_count=10, mode='power_save_low_latency', dtim_aligned_type=0,
                   num_of_dtim_skip=0, listen_interval=1000, monitor_interval=50):
        join_status = False
        if self.testcase == "694947":
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                    Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        if self.testcase == "783506":
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)

        for count in range(3):
            try:
                logger().info(f"DUT Joining to 3rd party AP using credentials --> {ssid}:{passphrase}:{security}")
                self.wifi_dut.interfaces.wifi.join(ssid=ssid, passphrase=passphrase, security=security,
                                              timeout=60)
                join_status = True
                break
            except Exception as error:
                logger().info(f"Joining to AP failed:{error}, retry_count...{count}")
                time.sleep(10)
        assert join_status, "Failed to join to 3rd party AP"
        ip_config = self.sl_collections.configure_ip(self.wifi_dut, retry_count=3, timeout=120)[-1]
        dut_sta_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info("Pinging to DUT")
        status = self.sl_collections.ping(device_ip=dut_sta_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"

        if self.power_save:
            logger().info(f"....Applying performance profile mode : {mode}")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip,
                                                             listen_interval, monitor_interval)
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            if self.ping_after_power_save:
                logger().info("....Pinging DUT after power-save....")
                status = self.sl_collections.ping(device_ip=dut_sta_ip, ping_count=ping_count)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        return dut_sta_ip

    def set_opermode_client(self):
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANBLE,
            features=Si91xFeatureBitMap.Default,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client,
            config_features= Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            custom_features= Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
            ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
            ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            bt_features= 0,
            ble_features= 0,
            ble_custom_ext_features= 0,)

    def set_opermode_ap(self):
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.AccessPoint,
            coex_mode=Si91xCoexMode.WLANBLE,
            features= Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Server,
            custom_features= Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            ext_custom_features=Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
            ext_tcpip_features=0,
            config_features=0,
            bt_features= 0,
            ble_features= 0,
            ble_custom_ext_features= 0,)

    def run(self):
        self.set_opermode_ap()
        self.wifi_dut.interfaces.wifi.init(config_required=False, mode="ap")
        logger().info(" ******************** Starting http server provisioning ******************** ")
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.psk,
                                          channel=self.ap_channel,
                                          dtim_beacon_count="1", beacon_interval="100")
        time.sleep(30)
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=self.webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()

        # Connect the client to DUT-AP
        logger().info(f" ********** RASPI-STA:'{self.wifi_client.name}' is joining to DUT-AP ********** ")
        self.wifi_client.interfaces.wifi.join()
        dut_as_ap_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"RASPI-STA:'{self.wifi_client.name}' is successfully connected to DUT-AP")
        logger().info(f"Initiating wlan ping from client '{self.wifi_client.name}' to DUT")
        client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c 5 {dut_as_ap_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

        if self.testcase == "783506":
            security = SecurityMode.WPA3Transition
        else:
            security = self.wifi_access_point.interfaces.wifi.security
        self.wiseconnect_web.interfaces.wiseconnect_ui.connect(ip_address=dut_as_ap_ip, web_ui_port=80,
                                                          ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                          security=security,
                                                          passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
        data = self.wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)

        logger().info(f"credenatils from webpage: {data}")
        self.credentials = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        logger().info(f"credenatils: {self.credentials}")
        assert self.credentials, "Unable to fetch 3rd party AP details from DUT"
        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()
        self.wifi_dut.interfaces.wifi.deinit()

        self.set_opermode_client()
        self.wifi_dut.interfaces.wifi.init(timeout=20, config_required=False)
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=1)

        self.dut_sta_ip = self.join_to_ap(self.credentials[1], self.credentials[2], self.credentials[3].lower())

pytestmark = [
    pytest.mark.config("wifi_dut", wifi = {"thread_config": {"wifi": {"count": 1, "stack_len": 4096}},})
]

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
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": SecurityMode.Open, "channel": 1, "ssid": 'ThirdPartyAP'})
def test_wifi_provisioning_via_ap_open_c667576(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point in OPEN security
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                    wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel, webpage=webpage2)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": SecurityMode.Open,
        "ssid": "SILABS_AP_MODE",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config("wifi_dut",  wifi={"security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 1})
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test1234'})
def test_wifi_provisioning_via_ap_WPA2_c694946(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point with APUT in WPA2 mode and third party AP in WPA2 mode
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel,
                                                APUT_ssid="SILABS_AP_MODE", APUT_security="Open", webpage=webpage1)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
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
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test1234'})
def test_wifi_provisioning_via_ap_loop_c667577(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point in WPA2 security and APUT in WPA2 mode in LOOP
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel, webpage=webpage1, testcase="667577")

        for i in range(5):
            logger().info(f" \n ****************************************  Iteration {i+1} **************************************** \n")
            provision_obj.start()
            provision_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.deinit()
            time.sleep(10)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
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
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test1234'})
def test_wifi_provisioning_via_ap_WPA3_c694947(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point in WPA3 security and APUT in WPA2 mode
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel, testcase="694947", webpage=webpage1)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
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
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test1234'})
def test_wifi_provisioning_via_ap_WPA3Transition_c783506(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point in WPA3Transition security and APUT in WPA2 mode
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel, testcase="783506", webpage=webpage2)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
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
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test123456789012345678901234567890'})
def test_wifi_provisioning_via_ap_psk_len_more_than_32_c780931(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point with PSK length more than 32 bytes
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel, webpage=webpage1)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": SecurityMode.Open,
        "ssid": "SILABS_AP_MODE",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config("wifi_dut",  wifi={"security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 1})
@pytest.mark.parametrize("channel", [1])
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": SecurityMode.WPAWPA2MixedMode, "channel": 1, "ssid": 'ThirdPartyAP', 'passphrase': 'test1234'})
def test_wifi_provisioning_via_ap_mixed_mode_c789510(wifi_dut, wifi_client, channel, wifi_access_point,
                                                                 wiseconnect_web, request, wifi_sniffer, sl_collections):
    """
    Verify wi-fi provisioning via Access Point in WPAWPA2MixedMode
    """
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        provision_obj = http_server_provisioning(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                                wiseconnect_web=wiseconnect_web, wifi_access_point=wifi_access_point, ap_channel=channel,
                                                APUT_ssid="SILABS_AP_MODE", APUT_security="Open", webpage=webpage1)

        provision_obj.start()
        provision_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
