import time
import binascii
import hashlib
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.wifi import SecurityMode

"""
    setup requirement:
        1. Soc
        2. Access Point
        3. Raspberry PI4
        4. NUC

    Test Steps:
        1. Configure the DUT in wlan coex mode for 2.4Ghz
        2. Initiate ble in DUT 
        3. Configure the DUT with the gatt services
        4. Initiate the ble client and connect to the DUT
        5. Credentials are sent from the client to the DUT
        6. DUT will scan list of available networks
        7. DUT will connect to the network with the credentials received from the client
        8. Validate the Acknowledgement from the DUT

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
value="WPA">WPA</option><option value="WPA2">WPA2</option><option value="WPA3">WPA3</option><option value="Mixed Mode">
Mixed Mode</option></select></div><input type="submit" 
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
value="Open">Open</option><option value="WPA2WPA3MixedMode">WPA2WPA3MixedMode</option><option value=
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

class ProvisioningFunctionality(ThreadBase):
    ip_dict = {}
    def __init__(self, wifi_dut=None, sl_collections=None, test_case=None,
                     utf_constants=None, wifi_access_point=None, wifi_sniffer=None, wifi_access_points=None, device_ip=None,dut_mac_address=None,
                     ssid=None, security=None, psk=None, set_smp=None, ble_dut=None, webpage=webpage1,
                     ap_channel=None, wiseconnect_web=None, result=None, wifi_clients=None,sniffer_filter=None, power_save=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_points = wifi_access_points
        self.device_ip = device_ip
        self.dut_mac_address = dut_mac_address
        self.ssid = ssid
        self.security = security
        self.psk = psk
        self.ap_channel = ap_channel
        self.ble_dut = ble_dut
        self.set_smp = set_smp
        self.wiseconnect_web = wiseconnect_web
        self.result = result
        self.wifi_clients = wifi_clients
        self.sniffer_filter = sniffer_filter
        self.no_of_clients = 1
        self.power_save = power_save
        self.webpage = webpage
        self.ap_addr = None
        self.dut_addr = None

        logger().info("******************** initializing ble in dut ********************")
        self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)


    def run(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

    def sl_net_deinit(self):
        self.wifi_dut.interfaces.wifi.deinit(mode="ap")

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")
        self.ap_addr = self.wifi_access_point.interfaces.wifi.bssid
        self.dut_addr = self.wifi_dut.interfaces.wifi.get_mac_address()

    def wifi_disconnect(self):
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("....Successfully disconnected from the AP....")

    def ble_start_advertising(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

    def ble_stop_advertising(self):
        logger().info("Device is in advertising status try to stop advertising")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()

    def check_beacon(self):
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr, filter_name='beacon')
        logger().info(f"***** Validating beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "No beacon found in sniffer"

    def scan_on_ap_interface(self):
        scan_result_ssid_security = []
        logger().info("******* scanning on AP interface ********")
        scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap")

        for scan in scan_results:
            ssid = re.findall(r"((?<=ssid:\s)[\w\W]+?(?=\sbssid))", str(scan))
            security = re.findall(r"((?<=security_mode:\s)\d+)", str(scan))
            scan_result_ssid_security.append((ssid[0], security[0]))

        logger().info(f".... scan result for ssid and security is : {scan_result_ssid_security} ....")

    def connect_clients_to_dut_as_ap(self):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.get_channel_info(interface='ap')
        for i in range(0, self.no_of_clients):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=0)

            time.sleep(5)
            ProvisioningFunctionality.ip_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {ProvisioningFunctionality.ip_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    ProvisioningFunctionality.ip_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {ProvisioningFunctionality.ip_dict['rasp_mac_address']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} -I wlan0 {'192.168.100.76'}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

    def http_server_provisioning(self):
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=self.webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        self.connect_clients_to_dut_as_ap()
        self.ble_stop_advertising()

        self.scan_on_ap_interface()
        self.wiseconnect_web.interfaces.wiseconnect_ui.connect(
            ip_address="192.168.100.76", web_ui_port=80,
            ssid=self.wifi_access_point.interfaces.wifi.ssid,
            security=self.wifi_access_point.interfaces.wifi.security,
            passphrase=self.wifi_access_point.interfaces.wifi.passphrase)

        # time.sleep(300)
        time.sleep(3)
        data = self.wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        self.result = re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())
        logger().info(f"received cred on dutap: {self.result}")
        assert self.result, "Unable to fetch 3rd party AP details from DUT"
        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()

    def ap_mode_start(self):
        """
        Method to start the DUT as an Access Point.
        """
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(
            ssid=self.ssid, security=self.security, psk=self.psk, channel=self.ap_channel, dtim_beacon_count="1",
            beacon_interval="100")

    def set_wps_config(self):
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
            tcpip_features=Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNS | Si91xTCPIPFeatureBitMap.SSL
                           | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            custom_features=Si91xCustomFeatureBitMap.Default,
            ext_custom_features=Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower,
            ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                10),
            config_features=Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            bt_features=0,
            ble_features=0,
            ble_custom_ext_features=0,
        )

    def set_prov_config(self):
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode= Si91xOperatingMode.AccessPoint,
            coex_mode= Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            features= Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
            tcpip_features= Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                                 Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            custom_features= Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            ext_custom_features= Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                    | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            ext_tcpip_features= Si91xExtTCPIPFeatureBitMap.Default,
            config_features= Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            bt_features= Si91xBTFeatureBitMap.Default,
            ble_features= Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            ble_custom_ext_features= Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                     Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                     Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                     Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                     Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
            )

    def start_wps_path(self):
        logger().info(" ====== Start WPS PBC on Access Point ====== ")
        self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        logger().info(" ====== Start WPS PBC on DUT ====== ")
        data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=True)
        self.verify_response_structure(data)

        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=3)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"\n **** Device IP Address: {self.device_ip} ****\n")
        logger().info(f"\n =========== pinging DUT before power save ===============\n")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            logger().info(f"\n =========== pinging DUT after power save ===============\n")
            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def generate_psk(self):
        ssid = self.wifi_access_point.interfaces.wifi.ssid
        passphrase = self.wifi_access_point.interfaces.wifi.passphrase

        ssid_bytes = ssid.encode('utf-8')
        passphrase_bytes = passphrase.encode('utf-8')

        iterations = 4096
        key_length = 32

        psk_bytes = hashlib.pbkdf2_hmac('sha1', passphrase_bytes, ssid_bytes, iterations, key_length)
        psk_hex = binascii.hexlify(psk_bytes).decode('ascii').upper()
        logger().info(f"\n Generated PSK (hex) using AP ssid and passphrase: {psk_hex} \n")
        return psk_hex

    def verify_response_structure(self, data):
        """This function is responsible for verifying the WPS response structure and validating against AP configuration"""

        required_fields = ['status', 'ssid', 'ssid_length', 'security_type', 'key', 'ap_mac_address', 'reserved']

        for field in required_fields:
            assert field in data, f"{field} field is missing in WPS response structure"
        logger().info(f"\n **** WPS response structure verification completed ****\n")

        ap_ssid = self.wifi_access_point.interfaces.wifi.ssid
        ap_passphrase = self.wifi_access_point.interfaces.wifi.passphrase
        ap_security = self.wifi_access_point.interfaces.wifi.security.name.lower()
        ap_mac = self.wifi_access_point.interfaces.wifi.bssid
        ap_psk = self.generate_psk()

        if self.test_case == "922309":
            ap_security = "wpa2"

        logger().info(f"\n AP Configuration - SSID: {ap_ssid}, Security: {ap_security}, MAC: {ap_mac} \n ")
        security_mapping = {
            'open': '0x00',
            'wpa': '0x01',
            'wpa2': '0x02',
        }
        assert data['ssid'] == ap_ssid, f"SSID mismatch: WPS response '{data['ssid']}' != AP SSID '{ap_ssid}'"
        logger().info(f"SSID validation successful: '{data['ssid']}' matches AP SSID '{ap_ssid}'")

        if ap_security != 'open':
            assert data[
                       'key'].upper() == ap_psk, f"Passphrase mismatch: WPS response key '{data['key']}' != AP PSK '{ap_psk}'"
            logger().info(f"Passphrase validation successful: '{data['key']}' matches AP passphrase")

        assert data['security_type'] == security_mapping.get(
            ap_security), f"Security type mismatch: WPS response '{data['security_type']}' != Expected corresponding AP security '{ap_security}'"
        logger().info(
            f"Security type validation successful: WPS response '{data['security_type']}' matches AP security '{ap_security}'")

        assert data['ap_mac_address'].replace(':', '').upper() == ap_mac.replace(':',
                                                                                 '').upper(), f"MAC address mismatch: WPS response '{data['ap_mac_address']}' != AP MAC '{ap_mac}'"
        logger().info(
            f"AP MAC address validation successful: WPS response '{data['ap_mac_address']}' matches AP MAC '{ap_mac}'")

        assert data['status'] == '0x00000000', f"WPS operation failed with status: {data['status']}"

        logger().info(f"\n **** WPS response validation against AP configuration completed successfully ****\n")

    def negative_sniffer_validation(self, beacon=True, probe_req=True, assoc_req=True, assoc_resp=True):
        logger().info(f"\n ============== WPS Sniffer validation started ============= \n")
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_pbc_beacon')
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_pbc_probe_req')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_assoc_req')
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_assoc_resp')
        if beacon:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Sniffer:Found beacon frame with WPS PBC enabled from AP, but expected not to find'
            logger().info("\n ****************** Beacon frame with WPS PBC not found as expected ****************** \n")

        if probe_req:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count'], \
                'Sniffer:Found probe request frame with WPS PBC enabled from DUT, but expected not to find'
            logger().info(
                "\n ****************** Probe request frame with WPS PBC not found as expected ****************** \n")

        if assoc_req:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                'packet_count'], \
                'Sniffer:Found WPS association request frame from DUT, but expected not to find'
            logger().info(
                "\n ****************** WPS association request frame not found as expected ****************** \n")

        if assoc_resp:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
                'packet_count'], \
                'Sniffer:Found WPS association response frame from AP, but expected not to find'
            logger().info(
                "\n ****************** WPS association response frame not found as expected ****************** \n")


    def wps_pbc_sniffer_validation(self, beacon=True, probe_req=True, assoc_req=True, assoc_resp=True,
                                   power_mgmt_bit=True):
        logger().info(f"\n ============== WPS Sniffer validation started ============= \n")

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_pbc_beacon')
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_pbc_probe_req')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_assoc_req')
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_assoc_resp')
        packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_addr,
                                                                                             da_addr=self.ap_addr,
                                                                                             filter_name='power_mgmt_bit')
        if beacon:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Sniffer: Unable to find beacon frame with WPS PBC enabled from AP'
        if probe_req:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count'], \
                'Sniffer: Unable to find probe request frame with WPS PBC enabled from DUT'
        if assoc_req:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                'packet_count'], \
                'Sniffer: Unable to find WPS association request frame from DUT'
        if assoc_resp:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
                'packet_count'], \
                'Sniffer: Unable to find WPS association response frame from AP'
        if power_mgmt_bit:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
                'packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '


def wifi_dut_marker(wifi_thread=1, IEEE802_11W=0, memory_config=0, OpenMode=0, HiddenSSID=0):
    config = {
        "thread_config": {"wifi": {"count": wifi_thread, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT | OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | HiddenSSID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | IEEE802_11W | memory_config
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    }
    return pytest.mark.config("wifi_dut", wifi=config)



@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
    },
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
def test_wifi_sdk_ap_wps_provisioning_wpa2_security_C922304(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, sniffer_filter, ble_dut):
    """This test case Validates SoftAP+BLE provisioning workflow followed by WPS connection to wpa2 security network with sniffer validation."""

    try:
        test_name = request.node.name
        wifi_clients = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, test_case="922304",
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        provisioning_obj.ap_mode_start()
        provisioning_obj.ble_start_advertising()
        provisioning_obj.firmware_version()
        time.sleep(10)
        provisioning_obj.check_beacon()
        provisioning_obj.http_server_provisioning()
        provisioning_obj.sl_net_deinit()
        provisioning_obj.set_wps_config()
        wifi_dut.interfaces.wifi.init( config_required=False)
        provisioning_obj.start_wps_path()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        provisioning_obj.wps_pbc_sniffer_validation()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()



@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
    },
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": SecurityMode.Open, "passphrase": '123456789', "channel": 11})
def test_wifi_sdk_ap_wps_provisioning_open_security_C922307(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, sniffer_filter, ble_dut):
    """This test case Validates SoftAP+BLE provisioning workflow followed by WPS connection to open security network with sniffer validation."""

    try:
        test_name = request.node.name
        wifi_clients = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security="wpa2", psk='123456789', ap_channel=ap_channel, test_case="922307",
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, webpage=webpage2)

        provisioning_obj.ap_mode_start()
        provisioning_obj.ble_start_advertising()
        provisioning_obj.firmware_version()
        time.sleep(10)
        provisioning_obj.check_beacon()
        provisioning_obj.http_server_provisioning()
        provisioning_obj.sl_net_deinit()
        provisioning_obj.set_wps_config()
        wifi_dut.interfaces.wifi.init( config_required=False)
        provisioning_obj.start_wps_path()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        provisioning_obj.wps_pbc_sniffer_validation()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
    },
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sharma123', "security": 'WPA2WPA3MixedMode', "passphrase": '123456789', "channel": 11, 'protected_management_frame': 'Capable'})
def test_wifi_sdk_ap_wps_provisioning_wpa2_wpa3_security_C922309(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, sniffer_filter, ble_dut):
    """This test case Validates SoftAP+BLE provisioning workflow followed by WPS connection to wpa2/wpa3Mixed security network with sniffer validation."""

    try:
        test_name = request.node.name
        wifi_clients = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security="wpa2", psk='123456789', ap_channel=ap_channel, test_case="922309",
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        provisioning_obj.ap_mode_start()
        provisioning_obj.ble_start_advertising()
        provisioning_obj.firmware_version()
        time.sleep(10)
        provisioning_obj.check_beacon()
        provisioning_obj.http_server_provisioning()
        provisioning_obj.sl_net_deinit()
        provisioning_obj.set_wps_config()
        wifi_dut.interfaces.wifi.init( config_required=False)
        provisioning_obj.start_wps_path()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        logger().info("\n ====== Validate Beacon frame with PMF capable in Sniffer Capture ====== \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=provisioning_obj.ap_addr,
                                                                                        filter_name="beacon_pmf")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find beacon frame with PMF capable'
        provisioning_obj.wps_pbc_sniffer_validation()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()



@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
    },
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
def test_wifi_sdk_ap_wps_provisioning_loop_C922310(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, sniffer_filter, ble_dut):
    """This test case will run in a loop for multiple iterations to Validate SoftAP+BLE provisioning workflow followed by WPS connection to wpa2 security network with sniffer validation."""

    try:
        test_name = request.node.name
        wifi_clients = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, test_case="922310",
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        for i in range(2):
            logger().info(f"\n ====== BLE + Soft AP + WPS provisioning loop count: {i + 1} ====== \n")
            if i != 0:
                provisioning_obj.set_prov_config()
                wifi_dut.interfaces.wifi.init(config_required=False)
                logger().info("******************** initializing ble in dut ********************")
                ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)

            provisioning_obj.ap_mode_start()
            provisioning_obj.ble_start_advertising()
            provisioning_obj.firmware_version()
            time.sleep(10)
            provisioning_obj.check_beacon()
            provisioning_obj.http_server_provisioning()
            provisioning_obj.sl_net_deinit()
            provisioning_obj.set_wps_config()
            wifi_dut.interfaces.wifi.init(config_required=False)
            provisioning_obj.start_wps_path()
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.deinit(mode="client")
            time.sleep(10)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        provisioning_obj.wps_pbc_sniffer_validation()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
    },
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
def test_wifi_sdk_ap_wps_provisioning_failure_no_AP_C922305(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, sniffer_filter, ble_dut):
    """ This test case validates the negative scenario of WPS provisioning workflow where DUT should not connect to AP when WPS PBC is initiated on DUT but not on AP.
    Sniffer validation is also included to validate the absence of WPS frames in the air. """
    try:
        test_name = request.node.name
        wifi_clients = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, test_case="922308",
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        provisioning_obj.ap_mode_start()
        provisioning_obj.ble_start_advertising()
        provisioning_obj.firmware_version()
        time.sleep(10)
        provisioning_obj.check_beacon()
        provisioning_obj.http_server_provisioning()
        provisioning_obj.sl_net_deinit()
        provisioning_obj.set_wps_config()
        wifi_dut.interfaces.wifi.init( config_required=False)
        logger().info("\n ====== Do not start WPS PBC on Access Point and Start WPS PBC on DUT====== \n")
        wifi_dut.interfaces.wifi.start_client_wps(auto_connect=True,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_ASSOCIATION_TIMEOUT_IN_P2P_WPS_MODE)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        provisioning_obj.wps_pbc_sniffer_validation(beacon=False, probe_req=True, assoc_req=False, assoc_resp=False,
                                           power_mgmt_bit=False)
        provisioning_obj.negative_sniffer_validation(beacon=True, probe_req=False, assoc_req=True, assoc_resp=True)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()

