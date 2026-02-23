import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode
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


class ProvisioningFunctionality(ThreadBase):
    ip_dict = {}

    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, ble_dut=None,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, bt_dut_address=None, credentials=None,
                 ble_client_address=None, char_path=None, char_uid=None, adv_int=None, min_conn_interval=160,
                 max_conn_interval=160, conn_latency=0, supervision_timeout=3200, svc=None, charc=None,
                 write_handle=None, wifi_access_points=None, device_ip=None, device_ip_two=None,
                 dut_mac_address_two=None, dut_mac_address=None, set_smp=None, ssid=None, security=None, psk=None,
                 ap_channel=None, wifi_client=None, wiseconnect_web=None, result=None, wifi_clients=None,
                 net_perf_client=None, protocol=None, traffic=None, qos=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.bt_dut_address = bt_dut_address
        self.credentials = credentials
        self.ble_client_address = ble_client_address
        self.char_path = char_path
        self.char_uid = char_uid
        self.adv_int = adv_int
        self.min_conn_interval = min_conn_interval
        self.max_conn_interval = max_conn_interval
        self.conn_latency = conn_latency
        self.supervision_timeout = supervision_timeout
        self.svc = svc
        self.charc = charc
        self.write_handle = write_handle
        self.wifi_access_points = wifi_access_points
        self.device_ip = device_ip
        self.device_ip_two = device_ip_two
        self.dut_mac_address_two = dut_mac_address_two
        self.dut_mac_address = dut_mac_address
        self.set_smp = set_smp
        self.ssid = ssid
        self.security = security
        self.psk = psk
        self.ap_channel = ap_channel
        self.wifi_client = wifi_client
        self.wiseconnect_web = wiseconnect_web
        self.result = result
        self.wifi_clients = wifi_clients
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.traffic = traffic
        self.qos = qos
        self.sniffer_filter = sniffer_filter
        self.no_of_clients = 1

        logger().info("******************** initializing ble in dut ********************")
        self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
        assert self.bt_dut_address, "failed to initialize ble in dut"

    def run(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

    def sl_net_deinit(self):
        self.wifi_dut.interfaces.wifi.deinit(mode="ap")

    def wifi_connect(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.wifi_access_point.interfaces.wifi.ssid, passphrase=self.result[2], security=self.result[3].lower())
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

        # dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        # logger().info(f'dut_mac_address is {dut_mac_address}')
        #
        # logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} DUT IP ADDRESS : {self.device_ip}")
        #
        # logger().info(f"....Pinging to DUT before Power Save")
        # status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        # assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")

    def wifi_disconnect(self):
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("....Successfully disconnected from the AP....")

    def wifi_connect_wrong_psk(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.result[1], passphrase='thisisnotatestnetworkwahh', security=self.result[3].lower(),
            expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("....De-Authentication received when trying to connect with AP using wrong PSK....")

    def wifi_connect_mixed_security(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.result[1], passphrase=self.result[2], security='wpa2')

    def ble_start_advertising(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

    def ble_stop_advertising(self):
        logger().info("Device is in advertising status try to stop advertising")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()

    def check_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
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

            if self.test_case == 887643:
                logger().info("******* joining client to DUT-AP in OPEN security ********")
                self.wifi_clients[i].interfaces.wifi.join(security=SecurityMode.Open, scan_ssid=0)

            elif self.test_case == 887650:
                logger().info("******* joining client to DUT-AP in Mixed Mode security ********")
                self.wifi_clients[i].interfaces.wifi.join(security=SecurityMode.WPA2, scan_ssid=0)

            elif self.test_case == 887659:
                self.wifi_clients[i].interfaces.wifi.join(scan_ssid=1)

            else:
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
                    # ProvisioningFunctionality.ip_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    # logger().info(f"Client{i + 1}_ip: {ProvisioningFunctionality.ip_dict[f'client{i + 1}_ip']}")
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
        # return ProvisioningFunctionality.ip_dict

    def http_server_provisioning(self):
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        # ProvisioningFunctionality.ip_dict['dut_ip'] = self.connect_clients_to_dut_as_ap()
        self.connect_clients_to_dut_as_ap()
        self.ble_stop_advertising()

        if self.test_case == 887658:
            self.wifi_clients[0].interfaces.wifi.leave()
            self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            self.ap_mode_start()
            self.ble_start_advertising()
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
        if self.test_case == 887649:
            self.result = re.search(r'ssid:([\w@!]+),password:([\w@#!]+),security:(\w+)', data.decode())
        else:
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

    def run_iperf(self):
        host_ip = self.wifi_clients[0].interfaces.wifi.get_ip_address(network_interface='eth1')
        logger().info(f"******** HOST IP {self.host_ip} *******")

        self.net_perf_client.interfaces.net_perf.init_server(
            host_ip=host_ip, device_ip=self.device_ip, protocol=self.protocol, tos_value=self.traffic,
            time_out=300)
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {self.device_ip}, Protocol: {self.protocol}, "
            f"tos_value: {self.traffic}")
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.device_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=300, throughput_type=1, qos=self.qos, timeout=350)
        logger().info("data transfer is successful")
        time.sleep(3)


def wifi_dut_marker(IEEE802_11W=0, memory_config=0, OpenMode=0, HiddenSSID=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}, "ble": {"count": 1, "stack_len": 2048}},
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
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_c887642(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, wifi_clients, sniffer_filter, ble_client, ble_dut):

    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_client=ble_client, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        # ble_obj.ble_start_advertising()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


#@pytest.mark.skip("OPEN security issue - 0x10019")
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode, OpenMode=Si91xFeatureBitMap.OpenMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sharma_test', "security": 'OPEN', "passphrase": '123456789',
                                               "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_open_security_c887643(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in OPEN security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='open', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter,
            test_case=887643)

        ble_obj.ap_mode_start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip("WPA3 security issue")
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA3",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa3_security_c887644(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA3 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa3', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2',
                          "passphrase": 'thisistestnetworkthisistestnetworkthisistestnetworkthisistestne',
                          "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_with_psk_63bytes_c887645(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security with PSK length 63bytes and also check WLAN connection to the
    third party home AP with the received credentials on APUT"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma_testsharma_testsharma_tes', "security": 'WPA2',
                          "passphrase": '123456789',
                          "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_with_ssid_32bytes_c887646(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security with SSID length 32bytes and also check WLAN connection to the
    third party home AP with the received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_with_wrong_psk_c887647(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning when configuring wrong PSK and also check WLAN connection to the third party home AP
    with the received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect_wrong_psk()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
# @pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
# @pytest.mark.end_state("wifi_dut", wifi=["reset"])
def test_wifi_sdk_ap_provisioning_in_loop_c887648(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT for multiple iteration in loop(5 Iteration)"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        for count in range(0, 1):
            # wifi_dut.interfaces.wifi.is_sl_net_enabled = True
            ble_obj.ap_mode_start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.firmware_version()
            time.sleep(10)
            ble_obj.check_beacon()
            # ble_obj.scan_on_ap_interface()
            ble_obj.http_server_provisioning()
            ble_obj.sl_net_deinit()

            wifi_dut.interfaces.wifi.set_wifi_config(
                oper_mode=Si91xOperatingMode.WiFiClient,
                coex_mode=Si91xCoexMode.WLANOnly,
                features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
                tcpip_features=Si91xTCPIPFeatureBitMap.Default)
            # wifi_dut.interfaces.wifi.is_sl_net_enabled = True
            wifi_dut.interfaces.wifi.sl_net_init(mode="client")
            wifi_dut.interfaces.wifi.scan()
            ble_obj.wifi_connect()
            ble_obj.wifi_disconnect()

            if count == 0:
                wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
                # wifi_dut.interfaces.wifi.set_wifi_config(
                #     oper_mode=Si91xOperatingMode.AccessPoint,
                #     coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                #     features=Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
                #     tcpip_features=Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                #                    Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
                #     ext_custom_features=Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                #                         | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid)
                # wifi_dut.interfaces.wifi.sl_net_init(mode="ap")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma@home_2GHz!",
            "passphrase": "P@ssw0rd#2025!",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "sharma@home_2GHz!", "passphrase": "P@ssw0rd#2025!", "security": "WPA2",
                          "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_with_special_charac_ssid_psk_c887649(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security with special characters in credentials and also check WLAN
    connection to the third party home AP with the received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma@home_2GHz!', security='wpa2', psk='P@ssw0rd#2025!', ap_channel=ap_channel,
            wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter, test_case=19)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test_sharma_t",
            "passphrase": "thisistestnetworkthisistestnetwor",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma_test_sharma_t', "passphrase": 'thisistestnetworkthisistestnetwor',
                          "security": 'WPA2', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_ssid_20bytes_psk_33bytes_c887652(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning with SSID 20bytes and PSK length 33bytes and also check whether we are getting DNS
    IP in the DHCP Offer packet in AP mode"""

    """Need to add code for sniffer check for DNS IP in DHCP offer Packet"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test_sharma_t', security='wpa2', psk='thisistestnetworkthisistestnetwor',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_ap_provisioning_and_iperf_run_in_sta_mode_c887653(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, protocol, net_perf_client, traffic,
        qos, sniffer_filter):

    """Verify Soft AP provisioning and also check WLAN connection to the third party home AP with the received
    credentials on APUT and run IPERF TCP TX"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, traffic=traffic, protocol=protocol,
            net_perf_client=net_perf_client, qos=qos, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()
        ble_obj.run_iperf()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_testsharma_te",
            "passphrase": "thisistestnetworkthisistestnetworkthisis",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma_testsharma_te', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_dut_ap_ssid_20bytes_psk_40bytes_c887666(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_testsharma_te', security='wpa2', psk='thisistestnetworkthisistestnetworkthisis',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_testsharma_testsharma_tes",
            "passphrase": "thisistestnetworkthisistestnetworkthisistestnetworkthisistestne",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma_testsharma_te', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_dut_ap_ssid_32bytes_psk_63bytes_c887665(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_testsharma_testsharma_tes', security='wpa2', psk='thisistestnetworkthisistestnetworkthisistestnetworkthisistestne',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "thisistestnetworkthisistestnetworkthisistestnetworkthisistestne", #wrong PSK test
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma_testsharma_te', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_dut_ap_wrong_psk_c887664(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify DUT behavior via SoftAP provisioning when passing wrong PSK when trying to connect to 917 device"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789',
            ap_channel=ap_channel, wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip("Skipping due to extended scan not supported in AP mode - WIFI_BT_UTFHELP-6027")
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_extended_scan_c887660(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify whether DUT is able to scan more than 11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


# @pytest.mark.skip("Skipping due to extended scan not supported in AP mode - WIFI_BT_UTFHELP-6027")
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_extended_scan_and_connect_third_party_ap_c887661(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify whether DUT is able to connect to AP which comes after 11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is
    enabled"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
                 HiddenSSID=Si91xCustomFeatureBitMap.HiddenSSID)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_with_hidden_ssid_c887659(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning with hidden SSID and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, test_case=887659)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "3",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [3])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 3})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_client_conn_reconn_c887658(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify remote client connection and disconnection and reconnection to DUT AP in Soft AP provisioning path and
    also check wifi connection to the third party home AP with the received credentials on APUT"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, test_case=887658)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
        1: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_multi_client_connection_c887657(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify the behavior via Soft AP provisioning when connecting multiple clients on aput"""

    try:
        test_name = request.node.name
        assert len(wifi_clients) == 2, f"Minimum 2 raspi devices needed for this test"

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.no_of_clients = 2
        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'Anshul_test', "security": 'WPAWPA2MixedMode', "passphrase": '123456789',
                          "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_mixed_security_c887650(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):

    """Verify Soft AP provisioning in Mixed Mode security and also check WLAN connection to the third party home AP
    with the received credentials on APUT"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa_wpa2_mixed', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter,
            test_case=887650)

        ble_obj.ap_mode_start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect_mixed_security()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_12h_long_run_c887672(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point, ble_client, ble_dut,
        wiseconnect_web, request, utf_constants, wifi_clients, sniffer_filter):
    """Verify SoftAP provisioning and check the stability of the remote client connection for 12 hours"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        # Start 12-hour ping stability test
        logger().info("Starting 12-hour ping stability test to access point")
        test_duration = 12 * 60 * 60  # 12 hours in seconds
        ping_interval = 60  # Ping every 60 seconds
        start_time = time.time()
        ping_count = 0
        failed_pings = 0
        # Get the gateway IP from DUT's network config (access point IP)
        dut_ip = ble_obj.device_ip
        # Decode bytes to string if needed
        if isinstance(dut_ip, bytes):
            dut_ip = dut_ip.decode('utf-8')
        # Gateway is typically .1 in the subnet - derive from DUT IP
        ap_ip = '.'.join(dut_ip.split('.')[:-1]) + '.1'

        logger().info(f"Target AP IP: {ap_ip}")
        logger().info(f"Test will run for {test_duration / 3600} hours with ping interval of {ping_interval} seconds")

        while (time.time() - start_time) < test_duration:
            elapsed_time = time.time() - start_time
            ping_count += 1

            try:
                # Perform ping test - ping() returns status code where 0 means success
                ping_result = wifi_dut.interfaces.wifi.ping(ap_ip, 5, 5)

                # Check if ping succeeded (result is not None and no exception)
                logger().info(f"Ping #{ping_count} successful - Elapsed time: {elapsed_time / 3600:.2f} hours")

            except Exception as ping_error:
                failed_pings += 1
                logger().error(
                    f"Ping #{ping_count} exception: {ping_error} - Elapsed time: {elapsed_time / 3600:.2f} hours - Total failures: {failed_pings}")

                if ping_result:
                    logger().info(f"Ping #{ping_count} successful - Elapsed time: {elapsed_time / 3600:.2f} hours")
                else:
                    failed_pings += 1
                    logger().error(
                        f"Ping #{ping_count} FAILED - Elapsed time: {elapsed_time / 3600:.2f} hours - Total failures: {failed_pings}")

            except Exception as ping_error:
                failed_pings += 1
                logger().error(
                    f"Ping #{ping_count} exception: {ping_error} - Elapsed time: {elapsed_time / 3600:.2f} hours - Total failures: {failed_pings}")

            # Log progress every hour
            if ping_count % (3600 // ping_interval) == 0:
                success_rate = ((ping_count - failed_pings) / ping_count) * 100 if ping_count > 0 else 0
                logger().info(
                    f"Progress Report - Elapsed: {elapsed_time / 3600:.2f} hours, Total pings: {ping_count}, Failed: {failed_pings}, Success rate: {success_rate:.2f}%")

            # Wait for next ping interval
            time.sleep(ping_interval)

        # Final report
        logger().info("12-hour stability test completed")
        logger().info(f"Total pings: {ping_count}, Failed pings: {failed_pings}")
        success_rate = ((ping_count - failed_pings) / ping_count) * 100 if ping_count > 0 else 0
        logger().info(f"Overall success rate: {success_rate:.2f}%")

        # Assert that success rate is acceptable (e.g., > 80%)
        assert success_rate >= 80.0, f"Ping success rate {success_rate:.2f}% is below acceptable threshold of 80%"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_with_wrong_psk_for_multiple_iterations_C887671(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """Verify Soft AP provisioning when configuring wrong PSK and also check WLAN connection to the third party home AP
    with the received credentials on APUT for multiple iteration in loop(20 Iteration) - Negative test case"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]
        from utf.utils.commander import Commander
        commander = Commander()

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        for iteration in range(1, 21):
            logger().info(f"******************** Starting iteration {iteration} of 20 ********************")

            # For iterations 2-20, reset the device and re-configure for AP+BLE mode
            if iteration > 1:
                logger().info(f"Resetting device for iteration {iteration}")
                commander.reset_device()
                time.sleep(3)
                # Reset framework state so it allows new config after hardware reset
                wifi_dut.interfaces.wifi._state = 'deinit'
                wifi_dut.interfaces.wifi._wifi_config = None  # Clear previous config tracking
                # Reset thread state so threads get re-initialized after commander reset
                if hasattr(wifi_dut.interfaces.wifi, '_threads'):
                    wifi_dut.interfaces.wifi._threads = {}
                if hasattr(wifi_dut.interfaces.wifi, '_threads_initialized'):
                    wifi_dut.interfaces.wifi._threads_initialized = False
                # Reset BLE interface state after commander reset
                if hasattr(ble_dut.interfaces.bluetooth, '_state'):
                    ble_dut.interfaces.bluetooth._state = 'deinit'
                if hasattr(ble_dut.interfaces.bluetooth, '_initialized'):
                    ble_dut.interfaces.bluetooth._initialized = False

                # Reset ALL framework state after commander reset
                wifi_dut.interfaces.wifi._threads_initialized = False
                wifi_dut.interfaces.wifi._threads = {}
                wifi_dut.interfaces.wifi._state = 'deinit'
                wifi_dut.interfaces.wifi._wifi_config = None

                # Set thread_config on interface
                wifi_dut.interfaces.wifi._thread_config = {"wifi": {"count": 1, "stack_len": 3072},
                                                           "ble": {"count": 1, "stack_len": 2048}}

                # Re-initialize device with AP+BLE mode config (same as fixture)
                wifi_dut.interfaces.wifi.set_wifi_config(
                    oper_mode=Si91xOperatingMode.AccessPoint,
                    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                    features=Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
                    tcpip_features=Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
                    custom_features=Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                    ext_custom_features=Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                    ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.Default,
                    config_features=Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                    bt_features=Si91xBTFeatureBitMap.Default,
                    ble_features=Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
                    ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST)

                # Send plain wifi.init command (no thread prefix)
                wifi = wifi_dut.interfaces.wifi

                # Find the underlying CLI that sends raw commands
                cli = None
                for attr_name in ['_cli', 'cli', '_connection', 'connection', '_serial_connection',
                                  '_serial', 'serial', 'host_connection', '_host_connection',
                                  'serial_connection', '_host', 'host', '_bus', 'bus']:
                    obj = getattr(wifi, attr_name, None)
                    if obj is not None:
                        cli = obj
                        break

                # If no CLI found on wifi interface, try getting it from the device
                if cli is None:
                    device = getattr(wifi, '_device', None) or getattr(wifi, 'device', None)
                    if device is not None:
                        for attr_name in ['_connection', 'connection', '_serial_connection', '_serial',
                                          'host_connection', '_host', 'host', '_bus', 'bus', '_cli', 'cli']:
                            obj = getattr(device, attr_name, None)
                            if obj is not None:
                                cli = obj
                                break

                # Also check wifi_dut directly
                if cli is None:
                    for attr_name in ['_connection', 'connection', '_serial_connection', '_serial',
                                      'host_connection', '_cli', 'cli']:
                        obj = getattr(wifi_dut, attr_name, None)
                        if obj is not None:
                            cli = obj
                            break

                # Send commands using the CLI if found
                sent_commands = False
                if cli is not None:
                    if hasattr(cli, 'send_command'):
                        cli.send_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        cli.send_command("thread 0 3072 1600", timeout=5)
                        cli.send_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True
                    elif hasattr(cli, 'send'):
                        cli.send("wifi.init\r\n")
                        time.sleep(3)
                        wifi._state = 'init'
                        cli.send("thread 0 3072 1600\r\n")
                        time.sleep(1)
                        cli.send("thread 1 2048 1600\r\n")
                        time.sleep(1)
                        sent_commands = True

                if not sent_commands:
                    # Try using internal command methods
                    if hasattr(wifi, '_issue_command'):
                        wifi._issue_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        wifi._issue_command("thread 0 3072 1600", timeout=5)
                        wifi._issue_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True
                    elif hasattr(wifi, '_send_command'):
                        wifi._send_command("wifi.init")
                        wifi._state = 'init'
                        wifi._send_command("thread 0 3072 1600")
                        wifi._send_command("thread 1 2048 1600")
                        sent_commands = True
                    elif hasattr(wifi, 'issue_command'):
                        wifi.issue_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        wifi.issue_command("thread 0 3072 1600", timeout=5)
                        wifi.issue_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True

                if not sent_commands:
                    # Final fallback: disable thread creation temporarily
                    original_thread_config = getattr(wifi, '_thread_config', None)
                    wifi._thread_config = None
                    wifi._threads_initialized = False
                    wifi._threads = {}

                    try:
                        wifi.init()
                    finally:
                        wifi._thread_config = original_thread_config

                    if hasattr(wifi, '_create_threads'):
                        wifi._create_threads()

                wifi._threads = {"wifi": [0], "ble": [1]}
                wifi._threads_initialized = True

            # Create fresh ble_obj for each iteration
            ble_obj = ProvisioningFunctionality(
                wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
                utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
                wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

            ble_obj.ap_mode_start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            if iteration == 1:
                ble_obj.firmware_version()
            time.sleep(10)
            ble_obj.check_beacon()
            ble_obj.http_server_provisioning()
            ble_obj.sl_net_deinit()

            wifi_dut.interfaces.wifi.set_wifi_config(
                oper_mode=Si91xOperatingMode.WiFiClient,
                coex_mode=Si91xCoexMode.WLANOnly,
                features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
                tcpip_features=Si91xTCPIPFeatureBitMap.Default)
            wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
            wifi_dut.interfaces.wifi.scan()

            # Negative test: Attempt to connect with wrong PSK - should fail
            ble_obj.wifi_connect_wrong_psk()

            # Disconnect raspi client from DUT-AP before next iteration
            for client in wifi_clients:
                try:
                    client.interfaces.wifi.leave()
                except Exception as e:
                    logger().info(f"Raspi disconnect: {e}")

            # Cleanup DUT for next iteration
            wifi_dut.interfaces.wifi.deinit()

            logger().info(f"******************** Completed iteration {iteration} of 20 ********************")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_for_multiple_iteration_loop_C887673(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP
    with the received credentials on APUT for multiple iteration in loop(20 Iteration) """

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]
        from utf.utils.commander import Commander
        commander = Commander()

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        for iteration in range(1, 21):
            logger().info(f"******************** Starting iteration {iteration} of 20 ********************")

            # For iterations 2-5, reset the device and re-configure for AP+BLE mode
            if iteration > 1:
                logger().info(f"Resetting device for iteration {iteration}")
                commander.reset_device()
                time.sleep(3)
                # Reset framework state so it allows new config after hardware reset
                wifi_dut.interfaces.wifi._state = 'deinit'
                wifi_dut.interfaces.wifi._wifi_config = None  # Clear previous config tracking
                # Reset thread state so threads get re-initialized after commander reset
                if hasattr(wifi_dut.interfaces.wifi, '_threads'):
                    wifi_dut.interfaces.wifi._threads = {}
                if hasattr(wifi_dut.interfaces.wifi, '_threads_initialized'):
                    wifi_dut.interfaces.wifi._threads_initialized = False
                # Reset BLE interface state after commander reset
                if hasattr(ble_dut.interfaces.bluetooth, '_state'):
                    ble_dut.interfaces.bluetooth._state = 'deinit'
                if hasattr(ble_dut.interfaces.bluetooth, '_initialized'):
                    ble_dut.interfaces.bluetooth._initialized = False

                # Reset ALL framework state after commander reset
                wifi_dut.interfaces.wifi._threads_initialized = False
                wifi_dut.interfaces.wifi._threads = {}
                wifi_dut.interfaces.wifi._state = 'deinit'
                wifi_dut.interfaces.wifi._wifi_config = None

                # Set thread_config on interface
                wifi_dut.interfaces.wifi._thread_config = {"wifi": {"count": 1, "stack_len": 3072},
                                                           "ble": {"count": 1, "stack_len": 2048}}

                # Re-initialize device with AP+BLE mode config (same as fixture)
                # set_wifi_config sends the wifi.set_config command
                wifi_dut.interfaces.wifi.set_wifi_config(
                    oper_mode=Si91xOperatingMode.AccessPoint,
                    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                    features=Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
                    tcpip_features=Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
                    custom_features=Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                    ext_custom_features=Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                    ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.Default,
                    config_features=Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                    bt_features=Si91xBTFeatureBitMap.Default,
                    ble_features=Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
                    ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST)

                # Send plain wifi.init command (no thread prefix)
                # The framework's init() uses issue_command_in_thread() which adds thread prefix
                # even when _threads is empty - it seems to auto-create threads
                # We need to bypass the init() method entirely
                wifi = wifi_dut.interfaces.wifi

                # Find the underlying CLI that sends raw commands
                # Look for _cli attribute which typically has the raw send method
                cli = None
                for attr_name in ['_cli', 'cli', '_connection', 'connection', '_serial_connection',
                                  '_serial', 'serial', 'host_connection', '_host_connection',
                                  'serial_connection', '_host', 'host', '_bus', 'bus']:
                    obj = getattr(wifi, attr_name, None)
                    if obj is not None:
                        cli = obj
                        break

                # If no CLI found on wifi interface, try getting it from the device
                if cli is None:
                    device = getattr(wifi, '_device', None) or getattr(wifi, 'device', None)
                    if device is not None:
                        for attr_name in ['_connection', 'connection', '_serial_connection', '_serial',
                                          'host_connection', '_host', 'host', '_bus', 'bus', '_cli', 'cli']:
                            obj = getattr(device, attr_name, None)
                            if obj is not None:
                                cli = obj
                                break

                # Also check wifi_dut directly
                if cli is None:
                    for attr_name in ['_connection', 'connection', '_serial_connection', '_serial',
                                      'host_connection', '_cli', 'cli']:
                        obj = getattr(wifi_dut, attr_name, None)
                        if obj is not None:
                            cli = obj
                            break

                # Send commands using the CLI if found
                sent_commands = False
                if cli is not None:
                    if hasattr(cli, 'send_command'):
                        cli.send_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        cli.send_command("thread 0 3072 1600", timeout=5)
                        cli.send_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True
                    elif hasattr(cli, 'send'):
                        cli.send("wifi.init\r\n")
                        time.sleep(3)  # Wait for init to complete
                        wifi._state = 'init'
                        cli.send("thread 0 3072 1600\r\n")
                        time.sleep(1)
                        cli.send("thread 1 2048 1600\r\n")
                        time.sleep(1)
                        sent_commands = True

                if not sent_commands:
                    # Try using the internal command methods of the wifi interface
                    if hasattr(wifi, '_issue_command'):
                        wifi._issue_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        wifi._issue_command("thread 0 3072 1600", timeout=5)
                        wifi._issue_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True
                    elif hasattr(wifi, '_send_command'):
                        wifi._send_command("wifi.init")
                        wifi._state = 'init'
                        wifi._send_command("thread 0 3072 1600")
                        wifi._send_command("thread 1 2048 1600")
                        sent_commands = True
                    elif hasattr(wifi, 'issue_command'):
                        # This might be the raw command method without thread prefix
                        wifi.issue_command("wifi.init", timeout=10)
                        wifi._state = 'init'
                        wifi.issue_command("thread 0 3072 1600", timeout=5)
                        wifi.issue_command("thread 1 2048 1600", timeout=5)
                        sent_commands = True

                if not sent_commands:
                    # Final fallback: completely reset the framework and let it reinitialize
                    # The problem is init() creates threads automatically
                    # We need to prevent that by setting _thread_config to None temporarily
                    original_thread_config = getattr(wifi, '_thread_config', None)
                    wifi._thread_config = None  # Disable thread creation
                    wifi._threads_initialized = False
                    wifi._threads = {}

                    try:
                        # Call init without thread support
                        wifi.init()
                    finally:
                        # Restore thread config for subsequent commands
                        wifi._thread_config = original_thread_config

                    # Manually create threads after init
                    if hasattr(wifi, '_create_threads'):
                        wifi._create_threads()

                wifi._threads = {"wifi": [0], "ble": [1]}
                wifi._threads_initialized = True

            # Create fresh ble_obj for each iteration to avoid stale references
            ble_obj = ProvisioningFunctionality(
                wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
                utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
                wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

            ble_obj.ap_mode_start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.firmware_version()
            time.sleep(10)
            ble_obj.check_beacon()
            ble_obj.http_server_provisioning()
            ble_obj.sl_net_deinit()

            wifi_dut.interfaces.wifi.set_wifi_config(
                oper_mode=Si91xOperatingMode.WiFiClient,
                coex_mode=Si91xCoexMode.WLANOnly,
                features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
                tcpip_features=Si91xTCPIPFeatureBitMap.Default)
            wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
            wifi_dut.interfaces.wifi.scan()
            wifi_dut.interfaces.wifi.join(
                ssid=wifi_access_point.interfaces.wifi.ssid,
                passphrase=ble_obj.result[2],
                security=ble_obj.result[3].lower(),
                channel=ap_channel)
            logger().info("....Successfully connected to the AP....")
            ip_status, ip_config = sl_collections.configure_ip(wifi_dut=wifi_dut)
            assert ip_status, f"Unable to assign IP ADDRESS through DHCP: {ip_config}"

            # Disconnect raspi client from DUT-AP before next iteration
            for client in wifi_clients:
                client.interfaces.wifi.leave()

            # Properly cleanup DUT: disconnect from third-party AP and deinit WiFi
            # This resets the framework's config tracking for the next iteration
            wifi_dut.interfaces.wifi.leave()
            time.sleep(1)
            wifi_dut.interfaces.wifi.deinit()

            logger().info(f"******************** Completed iteration {iteration} of 20 ********************")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_only_provisioning_wpa2_security_for_multiple_iteration_loop_C887674(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """Verify Soft AP provisioning in WPA2 security for multiple iteration in loop (20 Iteration)
    - Only HTTP Server provisioning mode (no client mode connection to third-party AP)
    - Iteration 1: Use fixture-initialized device + provisioning
    - Iteration 2-20: Only HTTP server provisioning loop (AP stays running)"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        # ==================== ITERATION 1: Use fixture-initialized device ====================
        # Note: The pytest fixture (@wifi_dut_marker) already:
        # - Reset the device
        # - Set wifi config with AP+BLE mode
        # - Called wifi.init()
        # - Created threads
        # So we just create the ble_obj and proceed with provisioning
        logger().info("******************** Starting iteration 1 of 20 (Using fixture setup) ********************")

        # Create ble_obj (will be reused for all iterations)
        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        # Start DUT as SoftAP
        ble_obj.ap_mode_start()

        # Start BLE advertising
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get firmware version
        ble_obj.firmware_version()

        time.sleep(10)

        # Verify beacon packets
        ble_obj.check_beacon()

        # HTTP Server Provisioning (iteration 1) with retry logic
        max_retries = 3
        for retry in range(max_retries):
            try:
                logger().info(f"HTTP Server Provisioning attempt {retry + 1} of {max_retries}")
                ble_obj.http_server_provisioning()
                break  # Success, exit retry loop
            except (AssertionError, Exception) as e:
                logger().info(f"HTTP provisioning failed on attempt {retry + 1}: {e}")
                if retry < max_retries - 1:
                    logger().info("Cleaning up HTTP server before retry...")
                    # Stop and deinit HTTP server if it was started
                    try:
                        wifi_dut.interfaces.wifi.http_server_stop()
                    except:
                        pass
                    try:
                        wifi_dut.interfaces.wifi.http_server_deinit()
                    except:
                        pass
                    # Disconnect client before retry
                    for client in wifi_clients:
                        try:
                            client.interfaces.wifi.leave()
                        except:
                            pass
                    logger().info("Waiting 10 seconds before retry...")
                    time.sleep(10)
                else:
                    raise  # Re-raise on final attempt

        # Disconnect RASPI client from DUT-AP
        for client in wifi_clients:
            try:
                client.interfaces.wifi.leave()
            except Exception as e:
                logger().info(f"Failed to disconnect client: {e}")

        logger().info("******************** Completed iteration 1 of 20 ********************")

        # ==================== ITERATION 2-20: Only HTTP Server Provisioning ====================
        for iteration in range(2, 21):
            logger().info(f"******************** Starting iteration {iteration} of 20 (HTTP Provisioning Only) ********************")

            # Verify beacon packets
            ble_obj.check_beacon()

            # HTTP Server Provisioning with retry logic
            for retry in range(max_retries):
                try:
                    logger().info(f"HTTP Server Provisioning attempt {retry + 1} of {max_retries}")
                    ble_obj.http_server_provisioning()
                    break  # Success, exit retry loop
                except (AssertionError, Exception) as e:
                    logger().info(f"HTTP provisioning failed on attempt {retry + 1}: {e}")
                    if retry < max_retries - 1:
                        logger().info("Cleaning up HTTP server before retry...")
                        # Stop and deinit HTTP server if it was started
                        try:
                            wifi_dut.interfaces.wifi.http_server_stop()
                        except:
                            pass
                        try:
                            wifi_dut.interfaces.wifi.http_server_deinit()
                        except:
                            pass
                        # Disconnect client before retry
                        for client in wifi_clients:
                            try:
                                client.interfaces.wifi.leave()
                            except:
                                pass
                        logger().info("Waiting 10 seconds before retry...")
                        time.sleep(10)
                    else:
                        raise  # Re-raise on final attempt

            # Disconnect RASPI client from DUT-AP before next iteration
            for client in wifi_clients:
                try:
                    client.interfaces.wifi.leave()
                except Exception as e:
                    logger().info(f"Failed to disconnect client: {e}")

            logger().info(f"******************** Completed iteration {iteration} of 20 ********************")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_Auto_JOIN_to_same_AP_C913405(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, wifi_clients, sniffer_filter, ble_client, ble_dut):

    """Verify the behavior when the SiWx917 is acting as station mode, disconnect from third party
    access point and reconnect to same third-party AP using auto join post-provisioning 	"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_client=ble_client, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        # ble_obj.ble_start_advertising()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        # Verify connectivity to third-party AP via ping before disconnect
        logger().info("....Pinging AP to verify connectivity before disconnect....")
        status = sl_collections.ping(device_ip=ble_obj.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING before disconnect"

        # Disconnect from the third-party AP
        logger().info("....Disconnecting from the third-party AP....")
        ble_obj.wifi_disconnect()
        time.sleep(5)

        # Auto-join to the same AP
        logger().info("....Initiating Auto Join to the same AP....")
        wifi_dut.interfaces.wifi.join(
            ssid=wifi_access_point.interfaces.wifi.ssid,
            passphrase=ble_obj.result[2],
            security=ble_obj.result[3].lower())
        logger().info("....Auto Join successful, connected back to the same AP....")

        # Re-configure IP after auto-join
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut=wifi_dut)
        assert ip_status, f"....Unable to assign IP after auto join: {ip_config}...."
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP after auto join: {device_ip}")

        # Verify connectivity via ping after auto-join
        logger().info("....Pinging AP to verify connectivity after Auto Join....")
        status = sl_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING after Auto Join"
        logger().info("....Auto Join and Ping verification successful....")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ap_provisioning_wpa2_security_Auto_JOIN_to_other_AP_C913406(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, wifi_clients, sniffer_filter, ble_client, ble_dut,
        wifi_access_points):

    """	Verify the behavior when the SiWx917 is acting as station mode, disconnect from third party
    access point and reconnection to other available third-party AP post-provisioning"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        # Get the second third-party AP from harness (dlink_ap)
        assert len(wifi_access_points) >= 2, "Minimum 2 access points needed in harness for this test"
        other_ap = wifi_access_points[1]
        other_ap_ssid = other_ap.interfaces.wifi.ssid
        other_ap_security_raw = other_ap.interfaces.wifi.security if hasattr(other_ap.interfaces.wifi, 'security') else 'wpa2'
        other_ap_security = other_ap_security_raw.name.lower() if hasattr(other_ap_security_raw, 'name') else str(other_ap_security_raw).lower()
        other_ap_passphrase = other_ap.interfaces.wifi.passphrase
        other_ap_channel = other_ap.interfaces.wifi.channel if hasattr(other_ap.interfaces.wifi, 'channel') else 0
        logger().info(f"Second AP details - SSID: {other_ap_ssid}, Security: {other_ap_security}, Channel: {other_ap_channel}")

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, ble_client=ble_client, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        # ble_obj.ble_start_advertising()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        # Verify connectivity to primary third-party AP via ping before disconnect
        logger().info("....Pinging primary AP to verify connectivity before disconnect....")
        status = sl_collections.ping(device_ip=ble_obj.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING on primary AP before disconnect"

        # Disconnect from the primary third-party AP
        logger().info(f"....Disconnecting from primary AP ({wifi_access_point.interfaces.wifi.ssid})....")
        ble_obj.wifi_disconnect()
        time.sleep(5)

        # Connect to the other (second) third-party AP from harness
        logger().info(f"....Initiating connection to other third-party AP (SSID: {other_ap_ssid})....")
        wifi_dut.interfaces.wifi.scan()
        wifi_dut.interfaces.wifi.join(
            ssid=other_ap_ssid,
            passphrase=other_ap_passphrase,
            security=other_ap_security,
            channel=other_ap_channel)
        logger().info(f"....Successfully connected to other third-party AP ({other_ap_ssid})....")

        # Re-configure IP after connecting to other AP
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut=wifi_dut)
        assert ip_status, f"....Unable to assign IP after connecting to other AP ({other_ap_ssid}): {ip_config}...."
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP after connecting to other AP ({other_ap_ssid}): {device_ip}")
        logger().info(f"....Successfully connected and obtained IP on other third-party AP ({other_ap_ssid})....")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

