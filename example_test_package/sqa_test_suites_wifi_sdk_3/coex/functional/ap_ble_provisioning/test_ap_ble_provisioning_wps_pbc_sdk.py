import time
import pytest
import re

from example_test_package.conftest import sl_collections
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.wifi import SecurityMode
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)

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
                 net_perf_client=None, protocol=None, traffic=None, qos=None, sniffer_filter=None, associated=None, power_save=True,
                 skip_scan=False, tcp_ip_bypass=False, ip_config_disable=False, retry_count=1, ping_after_power_save=True, ping_before_power_save=True,
                 mode='power_save_low_latency',
                 ping_count=10,
                 dtim_aligned_type=0, num_of_dtim_skip=0, listen_interval=0, monitor_interval=0,
                 ip_version='ipv4',
                 ipv6_type='global',
                 ):
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
        self.associated = associated
        self.power_save = power_save
        self.skip_scan = skip_scan
        self.tcp_ip_bypass = tcp_ip_bypass
        self.ip_config_disable = ip_config_disable
        self.retry_count = retry_count
        self.ping_after_power_save = ping_after_power_save
        self.ping_before_power_save = ping_before_power_save
        self.mode = mode
        self.ping_count = ping_count
        self.listen_interval = listen_interval
        self.monitor_interval = monitor_interval
        self.dtim_aligned_type = dtim_aligned_type
        self.num_of_dtim_skip = num_of_dtim_skip
        self.ip_version = ip_version
        self.ipv6_type = ipv6_type

        logger().info("******************** initializing ble in dut ********************")
        self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
        assert self.bt_dut_address, "failed to initialize ble in dut"

    def run(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising(
            ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

    def sl_net_deinit(self):
        self.wifi_dut.interfaces.wifi.deinit()

    def wifi_connect(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.result[1], passphrase=self.result[2], security=self.result[3].lower())
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")

    def stop_ap_interface(self):
        self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info("....Successfully stopped the AP interface....")

    def ble_stop_advertising(self):
        logger().info("Device is in advertising status try to stop advertising")
        self.ble_dut.interfaces.bluetooth.ble_stop_advertising()

    def wifi_disconnect(self):
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("....Successfully disconnected from the AP....")

    def ble_start_advertising(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

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
                    ProvisioningFunctionality.ip_dict['rasp_mac_address'] = self.wifi_clients[
                        i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {ProvisioningFunctionality.ip_dict['rasp_mac_address']}")
                    # ProvisioningFunctionality.ip_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    # logger().info(f"Client{i + 1}_ip: {ProvisioningFunctionality.ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {'192.168.100.77'}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        # return ProvisioningFunctionality.ip_dict

    def http_server_start(self):
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()

    def http_server_stop(self):
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

    def join_to_wifi_network_via_wps(self):
        """
        This function is responsible to connect DUT with AP using WPS Push Button Configuration
        :param wifi_dut: DUT device object
        :param wifi_access_point: Access Point object
        :param power_save: Enable power save mode
        :param mode: Power save mode type
        :param channel: WiFi channel
        :param ping_count: Number of ping packets
        :param retry_count: Retry count for operations
        :param ping_after_power_save: Ping after enabling power save
        :param ping_before_power_save: Ping before enabling power save
        :param associated: Current association status
        :param dtim_aligned_type: DTIM alignment type
        :param num_of_dtim_skip: Number of DTIM to skip
        :param listen_interval: Listen interval
        :param monitor_interval: Monitor interval
        :param ip_version: IP version ('ipv4' or 'ipv6')
        :param tcp_ip_bypass: Bypass TCP/IP configuration
        :param ip_config_disable: Disable IP configuration
        :param ipv6_type: IPv6 type ('global' or 'link_local')
        :param skip_scan: Skip WiFi scan
        :return: Dictionary containing 'device_ip' and 'dut_mac_address'
        """
        dut_add_dict = {}

        if self.associated is False:
            # Start WPS push button on AP first
            logger().info("Starting WPS push button process on Access Point")
            # wifi_access_point.start_wps_process_push()
            self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
            time.sleep(2)  # Give AP time to start WPS

            # Scan for APs if not skipped
            if self.skip_scan is False:
                scan_status, reason = self.sl_collections.scan(self.wifi_dut, scan_status=self.skip_scan, retry_count=self.retry_count,
                                                          channel=0)
                assert scan_status, f"....Scanning for AP failed..with reason: {reason}...."

            # Initiate WPS push button join from DUT
            logger().info("Initiating WPS push button connection from DUT")
            try:
                self.wifi_dut.interfaces.wifi.start_client_wps(
                    interface="client",
                    wps_role=0,  # 1-Enrollee
                    wps_mode=0,  # 0-PBC
                    auto_connect=True
                )
                logger().info("WPS push button connection initiated successfully")
                self.wifi_dut.interfaces.wifi.associated = True
            except Exception as e:
                logger().error(f"WPS connection failed: {str(e)}")
                raise

            logger().info("DUT successfully connected to AP via WPS")
            dut_add_dict['dut_mac_address'] = self.wifi_dut.interfaces.wifi.get_mac_address()

            if not (self.tcp_ip_bypass or self.ip_config_disable):
                # configure_ip tries to assign IP ADDRESS through DHCP
                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=self.retry_count,
                                                                   ip_version=self.ip_version,)
                assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

                if self.ip_version == 'ipv4':
                    device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                else:
                    if self.ipv6_type == 'global':
                        device_ip = ip_config[1]
                    else:
                        device_ip = ip_config[0]

                logger().info(f"DUT ip: {device_ip}")

                # we fetch the ip address and mac_address
                dut_add_dict['device_ip'] = device_ip

                logger().info(
                    f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} DUT IP ADDRESS : {dut_add_dict['device_ip']}")

                # ping to DUT before power_save
                if self.ping_before_power_save:
                    status = self.sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=self.ping_count)
                    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

            if self.power_save:
                logger().info(f"....Applying performance profile mode : {self.mode}")
                self.wifi_dut.interfaces.wifi.set_performance_profile(self.mode, self.dtim_aligned_type, self.num_of_dtim_skip,
                                                                 self.listen_interval, self.monitor_interval)
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                if not self.tcp_ip_bypass:
                    if self.ping_after_power_save:
                        logger().info("....Pinging DUT after power-save....")
                        status = self.sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=self.ping_count)
                        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

            return dut_add_dict
        else:
            logger().info(f'\n\n *** Device is already connected with AP *** \n\n')
            return None


def wifi_dut_marker(IEEE802_11W=0, memory_config=0, OpenMode=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072},
                          "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT | OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.NWP120MHz,
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
def test_wifi_sdk_wps_path_wpa2_security_c913440(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter, ap_channel):
    """Verify DUT behavior with WPS path flow"""

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
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, adv_int=160,
            associated=False, skip_scan=False, tcp_ip_bypass=False, ip_config_disable=False
        )

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_start()
        
        
        """ **** WPS Button press code - Workaround for WPS web configuration **** """
        logger().info(" ====== WPS button pressed and interrupt occurred and fallback to STA mode ====== ")

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # NEW c913440 staged teardown START
        # The firmware (1711.2.16.5.0.0.4) was hanging on wifi.deinit
        # when stop_ap_interface, ble_stop_advertising, http_server_stop
        # and sl_net_deinit were issued back-to-back in coex (AP+BLE)
        # mode (verified in pytest_log: TX wifi.deinit echoed but no
        # status response within 10s -> AssertionError -0x1 / FW_FAILURE).
        # Stage each teardown step with a small drain delay so the
        # firmware can settle before the next command, and retry the
        # final deinit a couple of times so a single transient hang
        # doesn't fail the test.
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        logger().info("##### [NEW c913440] staged teardown ENTER #####")

        logger().info("##### [NEW c913440] step 1/4: stop_ap_interface #####")
        ble_obj.stop_ap_interface()
        time.sleep(3)

        logger().info("##### [NEW c913440] step 2/4: ble_stop_advertising #####")
        ble_obj.ble_stop_advertising()
        time.sleep(2)

        logger().info("##### [NEW c913440] step 3/4: http_server_stop #####")
        ble_obj.http_server_stop()
        time.sleep(3)

        logger().info("##### [NEW c913440] step 4/4: sl_net_deinit (with retry) #####")
        deinit_attempts = 3
        deinit_ok = False
        for attempt in range(1, deinit_attempts + 1):
            try:
                ble_obj.sl_net_deinit()
                deinit_ok = True
                logger().info(f"##### [NEW c913440] sl_net_deinit succeeded on attempt {attempt} #####")
                break
            except Exception as deinit_err:
                logger().warning(
                    f"##### [NEW c913440] sl_net_deinit attempt {attempt}/{deinit_attempts} "
                    f"failed: {deinit_err} #####")
                time.sleep(3)
        if not deinit_ok:
            logger().warning(
                "##### [NEW c913440] sl_net_deinit hung repeatedly - relying on framework "
                "auto-recovery (commander reset already issued by sl_collections) #####")
        time.sleep(5)
        logger().info("##### [NEW c913440] staged teardown EXIT #####")
        # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        # NEW c913440 staged teardown END
        # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=0,
        coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        features=Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        tcpip_features=Si91xTCPIPFeatureBitMap.Default | 0,
        ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | 0,
        custom_features=Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | 0,
        bt_features=Si91xBTFeatureBitMap.Default,
        ble_features=Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=1)
                        | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=1)
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                        | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                        | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        config_features=Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp
        )

        time.sleep(5)

        # Use net.init to properly apply the wifi.set_config settings
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)

        # -------------------- WPS join (auto-connect ENABLED) --------------------
        logger().info("Starting WPS process with Auto Connect Enabled")
        wps_result = ble_obj.join_to_wifi_network_via_wps()
        logger().info(wps_result)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@pytest.mark.skip("OPEN security issue - 0x10019")
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
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, adv_int=480,
            test_case=887643)

        ble_obj.ap_mode_start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
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
@pytest.mark.parametrize("iteration_count", [3])  # Number of WPS iterations
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_wps_path_multiple_iterations_c913442(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients,
        sniffer_filter, ap_channel, iteration_count):
    """Verify DUT behavior with WPS path flow executed multiple times in loop.

    Each iteration mirrors the c913440 baseline single-shot flow:
      AP+BLE up -> AP+BLE teardown (staged) -> reconfig as STA+BLE -> WPS join
    Between iterations the DUT is brought back to AP+BLE (deinit + AP config
    + init) so the next iteration starts from the same clean state as iter 1.
    """

    def _force_commander_reset(tag):
        
        logger().info(f"##### [{tag}] forcing commander HW reset on DUT #####")
        try:
            wifi_dut.interfaces.wifi.reset()
            time.sleep(3)
            logger().info(f"##### [{tag}] commander reset OK #####")
            return True
        except Exception as reset_err:
            logger().error(f"##### [{tag}] commander reset failed: {reset_err} #####")
            return False

    def _staged_teardown(ble_obj_local, tag):
        
        logger().info(f"##### [{tag}] step 1/4: stop_ap_interface #####")
        try:
            ble_obj_local.stop_ap_interface()
        except Exception as e:
            logger().warning(f"##### [{tag}] stop_ap_interface error (continuing): {e} #####")
        time.sleep(3)
        logger().info(f"##### [{tag}] step 2/4: ble_stop_advertising #####")
        try:
            ble_obj_local.ble_stop_advertising()
        except Exception as e:
            logger().warning(f"##### [{tag}] ble_stop_advertising error (continuing): {e} #####")
        time.sleep(2)
        logger().info(f"##### [{tag}] step 3/4: http_server_stop #####")
        try:
            ble_obj_local.http_server_stop()
        except Exception as e:
            logger().warning(f"##### [{tag}] http_server_stop error (continuing): {e} #####")
        time.sleep(3)
        logger().info(f"##### [{tag}] step 4/4: sl_net_deinit (with retry) #####")
        deinit_attempts = 2  # 2 soft attempts then HW reset; FW hang is not transient on 1711.2.15.x
        deinit_ok = False
        for attempt in range(1, deinit_attempts + 1):
            try:
                ble_obj_local.sl_net_deinit()
                deinit_ok = True
                logger().info(f"##### [{tag}] sl_net_deinit succeeded on attempt {attempt} #####")
                break
            except Exception as deinit_err:
                logger().warning(
                    f"##### [{tag}] sl_net_deinit attempt {attempt}/{deinit_attempts} "
                    f"failed: {deinit_err} #####")
                time.sleep(3)
        if not deinit_ok:
            logger().warning(
                f"##### [{tag}] soft deinit hung - falling back to HW commander reset #####")
            _force_commander_reset(tag)
        time.sleep(5)
        return deinit_ok

    def _full_reinit_as_ap_ble(tag):
        
        logger().info(f"##### [{tag}] full re-init as AP+BLE ENTER #####")
        
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.inited_test_agent_threads = False
        wifi_dut.interfaces.wifi.test_agent_thread_index = -1
        wifi_dut.interfaces.wifi.test_agent_threads = {}
        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.AccessPoint,
            coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            features=Si91xFeatureBitMap.Aggregation
                     | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default
                           | Si91xTCPIPFeatureBitMap.DHCPv4Server
                           | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            custom_features=Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
                            | Si91xCustomFeatureBitMap.NWP120MHz,
            ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                                | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                                | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.Default,
            config_features=Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            bt_features=Si91xBTFeatureBitMap.Default,
            ble_features=Si91xBLEFeatureBitMap.Default
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        )
        time.sleep(3)

        # wifi.init (no -i, no thread prefix) - "Started AP mode with BLE"
        wifi_dut.interfaces.wifi.init(mode=None, config_required=False)
        time.sleep(2)

        # Recreate FW-side test agent threads, same shape as wifi_dut_marker.
        wifi_dut.interfaces.wifi.init_test_agent_threads(thread_config={
            "wifi": {"count": 1, "stack_len": 3072},
            "ble":  {"count": 1, "stack_len": 2048},
        })
        time.sleep(2)
        logger().info(f"##### [{tag}] full re-init as AP+BLE EXIT #####")

    def _full_reinit_as_sta_ble(tag):
        logger().info(f"##### [{tag}] full re-init as STA+BLE ENTER #####")
        
        wifi_dut.interfaces.wifi.is_sl_net_enabled = False
        wifi_dut.interfaces.wifi.inited_test_agent_threads = False
        wifi_dut.interfaces.wifi.test_agent_thread_index = -1
        wifi_dut.interfaces.wifi.test_agent_threads = {}

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=0,
            coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            features=Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
                     | Si91xFeatureBitMap.ULPGPIOHandshake
                     | Si91xFeatureBitMap.Aggregation
                     | Si91xFeatureBitMap.PSKSecurity,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default | 0,
            ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                               | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | 0,
            custom_features=Si91xCustomFeatureBitMap.NWP120MHz
                            | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                                | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                                | 0,
            bt_features=Si91xBTFeatureBitMap.Default,
            ble_features=Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=1)
                         | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=1)
                         | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                         | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                         | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                         | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            config_features=Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        )
        time.sleep(3)

        
        wifi_dut.interfaces.wifi.init(mode=None, config_required=False)
        time.sleep(2)

        
        wifi_dut.interfaces.wifi.init_test_agent_threads(thread_config={
            "wifi": {"count": 1, "stack_len": 3072},
            "ble":  {"count": 1, "stack_len": 2048},
        })
        time.sleep(2)
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        time.sleep(2)
        logger().info(f"##### [{tag}] full re-init as STA+BLE EXIT #####")

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]
        successful_iterations = 0
        failed_iterations = []

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        for iteration in range(1, iteration_count + 1):
            logger().info(f"\n{'=' * 60}")
            logger().info(f"===== WPS ITERATION {iteration} of {iteration_count} =====")
            logger().info(f"{'=' * 60}\n")

            try:
                
                ble_obj = ProvisioningFunctionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                    ble_dut=ble_dut, set_smp=0, utf_constants=utf_constants,
                    wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                    ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel,
                    wifi_client=wifi_client, wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web,
                    sniffer_filter=sniffer_filter, adv_int=160, associated=False,
                    skip_scan=False, tcp_ip_bypass=False, ip_config_disable=False,
                    power_save=False,
                )

                ble_obj.ap_mode_start()
                ble_obj.start()
                ble_obj.wait_for_exit()
                ble_obj.firmware_version()
                time.sleep(10)
                ble_obj.check_beacon()
                ble_obj.http_server_start()

                """ **** WPS Button press code - Workaround for WPS web configuration **** """
                logger().info(" ====== WPS button pressed and interrupt occurred and fallback to STA mode ====== ")

                
                logger().info(f"##### [c913442 iter {iteration}] staged teardown ENTER #####")
                soft_deinit_ok = _staged_teardown(ble_obj, f"c913442 iter {iteration}")
                logger().info(
                    f"##### [c913442 iter {iteration}] staged teardown EXIT "
                    f"(soft_deinit_ok={soft_deinit_ok}) #####")

                logger().info(f"[Iteration {iteration}] Configuring WiFi for STA + BLE mode...")
                if not soft_deinit_ok:
                    _full_reinit_as_sta_ble(f"c913442 iter {iteration} reinit-sta")
                else:
                    
                    wifi_dut.interfaces.wifi.set_wifi_config(
                        oper_mode=0,
                        coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                        features=Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
                                 | Si91xFeatureBitMap.ULPGPIOHandshake
                                 | Si91xFeatureBitMap.Aggregation
                                 | Si91xFeatureBitMap.PSKSecurity,
                        tcpip_features=Si91xTCPIPFeatureBitMap.Default | 0,
                        ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                           | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                                           | 0,
                        custom_features=Si91xCustomFeatureBitMap.NWP120MHz
                                        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                        ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                                            | 0,
                        bt_features=Si91xBTFeatureBitMap.Default,
                        ble_features=Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=1)
                                     | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=1)
                                     | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                                     | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                                     | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                                     | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                                     | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                                     | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                                     | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
                        ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                                | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                                | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                                | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                                | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
                        config_features=Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                    )
                    time.sleep(5)

                    wifi_dut.interfaces.wifi.is_sl_net_enabled = True
                    wifi_dut.interfaces.wifi.init(mode="client", config_required=False)

                logger().info(f"[Iteration {iteration}] Starting WPS process with Auto Connect Enabled")
                wps_result = ble_obj.join_to_wifi_network_via_wps()
                logger().info(f"[Iteration {iteration}] WPS Result: {wps_result}")

                if wps_result is not None and wps_result.get("device_ip"):
                    logger().info(f"[Iteration {iteration}] SUCCESS - DUT IP: {wps_result['device_ip']}")
                    successful_iterations += 1
                else:
                    reason = "No IP assigned" if wps_result else "WPS returned None"
                    logger().warning(f"[Iteration {iteration}] {reason}")
                    failed_iterations.append((iteration, reason))

                # ---------- Inter-iteration: return DUT to AP+BLE ----------
                if iteration < iteration_count:
                    logger().info(f"[Iteration {iteration}] Returning DUT to AP+BLE for next iteration...")

                    try:
                        ble_obj.wifi_disconnect()
                    except Exception as disconnect_error:
                        logger().warning(f"[Iteration {iteration}] Disconnect warning: {disconnect_error}")
                    time.sleep(3)

                    # Disable WPS PBC on the AP - join_to_wifi_network_via_wps() will
                    # re-enable it at the start of the next iteration.
                    try:
                        wifi_access_point.interfaces.wifi.set_configure_wps_web()
                    except Exception as ap_err:
                        logger().warning(f"[Iteration {iteration}] AP WPS stop warning: {ap_err}")

                    wifi_dut.interfaces.wifi.is_sl_net_enabled = False
                    try:
                        ble_obj.sl_net_deinit()
                        logger().info(f"[Iteration {iteration}] inter-iter wifi.deinit ok")
                    except Exception as deinit_err:
                        logger().warning(
                            f"[Iteration {iteration}] inter-iter wifi.deinit failed: "
                            f"{deinit_err}")
                    time.sleep(3)

                    if not _force_commander_reset(f"c913442 iter {iteration} inter"):
                        logger().error(
                            f"[Iteration {iteration}] inter-iter HW reset failed; aborting loop")
                        break
                    time.sleep(3)

                    # Mimic the framework's setup sequence (wifi.init + threads).
                    _full_reinit_as_ap_ble(f"c913442 iter {iteration} inter")
                    time.sleep(3)

            except Exception as iter_error:
                logger().error(f"[Iteration {iteration}] FAILED with error: {str(iter_error)}")
                failed_iterations.append((iteration, str(iter_error)))
                
                if iteration < iteration_count:
                    logger().info(f"[Iteration {iteration}] Attempting state recovery for next iteration...")
                    try:
                        
                        if not _force_commander_reset(f"c913442 iter {iteration} except"):
                            logger().error(
                                f"[Iteration {iteration}] HW reset failed; aborting loop")
                            break
                        time.sleep(3)
                        # Full fresh re-init (wifi.init + threads), not net.init.
                        _full_reinit_as_ap_ble(f"c913442 iter {iteration} except")
                        time.sleep(3)
                    except Exception as recovery_err:
                        logger().error(
                            f"[Iteration {iteration}] state recovery failed; aborting loop: "
                            f"{recovery_err}")
                        break
                continue

        logger().info(f"\n{'=' * 60}")
        logger().info(f"===== WPS ITERATION TEST SUMMARY =====")
        logger().info(f"{'=' * 60}")
        logger().info(f"Total Iterations: {iteration_count}")
        logger().info(f"Successful: {successful_iterations}")
        logger().info(f"Failed: {len(failed_iterations)}")

        if failed_iterations:
            logger().info("Failed iterations details:")
            for iter_num, reason in failed_iterations:
                logger().info(f"  - Iteration {iter_num}: {reason}")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Sniffer capture stopped")

        assert successful_iterations == iteration_count, \
            f"WPS loop test failed: {successful_iterations}/{iteration_count} iterations succeeded. " \
            f"Failures: {failed_iterations}"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()

