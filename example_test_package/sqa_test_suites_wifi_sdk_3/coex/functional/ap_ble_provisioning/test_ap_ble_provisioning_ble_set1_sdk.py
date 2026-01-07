import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

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

    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, ble_dut=None,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, bt_dut_address=None, credentials=None,
                 ble_client_address=None, char_path=None, char_uid=None, min_conn_interval=160, sniffer_filter=None,
                 max_conn_interval=160, conn_latency=0, supervision_timeout=3200, svc=None, charc=None,
                 write_handle = None, wifi_access_points=None, device_ip=None, device_ip_two=None, scan_type=None,
                 dut_mac_address_two=None, dut_mac_address=None, set_smp=None, adv_int=100, beacon_stop=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
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
        self.ssid = self.wifi_access_point.interfaces.wifi.ssid
        self.security = self.wifi_access_point.interfaces.wifi.security.name.lower()
        self.psk = self.wifi_access_point.interfaces.wifi.passphrase
        self.ap_channel = self.wifi_access_point.interfaces.wifi.channel
        self.sniffer_filter = sniffer_filter
        self.beacon_stop = beacon_stop
        self.scan_type = scan_type

        logger().info("******************** initializing ble in dut ********************")
        self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
        assert self.bt_dut_address, "failed to initialize ble in dut"

    def run(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            self.svc = 'HealthThermometerService'
            self.charc = 'CustomNotifyCharacteristic'

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            self.wifi_dut.interfaces.wifi.ble_start_advertising(
                ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address,
                services=[self.svc])

            # self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
            #                                 ble_dut_address=self.bt_dut_address,
            #                                 min_conn_interval=self.min_conn_interval,
            #                                 max_conn_interval=self.max_conn_interval,
            #                                 conn_latency=self.conn_latency,
            #                                 supervision_timeout=self.supervision_timeout)

            logger().info(f'*** BLE is Connecting with Connection Interval {int(int(self.min_conn_interval)/1.25)} ***')
            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.bt_dut_address,
                                                        min_conn_interval=int(int(self.min_conn_interval) / 1.25),
                                                        max_conn_interval=int(int(self.max_conn_interval) / 1.25),
                                                        conn_latency=self.conn_latency,
                                                        supervision_timeout=self.supervision_timeout)
            time.sleep(10)

            logger().info(".... checking ble connection stability ....")
            time.sleep(60)

            logger().info(".... get connection state ....")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, ".... device is in disconnection state ...."

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            self.char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=self.char_uid)
            assert self.char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            logger().info(f"******************** get all profiles ********************")
            uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
                ble_remote_dev_address=self.ble_client_address)
            assert HealthThermometerService.UUID.lower() in uuids is not None, "couldn't fetch health_thermometer " \
                                                                               "profile "

            logger().info(" ******************** Resolving Profile ********************")
            start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=self.ble_client_address, uuid=int(HealthThermometerService.UUID, 16))
            assert start_handle is not None, "failed to fetch the start handle.."
            assert end_handle is not None, "failed to fetch end handle.."

            char_uuids, write_handles, char_properties = self.ble_dut.interfaces.wifi.ble_get_char_services_async(
                ble_remote_dev_address=self.ble_client_address,
                start_handle=int(start_handle, 16),
                end_handle=int(end_handle, 16),
                async_timeout=60)
            logger().info(
                f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
                f"{char_properties}")

            assert CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID in char_uuids, "Unable to find {} uuid".format(
                CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
            index = char_uuids.index(CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
            logger().info(f"UUID's are:{char_uuids}")
            logger().info(f"write_handles:{write_handles}")
            logger().info(f"index:{index}")
            assert char_properties[index].isdigit(), "Character property found is not an integer"
            assert CustomNotifyCharacteristic.prop_int == int(
                char_properties[index]), "Invalid character property found"

            self.write_handle = int(write_handles[index], 16)
            logger().info(f"write_handle:{self.write_handle}")
            assert self.write_handle > 0, "Unable to get write handle for configured service"

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def update_conn_params(self):
        self.wifi_dut.interfaces.wifi.ble_update_conn_param(
            ble_remote_dev_address=self.ble_client_address, ble_conn_interval_min=3200,
            ble_conn_interval_max=3200, ble_conn_latency=0, ble_supervision_timeout=2000)

    def credentials_send_over_ble(self):
        self.credentials = []
        data = [self.wifi_access_point.interfaces.wifi.ssid, self.wifi_access_point.interfaces.wifi.passphrase,
                self.wifi_access_point.interfaces.wifi.security.name.lower()]

        for length in range(len(data)):
            self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=1)

            since_time = time.perf_counter_ns()

            logger().info("******************** Sending data to DUT ***********************")
            self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, data[length])
            time.sleep(30)
            events = self.wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                    received_data = re.findall(r"((?<=att_value:\s)[\w\W]+(?=\n))", event.event_data)
                    received_credentials = str(received_data[0])
                    logger().info(f"******* Received Data on DUT : {received_credentials} ********")

                    self.credentials.append(received_credentials)
                    logger().info(f"******* credentials appending in list : {self.credentials} ********")
                    assert received_credentials == data[length], "data mismatched"

            self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=0)
            time.sleep(3)

    def power_save(self):
        logger().info(f"....Applying performance profile mode and Enable_bt_power_save....")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save()

    def ping_after_power_save(self):
        logger().info(f"....Pinging to DUT after Power Save")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def sl_net_deinit(self):
        # self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")
        self.wifi_dut.interfaces.wifi.deinit()

    def wifi_scan(self):
        scan_result_ssid_security = []
        result = self.wifi_dut.interfaces.wifi.scan()
        assert result, ".... scan results are empty ...."

        for scan in result:
            ssid = re.findall(r"((?<=ssid:\s)[\w\W]+?(?=\sbssid))", str(scan))
            security = re.findall(r"((?<=security_mode:\s)\d+)", str(scan))
            scan_result_ssid_security.append((ssid[0], security[0]))

        logger().info(f".... scan result for ssid and security is : {scan_result_ssid_security} ....")

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        for ssid in scan_result_ssid_security:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address, data=str(ssid))
            time.sleep(3)
            logger().info("******************** Validate Data ********************")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            time.sleep(30)
            logger().info(f' ******* received ssid and security on remote device is : {notifications} *******')

            assert notifications, ".... received data is empty ...."
            # assert notifications == [str(ssid)], ".... SSID or Security Mismatch or Acknowledgement not received ....."
        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(5)

    def wifi_connect(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase=self.credentials[1], security=self.credentials[2])
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')

        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} DUT IP ADDRESS : {self.device_ip}")

        logger().info(f"....Pinging to DUT before Power Save")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def mixed_mode_connect(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase=self.credentials[1], security='wpa', enc='tkip')
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')

        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} DUT IP ADDRESS : {self.device_ip}")

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")

    def wifi_connect_wrong_psk(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase='thisisnotatestnetwork', security=self.credentials[2],
            expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("....De-Authentication received when trying to connect with AP using wrong PSK....")

    def check_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "No beacon found in sniffer"

    def check_no_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating no beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2, negative_test=True)['packet_count']
        assert not snif_pkt_count, "found beacon packet in sniffer"

    def ble_remove_servie(self):
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_disconnect(self):
        logger().info("*********************** Disconnecting from DUT ***********************")
        self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
        self.ble_client.interfaces.bluetooth.close()

    def ble_cleanup_disconn(self):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True

        self.ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Cleanup Success *******************")

    def wifi_disconnect(self):
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("....Successfully disconnected from the AP....")

    def stop_ap_interface(self):
        self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info("....Successfully stopped the AP interface....")

    def ap_mode_start(self):
        """
        Method to start the DUT as an Access Point.
        """
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        if self.test_case == 887621:
            logger().info(" ********** Starting DUT as an AP ********* ")
            self.wifi_dut.interfaces.wifi.start_ap(
                ssid=self.ssid, security='wpa2', psk=self.psk, channel=self.ap_channel, dtim_beacon_count="1",
                beacon_interval="100", beacon_stop=self.beacon_stop)
        else:
            logger().info(" ********** Starting DUT as an AP ********* ")
            self.wifi_dut.interfaces.wifi.start_ap(
                ssid=self.ssid, security=self.security, psk=self.psk, channel=self.ap_channel, dtim_beacon_count="1",
                beacon_interval="100", beacon_stop=self.beacon_stop)

    def start_http_server(self):
        self.wifi_dut.interfaces.wifi.http_server_init(http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()

    def stop_http_server(self):
        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()

    def scan_on_ap_interface(self):
        scan_result_ssid_security = []
        logger().info("******* scanning on AP interface ********")
        scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap", scan_type=self.scan_type)

        for scan in scan_results:
            ssid = re.findall(r"((?<=ssid:\s)[\w\W]+?(?=\sbssid))", str(scan))
            security = re.findall(r"((?<=security_mode:\s)\d+)", str(scan))
            scan_result_ssid_security.append((ssid[0], security[0]))

        logger().info(f".... scan result for ssid and security is : {scan_result_ssid_security} ....")


def wifi_dut_marker(IEEE802_11W=0, memory_config=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_c887610(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning in WPA2 security and also verify wifi connection to the third party home AP with the
    received credentials over BLE"""

    ble_obj =None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter, min_conn_interval=200, max_conn_interval=200)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode= Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_conn_45ms_c887611(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning in WPA2 security with BLE connection interval 45ms and also verify wifi connection to
    the third party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=45, max_conn_interval=45, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_30ms_c887612(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 30ms in WPA2 security and also verify wifi connection to the third
    party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=30, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@pytest.mark.skip(reason="WPA3 connection is not working - need to verify manually")
@wifi_dut_marker(IEEE802_11W=Si91xExtCustomFeatureBitMap.IEEE802_11W,
                 memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_45ms_c887613(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 45ms in WPA3 security and also verify wifi connection to the third party
    home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=45, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient, coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default,
            ext_custom_features=Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                                Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode |
                                Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_120ms_c887614(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 120ms in OPEN security and also verify wifi connection to the third party
    home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=120, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_500ms_c887615(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 500ms in WPA2 security and also verify wifi connection to the third party
    home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=500, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_conn_95ms_c887640(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning in WPA2 security with BLE connection interval  and adv interval as 95ms and also
    verify wifi connection to the third party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=95, max_conn_interval=95, adv_int=95, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_conn_110ms_c887641(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 110ms in WPA2 security and also verify wifi connection to the third party
    home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=110, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@pytest.mark.skip(reason="BLE connection is not working when configuring adv interval 10240ms - WIFI_BT_UTFHELP-4773")
@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_adv_10240ms_c887616(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with adv int 10240ms in WPA2 security and also verify wifi connection to the third party
    home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, adv_int=10240, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'thisisableprovisioningtestplannn', "security": 'WPA2'})
def test_wifi_sdk_ble_provision_path_ssid_32bytes_c887617(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with SSID 32bytes and also verify wifi connection to the third party home AP with the
    received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"passphrase": 'thisiswifibleprovisioningtestplanthisisableprovisioningtestplan',
                          "security": 'WPA2'})
def test_wifi_sdk_ble_provision_path_passphrase_63bytes_c887618(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with PSK 63bytes and also verify WLAN connection to the third party home AP with the
    received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_wrong_passphrase_c887619(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify DUT behaviour via BLE provisioning when configuring wrong PSK and also verify wifi  connection to the
    third party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect_wrong_psk()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@pytest.mark.skip(reason="slave connection is not working in second iteration in loop - WIFI_BT_UTFHELP-5662")
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_multiple_iter_loop_c887620(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify DUT behaviour via BLE provisioning and also verify wifi connection to the third party home AP with the
    received credentials over BLE for multiple iteration in loop"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, sniffer_filter=sniffer_filter)

        for count in range(0, 2):
            ble_obj.ap_mode_start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.credentials_send_over_ble()
            ble_obj.sl_net_deinit()

            wifi_dut.interfaces.wifi.set_wifi_config(
                oper_mode=Si91xOperatingMode.WiFiClient,
                coex_mode= Si91xCoexMode.WLANOnly,
                features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
                tcpip_features=Si91xTCPIPFeatureBitMap.Default)
            wifi_dut.interfaces.wifi.is_sl_net_enabled = True
            wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
            wifi_dut.interfaces.wifi.scan()
            ble_obj.wifi_connect()
            ble_obj.wifi_disconnect()

            if count == 0:
                wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

                wifi_dut.interfaces.wifi.set_wifi_config(
                    oper_mode=Si91xOperatingMode.AccessPoint,
                    coex_mode= Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                    features= Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
                    tcpip_features= Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                                      Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
                    ext_custom_features= Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                                           | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid)

                wifi_dut.interfaces.wifi.sl_net_init(mode="ap")
            ble_client.interfaces.bluetooth.close()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPAWPA2MixedMode', "cipher": "TKIP_AES", "passphrase": '123456789'})
def test_wifi_sdk_ble_provision_path_mixed_mode_security_c887621(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning with Mixed Mode security and also verify WLAN connection to the third party home AP with
    the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=200, max_conn_interval=200, sniffer_filter=sniffer_filter, test_case=887621)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.mixed_mode_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_conn_30ms_c887622(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning in WPA2 security with BLE connection interval 30ms and also verify wifi connection to
    the third party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            min_conn_interval=30, max_conn_interval=30, sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ble_provision_path_max_conn_int_c887623(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning in WPA2 security with BLE max connection interval and also verify wifi connection to
    the third party home AP with the received credentials over BLE"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.update_conn_params()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ble_provision_path_with_power_save_and_ping_c887624(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning and enable power save post wifi connection to provisioned AP and run ping"""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1

        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()

        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()
        ble_obj.power_save()
        ble_obj.ping_after_power_save()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")
