import time
from datetime import datetime, timedelta
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
                 write_handle = None, wifi_access_points=None, device_ip=None, device_ip_two=None,
                 dut_mac_address_two=None, dut_mac_address=None, set_smp=None, adv_int=100,
                 wifi_client=None, wifi_clients=None, wiseconnect_web=None):
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
        self.ap_channel = self.wifi_access_point.interfaces.wifi.channel
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.wiseconnect_web = wiseconnect_web
        self.ssid = 'sharma_test'
        self.security = 'wpa2'
        self.psk = '123456789'

        logger().info("******************** initializing ble in dut ********************")
        self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
        assert self.bt_dut_address, "failed to initialize ble in dut"

    def run(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            self.svc = 'HealthThermometerService'
            self.charc = 'CustomNotifyCharacteristic'

            logger().info("******************** initializing ble in dut ********************")
            self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
            assert self.bt_dut_address, "failed to initialize ble in dut"

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            self.wifi_dut.interfaces.wifi.ble_start_advertising(
                ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address,
                services=[self.svc])

            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.bt_dut_address,
                                            min_conn_interval=self.min_conn_interval,
                                            max_conn_interval=self.max_conn_interval,
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

    def sl_net_deinit(self):
        self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="ap")

    def wifi_connect(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase=self.credentials[1], security='wpa3_transition')
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

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")

    def check_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "No beacon found in sniffer"

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

    def ap_mode_start(self):
        """
        Method to start the DUT as an Access Point.
        """
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        if self.test_case == 22:
            logger().info(" ********** Starting DUT as an AP ********* ")
            self.wifi_dut.interfaces.wifi.start_ap(
                ssid=self.ssid, security='wpa2', psk=self.psk, channel=self.ap_channel, dtim_beacon_count="1",
                beacon_interval="100")
        else:
            logger().info(" ********** Starting DUT as an AP ********* ")
            self.wifi_dut.interfaces.wifi.start_ap(
                ssid=self.ssid, security=self.security, psk=self.psk, channel=self.ap_channel, dtim_beacon_count="1",
                beacon_interval="100")

    def ble_advertising(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising(
            ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

    def ble_gatt_start(self):
        logger().info("******************** initializing ble in dut ********************")
        self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=self.set_smp)
        assert self.bt_dut_address, "failed to initialize ble in dut"

    def scan_from_remote_device(self):
        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address)

    def run_operations_for_12hours(self):
        start_time = datetime.now()
        logger().info(f"Starting test at: {start_time}")
        # Run the operations
        self.ble_gatt_start()
        self.ap_mode_start()
        self.ble_advertising()

        # Wait for 12 hours to check stability
        logger().info("**** Wait for 12 hours to check stability ****")
        time.sleep(43200)  # 12 hours in seconds

        logger().info("Operations completed successfully")

        end_time = datetime.now()
        logger().info(f"Test completed at: {end_time}")
        logger().info(f"Total duration: {end_time - start_time}")

    def ble_connection_stability(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising(
            ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address,
            services=[self.svc])

        self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                        ble_dut_address=self.bt_dut_address,
                                        min_conn_interval=self.min_conn_interval,
                                        max_conn_interval=self.max_conn_interval,
                                        conn_latency=self.conn_latency,
                                        supervision_timeout=self.supervision_timeout)
        time.sleep(10)


def wifi_dut_marker(IEEE802_11W=0, memory_config=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
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
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_Case_long_run_1(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify AP beaconing and BLE Advertisement Stability"""

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter, min_conn_interval=200, max_conn_interval=200)

        ble_obj.run_operations_for_12hours()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        ble_obj.check_beacon()
        ble_obj.scan_from_remote_device()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup_disconn()


@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_Case_long_run_2(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """Verify BLE provisioning and check the stability of the ble connection"""

    ble_obj = None
    try:
        start_time = datetime.now()
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter, min_conn_interval=200, max_conn_interval=200)

        ble_obj.ap_mode_start()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.start()
        ble_obj.wait_for_exit()

        logger().info(f"******* 12-hour test started at : {start_time} ********")
        time.sleep(43200)
        logger().info(f"12-hour test completed at: {datetime.now()}")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup_disconn()


# @pytest.mark.config(
#     "wifi_clients",
#     wifi={
#         0: {
#             "security": "WPA2",
#             "ssid": "sharma_test",
#             "passphrase": "123456789",
#             "channel": "11",
#         },
#     }
# )
# @wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
# @pytest.mark.parametrize("ap_channel", [11])
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
# def test_case_34(
#         sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
#         wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
#     try:
#         test_name = request.node.name
#         wifi_client = [wifi_client]
#
#         logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
#
#         ble_obj = ProvisioningFunctionality(
#             wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
#             utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
#             ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
#             wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter)
#
#         ble_obj.ble_gatt_start()
#         ble_obj.ap_mode_start()
#         ble_obj.ble_advertising()
#         ble_obj.firmware_version()
#         time.sleep(20)
#         ble_obj.http_server_provisioning()
#
#
#
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop the Sniffer")
#
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
