import subprocess
import time

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth.bluez import HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import CustomNotifyCharacteristic
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utf_config import UtfConfig
from utf.utils.decorators import skip_test_case
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xBTFeatureBitMap
)
from utf_wiseconnect_3.tests.interfaces import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus
import re


def logger():
    return get_logger(__name__)


class ProvisioningFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, ble_dut=None, ble_pairing=0,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, bt_dut_address=None, credentials=None,
                 ble_client_address=None, char_path=None, char_uid=None, adv_int=None, min_conn_interval=160,
                 max_conn_interval=160, conn_latency=0, supervision_timeout=3200):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
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
        self.device_ip = None

    def run(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'

            logger().info("******************** initializing ble in dut ********************")
            self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
            assert self.bt_dut_address, "failed to initialize ble in dut"

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            if self.test_case == 34483:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address, services=[svc])

            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.bt_dut_address,
                                            min_conn_interval=self.min_conn_interval,
                                            max_conn_interval=self.max_conn_interval,
                                            conn_latency=self.conn_latency,
                                            supervision_timeout=self.supervision_timeout)
            time.sleep(3)

            logger().info(f"....Applying performance profile mode and Enable_bt_power_save....")
            self.ble_dut.interfaces.bluetooth.set_performance_profile(mode="power_save_low_latency")
            self.ble_dut.interfaces.bluetooth.enable_bt_power_save()

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

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=self.char_path)

            if self.test_case == 34483:
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

                write_handle = int(write_handles[index], 16)
                logger().info(f"write_handle:{write_handle}")
                assert write_handle > 0, "Unable to get write handle for configured service"

                self.credentials = []
                data = [self.wifi_access_point.interfaces.wifi.ssid, self.wifi_access_point.interfaces.wifi.passphrase,
                        self.wifi_access_point.interfaces.wifi.security.name.lower()]

                for length in range(len(data)):
                    self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                        ble_remote_dev_address=self.ble_client_address, handle=(write_handle + 1), enable_notify=1)
                    time.sleep(1)

                    since_time = time.perf_counter_ns()

                    logger().info("******************** Sending data to DUT ***********************")
                    self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data[length])
                    time.sleep(1)
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
                        ble_remote_dev_address=self.ble_client_address, handle=(write_handle + 1), enable_notify=0)
                    time.sleep(3)

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

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
            logger().info(f' ******* received ssid and security on remote device is : {notifications} *******')

            assert notifications, ".... received data is empty ...."
            # assert notifications == [str(ssid)], ".... SSID or Security Mismatch or Acknowledgement not received
            # ....."
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

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=self.device_ip)
        time.sleep(3)
        logger().info("******************** Validate Data ********************")
        notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications_data} ***********************')
        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [self.device_ip], ".... Device IP Mismatched or Acknowledgement not received ....."

        # logger().info(f' *********************** unsubscribe to notifications ***********************')
        # self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        # time.sleep(5)
        # self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        # time.sleep(3)

    def ble_remove_servie(self):
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_disconnect(self):
        logger().info("*********************** Disconnecting from DUT ***********************")
        self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
        self.ble_client.interfaces.bluetooth.close()

    def ping_with_custom_interval_and_size(self, ping_count, interval, size):
        command = ["ping", "-c", str(ping_count), "-i", str(interval), "-s", str(size), self.device_ip]
        result = subprocess.run(command, capture_output=True)
        rc = result.returncode
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        if rc != 0 or stderr:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}\n{stderr}")
        else:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}")


class SnifferValidationProcess:
    def __init__(
            self,
            wifi_sniffer=None,
            wifi_access_point=None,
            dut_mac_address=None,
            ap_mac_address=None,
            sniffer_filter=None,
            sl_collections=None,
    ):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sl_collections = sl_collections
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_validation_join(self, tcp_ip_bypass=False):
        self.sl_collections.join_sniffer_validation(
            self.wifi_access_point,
            self.wifi_sniffer,
            self.dut_mac_address,
            self.ap_mac_address,
            self.sniffer_filter,
            power_save=self.power_save,
        )
        if not tcp_ip_bypass:
            self.sniffer_validation_powersave()

    def sniffer_validation_deauth(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="deauthentication"
            )
        )
        logger().info(f"Validating de-authentication frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find de-authentication packets in sniffer"

    def sniffer_validation_scan(self):

        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="probe_request"
            )
        )
        logger().info(f"Validating Probe req(Broadcast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find probe_request packets in sniffer"

    def sniffer_validation_powersave(self):
        if self.power_save:
            packet_filter1 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address, filter_name="ps_poll"
                )
            )
            logger().info(f"Validating PS-POLL frames ")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter1
            )["packet_count"], "Sniffer: Unable to find ps poll packets in sniffer"
            packet_filter2 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="qos_data_more_data",
                )
            )
            logger().info(f"Validating QOS data frames with more data bit set")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find QOS data frames with more data bit set in sniffer"


class FilterPacket:
    """This class is used to filter the packets from the sniffer capture"""

    def delta_between_ps_poll_and_null_fn(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = (line[count].strip().split(':')[1].replace(']', '').
                                                   strip().replace('seconds', ''))
                """time_delta_from_previous_packet should be greater than 20 milli seconds and less than 35 milli seconds"""
                if (float(time_delta_from_previous_packet) >= 0.020) and (
                        float(time_delta_from_previous_packet) <= 0.035):
                    time_diff_list.append(float(time_delta_from_previous_packet))
        filter_file.close()
        logger().info(f"Time delta between PS-POLL to NULL FUNCTION packets: {time_diff_list}")
        return time_diff_list

    def delta_between_qos_data_and_null_fn(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = (line[count].strip().split(':')[1].replace(']', '').
                                                   strip().replace('seconds', ''))
                """time_delta_from_previous_packet should be greater than 45 milli seconds and less than 55 milli 
                seconds """
                if (float(time_delta_from_previous_packet) >= 0.045) and (
                        float(time_delta_from_previous_packet) <= 0.055):
                    time_diff_list.append(float(time_delta_from_previous_packet))
        filter_file.close()
        logger().info(f"Time delta between QoS data and null function packets : {time_diff_list}")
        return time_diff_list


# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for Wi-Fi scan, connectivity, power save, data transfer"""

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            net_perf_client=None,
            protocol=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            region=None,
            switch=None,
            pmk_enable=False,
            traffic_type="TX",
            tcp_ip_bypass=False,
            enc="ccmp",
            timeout=60,
            http_server=None,
            index_path=None
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.pmk_enable = pmk_enable
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.traffic_type = traffic_type
        self.tcp_ip_bypass = tcp_ip_bypass
        self.enc = enc
        self.timeout = timeout
        self.http_server = http_server
        self.index_path = index_path
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, 5):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                                 channel=0)
            logger().info(f"scan results : {scan_results}")
            assert len(scan_results) > 0, "scan failed"
            time.sleep(5)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address}")

    def run_traffic(self, protocol="TCP", traffic_type="TX"):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=protocol,
            device_ip=self.device_ip,
            host_ip=host_ip,
            timeout=self.timeout,
            traffic_type=traffic_type,
        )

    def ping_with_custom_interval_and_size(self, ping_count, interval, size):
        command = ["ping", "-c", str(ping_count), "-i", str(interval), "-s", str(size), self.device_ip]
        result = subprocess.run(command, capture_output=True)
        rc = result.returncode
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        if rc != 0 or stderr:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}\n{stderr}")
        else:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}")

    def join_to_ap(self, skip_power_save=False):

        if not self.wifi_dut.interfaces.wifi.associated:

            if skip_power_save:
                pwr_save = False
            else:
                pwr_save = self.power_save
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=pwr_save,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                ping_after_power_save=True,
                ping_count=self.ping_count,
                pmk_enable=self.pmk_enable,
                tcp_ip_bypass=self.tcp_ip_bypass,
                enc=self.enc
            )
            if not self.tcp_ip_bypass:
                self.device_ip = self.dut_addr["device_ip"]
            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            return self.dut_addr

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def run(self):
        if self.test_type == "fast_ping":
            assert self.ping_with_custom_interval_and_size(ping_count=100, interval=0.05,
                                                           size=300), "DUT NOT ABLE TO FAST PING......"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info('ap.mac_address : ' + self.ap_mac_address)
            logger().info('dut.mac_address : ' + self.dut_mac_address)
            logger().info("Running data transfer")
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

        if self.test_type == "throughput":
            self.join_to_ap()
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            protocols = ["TCP", "UDP"]
            traffic_types = ["TX", "RX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=self.device_ip,
                        host_ip=host_ip,
                        timeout=50,
                        traffic_type=traffic_type,
                    )


class BleThread_anchorpoints(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None

    def disconnect(self):
        self.ble_client.interfaces.bluetooth.disconnect()

    def run(self):
        Connection_Handle = "0x61 0x00"
        Connection_Interval_Min = "0x0c 0x00"
        Connection_Interval_Max = "0x0c 0x00"
        Max_Latency = "0x00 0x00"
        Supervision_Timeout = "0x00 0xC8"
        Min_CE_Length = "0x00 0x00"
        Max_CE_Length = "0x00 0x00"
        logger().info(f"Set up DUT for BLE advertising")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert self.ble_dut_address, f"Unable to find ble dut address"
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=120)

        logger().info(f"Begin Scanning for BLE devices")
        logger().info("Executing lescan in raspi")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address)
        assert self.ble_client_address, "Unable to get BLE client address"
        time.sleep(1)
        logger().info(f"Stop Scanning for BLE devices")
        self.ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("Initiating BLE connection")
        self.ble_client.interfaces.bluetooth.connect(self.ble_dut_address)
        logger().info("BLE Connection success")
        time.sleep(5)

        # setting data length on ble_client
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
            logger().info("Updating ble connection with connection parameters")
            self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(dev_addr=self.ble_dut_address,
                                                                                  connection_handle=Connection_Handle,
                                                                                  connection_interval_min=Connection_Interval_Min,
                                                                                  connection_interval_max=Connection_Interval_Max,
                                                                                  max_latency=Max_Latency,
                                                                                  supervision_timeout=Supervision_Timeout,
                                                                                  min_ce_length=Min_CE_Length,
                                                                                  max_ce_length=Max_CE_Length
                                                                                  )
        # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
        time.sleep(300)
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        logger().info("Disconnect BLE connection")
        self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        logger().info("BLE disconnect successful")


# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            ble_client=None,
            ble_test_type=None,
            sl_collections=None,
            ble_scan_type=1,
            ble_pairing=0,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
            set_smp=self.ble_pairing
        )
        assert (
                self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()
        self.ble_client.interfaces.bluetooth.close()

    def ble_disconnect(self, disconnect_from="remote"):

        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from,
            ble_client_address=self.ble_client_address,
        )

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_and_connect_from_remote(self):
        self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            timeout=30,
        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                timeout=20,
            )

        if self.ble_test_type == "scan":
            self.sl_collections.check_ble_scan_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_address=self.ble_dut_address,
                ble_scan_type=self.ble_scan_type,
                timeout=60,
            )
        if self.ble_test_type == "start_scan_stop_scan":
            # Start scanning
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=self.ble_client_address, timeout=60
            )
            logger().info(
                f"Remote device found in scan results, BLE scanning is successful"
            )
            # Stop scanning
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        if self.ble_test_type == "slave" or self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                mode=self.ble_test_type,
                ble_pairing=self.ble_pairing,
            )
        if self.ble_test_type == "scan_from_remote_device":
            self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
            )

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()


def cleanup_ble(ble_client, ble_dut_address):
    status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
    if status:
        logger().info(f"Initiating BLE disconnection from raspi")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    ble_client.interfaces.bluetooth.close()


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                               | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
]


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_wifi_ble_sdk_wlan_udp_rx_ble_conn_disconn_C34469(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                          request, utf_constants, sl_collections, wifi_client,
                                                          sniffer_filter, net_perf_client, protocol):
    """
    Test Steps:
        1. Start Sniffer Capture
        2. Wi-Fi initialization
        3. Wi-Fi Join(Scan, connect, get_ip, ping before PS, PS, ping after PS)
        4. UDP RX
        5. Start BLE advertising
        6. Initiating BLE connection(from Raspi)
        7. BLE disconnection
        8. Close UDP socket
        9. Stop Sniffer Capture
        10. Validate Sniffer Packets
    """
    ble_dut_addr = ''
    try:
        packet_filter2 = "    Type/Subtype: Null function (No data) (0x0024)"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = 'iperf'
        filter_obj = FilterPacket()
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_and_connect_from_dut")
        wifi_obj.join_to_ap(skip_power_save=False)
        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        wifi_obj.run_traffic(protocol="UDP", traffic_type="RX")
        ble_obj.ble_disconnect()
        time.sleep(5)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        'Validating sniffer packets'
        """1. Filter out only PS-Poll frames and Null function frames"""
        logger().info("\n1. PS-Poll and Null frames validation")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_mac_address,
            filter_name='wait_time')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count']
        delta_between_ps_poll_packet = filter_obj.delta_between_ps_poll_and_null_fn()
        if len(delta_between_ps_poll_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
        """2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)"""
        logger().info(
            "\n2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)")
        packet_filter4 = "    Type/Subtype: Null function (No data) (0x0024)"
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.dut_mac_address,
            filter_name='inactivity_timeout')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter4)['packet_count']
        delta_between_qos_data_packet = filter_obj.delta_between_qos_data_and_null_fn()
        if len(delta_between_qos_data_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        cleanup_ble(ble_client, ble_dut_addr)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "OPEN"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated"
    ],
)
def test_wifi_ble_sdk_wlan_fast_ping_ble_commissioning_C34483(wifi_sniffer, wifi_access_point, ble_dut, wifi_dut,
                                                              ble_client,
                                                              request, utf_constants, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Start Sniffer Capture
        2. Wi-Fi initialization
        3. Start BLE advertising
        4. Initiating BLE connection(using commissioning)
        5. List of APs once displayed, select the AP to connect
        6. Connect to the AP
        7. Enable the Power Save
        8. Do fast ping test
        9. Stop Sniffer Capture
        10. Validate Sniffer Packets
    """
    ble_dut_addr = ''
    ble_obj = ""
    try:
        packet_filter2 = "    Type/Subtype: Null function (No data) (0x0024)"
        test_name = request.node.name
        filter_obj = FilterPacket()
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=1,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=34483)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ping_with_custom_interval_and_size(ping_count=400, interval=0.05, size=300)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')
        logger().info("\n********************** Stopping the capture *************************")
        wifi_sniffer.interfaces.capture.stop_capture()

        'Validating sniffer packets'
        """1. Filter out only PS-Poll frames and Null function frames"""
        logger().info("\n1. PS-Poll and Null frames validation")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name='wait_time')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count']
        delta_between_ps_poll_packet = filter_obj.delta_between_ps_poll_and_null_fn()
        if len(delta_between_ps_poll_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
        """2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)"""
        logger().info(
            "\n2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)")
        packet_filter4 = "    Type/Subtype: Null function (No data) (0x0024)"
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=dut_mac_address,
            filter_name='inactivity_timeout')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter4)['packet_count']
        delta_between_qos_data_packet = filter_obj.delta_between_qos_data_and_null_fn()
        logger().info(f"Time delta between QoS data and null function packets : {delta_between_qos_data_packet}")
        if len(delta_between_qos_data_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "OPEN"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated"
    ],
)
def test_wifi_ble_sdk_wlan_fast_ping_ble_anchorpoints_C34484(
        wifi_sniffer, wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter):
    """
    Test Steps:
        1. Start Sniffer Capture
        2. Wi-Fi initialization
        3. Start BLE advertising
        4. Initiating BLE connection using hcitool commands
        5. Wi-Fi Join(Scan, connect, get_ip, ping before PS, PS, ping after PS)
        6. Fast ping test
        7. BLE connect and disconnect multiple times from remote dongle
        8. Stop Sniffer Capture
        9. Validate Sniffer Packets
    """
    ble_cli = ""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = 'fast_ping'
        filter_obj = FilterPacket()
        packet_filter2 = "    Type/Subtype: Null function (No data) (0x0024)"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_dut=wifi_dut,
                                  wifi_access_point=wifi_access_point,
                                  testcase=test_name,
                                  wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count,
                                  sniffer_filter=sniffer_filter,
                                  test_type=test_type)
        ble_cli = BleThread_anchorpoints(wifi_dut, ble_client)
        wifi_obj.join_to_ap(skip_power_save=False)
        ble_cli.start()
        time.sleep(10)
        ble_cli.wait_for_exit()
        wifi_obj.ping_with_custom_interval_and_size(ping_count=300, interval=0.05, size=300)
        wifi_sniffer.interfaces.capture.stop_capture()
        'Validating sniffer packets'
        """1. Filter out only PS-Poll frames and Null function frames"""
        logger().info("\n1. PS-Poll and Null frames validation")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_mac_address,
            filter_name='wait_time')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count']
        delta_between_ps_poll_packet = filter_obj.delta_between_ps_poll_and_null_fn()
        if len(delta_between_ps_poll_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
        """2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)"""
        logger().info(
            "\n2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)")
        packet_filter4 = "    Type/Subtype: Null function (No data) (0x0024)"
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.dut_mac_address,
            filter_name='inactivity_timeout')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter4)['packet_count']
        delta_between_qos_data_packet = filter_obj.delta_between_qos_data_and_null_fn()
        if len(delta_between_qos_data_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.remove_device(ble_cli.ble_dut_address)
        if ble_cli is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_cli.ble_client_address,
                                       ble_dut_address=ble_cli.ble_dut_address)



@pytest.mark.skip('SI91X-16219')
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "OPEN"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated"
    ],
)
# ENHANCED MAX PSP_34488:
def test_wifi_ble_sdk_wlan_fast_ping_ble_dual_C34488(
        wifi_sniffer, wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol):
    """
        Test Steps:
            1. Start Sniffer Capture
            2. Wi-Fi initialization
            3. Wi-Fi Join(Scan, connect, get_ip, ping before PS, PS, ping after PS)
            4. FAST Ping Test
            5. start BLE advertising from Remote device(Raspi)
            6. Start BLE scanning
            7. Initiate BLE connection from DUT_BLE.
            8. BLE disconnection from DUT_BLE.
            9. Re-initiate BLE connection from DUT_BLE.
            10. BLE disconnection from DUT_BLE.
            11. Stop Sniffer Capture
            12. Validate Sniffer Packets
        """
    ble_dut_addr = ''
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = 'fast_ping'
        filter_obj = FilterPacket()
        packet_filter2 = "    Type/Subtype: Null function (No data) (0x0024)"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_dut=wifi_dut,
                                  wifi_access_point=wifi_access_point,
                                  testcase=test_name,
                                  wifi_client=wifi_client,
                                  net_perf_client=net_perf_client,
                                  sl_collections=sl_collections,
                                  protocol=protocol,
                                  ping_count=ping_count,
                                  sniffer_filter=sniffer_filter,
                                  test_type=test_type)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_and_connect_from_dut")
        wifi_obj.join_to_ap(skip_power_save=False)
        wifi_obj.ping_with_custom_interval_and_size(wifi_obj.device_ip, ping_count=100, interval=0.05, size=300)
        for i in range(0, 3):
            ble_obj.advertise_dut()
            time.sleep(0.5)
            ble_obj.scan_and_connect_from_remote()
            time.sleep(0.5)
            ble_obj.advertise_remote_device()
            time.sleep(0.5)
            ble_obj.scan_and_connect_from_dut()
            time.sleep(10)
            ble_obj.ble_disconnect()
            logger().info('\n\n Time sleep! Wait for 20 seconds......')
            time.sleep(20)
        wifi_obj.ping_with_custom_interval_and_size(ping_count=100, interval=0.05, size=300)
        wifi_obj.disconnect()
        """1. Filter out only PS-Poll frames and Null function frames"""
        logger().info("\n1. PS-Poll and Null frames validation")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_mac_address,
            filter_name='wait_time')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count']
        delta_between_ps_poll_packet = filter_obj.delta_between_ps_poll_and_null_fn()
        if len(delta_between_ps_poll_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
        """2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)"""
        logger().info(
            "\n2. Check for Null Function from DUT in the time delta between QoS Data and Null Function(45ms to 55ms)")
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.dut_mac_address,
            filter_name='inactivity_timeout')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter2)['packet_count']
        delta_between_qos_data_packet = filter_obj.delta_between_qos_data_and_null_fn()
        if len(delta_between_qos_data_packet) >= 3:
            logger().info("Test case passed")
            assert True
        else:
            logger().info("Test case failed")
            assert False
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        cleanup_ble(ble_client, ble_dut_addr)
