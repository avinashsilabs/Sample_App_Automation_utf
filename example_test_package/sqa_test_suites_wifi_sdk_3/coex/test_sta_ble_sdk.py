import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
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
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.time_measurer import TimeMeasurer
from datetime import datetime, date
import re



def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set Region ,scan ,connect, data transfer

    Author: Swathi.Chinthala

"""


class SnifferValidationProcess:
    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, sniffer_filter=None, sl_collections=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sl_collections = sl_collections
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_validation_join(self):
        power_save = True
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=self.power_save)

        self.sniffer_validation_powersave()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
            get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='deauthentication')
        logger().info(f"Validating deauthentication frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                       packet_filter1)['packet_count'], \
            'Sniffer: Unable to find deauthentication packets in sniffer'

    def sniffer_validation_scan(self):

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
            get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='probe_request')
        logger().info(f"Validating Probe req(Broadcast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                       packet_filter1)['packet_count'], \
            'Sniffer: Unable to find probe_request packets in sniffer'

    def sniffer_validation_powersave(self):
        if self.power_save:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='ps_poll')
            logger().info(f"Validating PS-POLL frames ")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter1)['packet_count'], \
                'Sniffer: Unable to find ps poll packets in sniffer'
            packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address,
                                   filter_name='qos_data_more_data')
            logger().info(f"Validating QOS data frames with more data bit set")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter2)['packet_count'], \
                'Sniffer: Unable to find QOS data frames with more data bit set in sniffer'

# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, test_type=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, region=None, switch=None, pmk_enable=False, traffic_type="TX",
                 tcp_ip_bypass=False):

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
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, 5):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) > 0), "scan failed"
            time.sleep(5)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address }")

    def run_traffic(self, protocol="TCP", traffic_type="TX"):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=protocol, device_ip=self.device_ip,
                                        host_ip=host_ip, timeout=60, traffic_type=traffic_type)
    def set_power_save(self):

            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

    def join_to_ap(self, skip_power_save=False):

        if not self.wifi_dut.interfaces.wifi.associated:
            logger().info("Enabling rejoin...")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)

            if skip_power_save:
                pwr_save = False
            else:
                pwr_save = self.power_save
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=pwr_save,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3, ping_after_power_save=True,
                                                                     ping_count=self.ping_count,
                                                                     pmk_enable=self.pmk_enable,
                                                                     tcp_ip_bypass=self.tcp_ip_bypass)
            if not self.tcp_ip_bypass:
                self.device_ip = self.dut_addr['device_ip']
            self.dut_mac_address = self.dut_addr['dut_mac_address']
            logger().info(f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")

            return self.dut_addr

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation_join(self):
        sniff_obj = SnifferValidationProcess(wifi_sniffer=self.wifi_sniffer, wifi_access_point=self.wifi_access_point,
                                               dut_mac_address=self.dut_mac_address,
                                               ap_mac_address=self.ap_mac_address, sniffer_filter=self.sniffer_filter,
                                               sl_collections=self.sl_collections)
        sniff_obj.sniffer_validation_join()

    def sniffer_validation_scan(self):
        sniff_obj = SnifferValidationProcess(wifi_sniffer=self.wifi_sniffer, wifi_access_point=self.wifi_access_point,
                                               dut_mac_address=self.dut_mac_address,
                                               ap_mac_address=self.ap_mac_address, sniffer_filter=self.sniffer_filter,
                                               sl_collections=self.sl_collections)
        sniff_obj.sniffer_validation_scan()



    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            self.join_to_ap()
            status = ping(self.device_ip, 30, size=300)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

        if self.test_type == "throughput":
            self.join_to_ap()
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                            protocol="TCP", device_ip=self.device_ip,
                                            host_ip=host_ip, timeout=100, traffic_type="TX")
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                            protocol="TCP", device_ip=self.device_ip,
                                            host_ip=host_ip, timeout=50, traffic_type="RX")
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                            protocol="UDP", device_ip=self.device_ip,
                                            host_ip=host_ip, timeout=100, traffic_type="TX")
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                            protocol="UDP", device_ip=self.device_ip,
                                            host_ip=host_ip, timeout=100, traffic_type="RX")

        if self.test_type == "http":
            self.join_to_ap()
            logger().info("http download")





class ScanTime_JoinTime(ThreadBase):

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 test_type=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, all_channel_2_4=None, all_channel_5=None,
                 select_channel_2_4=None, select_channel_5=None):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.all_channel_2_4 = all_channel_2_4
        self.all_channel_5 = all_channel_5
        self.select_channel_2_4 = select_channel_2_4
        self.select_channel_5 = select_channel_5
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.pmk_enable = False

    def caluculate_scan_time(self):

        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        scan_results = self.wifi_dut.interfaces.wifi.scan(
            channel=0, ssid=None
        )
        assert len(scan_results) >= 1, "Scan failed"
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info(
            f"enables the scan in DUT with the given channel bitmap value"
        )
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_expected_time = 0

        if self.all_channel_2_4:
            channel_list = self.all_channel_2_4
        elif self.all_channel_5:
            channel_list = self.all_channel_5
        elif self.select_channel_2_4:
            channel_list = self.select_channel_2_4
        else:
            channel_list = self.select_channel_5

        if len(channel_list):

            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100

            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info("start capturing with Sniffer by giving the test case name as filename")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

                if self.all_channel_2_4:

                    with TimeMeasurer() as t:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            channel=0, ssid=None, sleep_time=0.1
                        )
                        assert len(scan_results) >= 1, "Scan failed"
                        logger().info(scan_results)
                    logger().info(f"Scan in {t.duration} seconds")
                    assert t.duration < 1.2, f"scan time {t.duration} should be less than 1200ms"

                if self.select_channel_2_4:

                    with TimeMeasurer() as t:
                        scan_resp = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                       scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       sleep_time=0.1)

                    assert t.duration < 0.4, f"scan time {t.duration} should be less than 400ms"
                    assert len(scan_resp) >= 1, "Scan response not found"
                    logger().info(f"scan_resp {scan_resp}")
                    logger().info(f"Scan in {t.duration} seconds")
                    channel_selected = 0
                    for count in scan_resp:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1
                    assert channel_selected == len(scan_resp), "channel list and scan response list are not equal"

                self.wifi_sniffer.interfaces.capture.stop_capture()

                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                    get_sniffer_filter(sa_addr=dut_mac_address, filter_name='probe_request')
                logger().info(f"Validating Probe req(Broadcast)")
                result = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                                 packet_filter1)['packet_count']

                if result:
                    logger().info(f"Probe request found in sniffer")
                else:
                    logger().info(
                        "**** Not able to find the probe request, So checking for the bssid in the specific "
                        "channel scan *** "
                    )

                    with TimeMeasurer() as t:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            channel=channel, ssid=None
                        )
                        assert len(scan_results) >= 1, "Scan failed"
                        logger().info(scan_results)
                    if ap_bssid.lower() in str(scan_results):
                        logger().info(
                            f"found ap bssid in scan_results for channel {channel}"
                        )
                    else:
                        assert False, "Unable to find ap in scan results"
                    logger().info(f"Scan in {t.duration} seconds")

    def join_to_ap(self, tcp_ip_bypass=False):

        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        wifi_obj = WifiJoinThread(wifi_sniffer=self.wifi_sniffer, wifi_dut=self.wifi_dut,
                                  wifi_access_point=self.wifi_access_point, testcase=self.testcase,
                                  wifi_client=self.wifi_client, sl_collections=self.sl_collections,
                                  ping_count=self.ping_count, sniffer_filter=self.sniffer_filter,
                                  test_type=self.test_type, tcp_ip_bypass=tcp_ip_bypass)

        self.dut_addr = wifi_obj.join_to_ap()
        if not tcp_ip_bypass:
            self.device_ip = self.dut_addr['device_ip']
        self.dut_mac_address = self.dut_addr['dut_mac_address']
        logger().info(f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************")
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

        self.wifi_sniffer.interfaces.capture.stop_capture()

    def caluculate_join_time(self):

        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address,
            filter_name='probe_req_response')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
            get_sniffer_filter(sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address,
                               filter_name='assoc_req_resp_eapol_4_way_handshake')

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], \
            'Sniffer: Unable to find probe_req_response packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                       packet_filter2=packet_filter2)[
            'packet_count'], \
            'Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'

        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter1 in x:
                result = re.search(r'\d+:\d+:\d+.\d+', x)
                logger().info(f" RESULT {result}")
                time_stamp = result.group()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        logger().info(f'time stamp list ={time_diff_list}')
        time_str1 = time_diff_list[0]
        time_str1 = time_str1[:-3]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
        logger().info(f'probe req time {time_object1}')

        time_str2 = time_diff_list[1]
        time_str2 = time_str2[:-3]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()

        logger().info(f'eapol key time {time_object2}')
        date1 = date(1, 1, 1)
        datetime1 = datetime.combine(date1, time_object1)
        datetime2 = datetime.combine(date1, time_object2)
        time_taken = datetime2 - datetime1
        time_taken = time_taken.total_seconds()
        assert time_taken <= 0.4, "join time is more than 400ms"
        logger().info(f"time taken to connect is: {time_taken}")
        time.sleep(2)


    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()


    def run(self):
        if self.test_type == "scan_time":
            self.caluculate_scan_time()

        if self.test_type == "join_time":
            self.caluculate_join_time()



# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, ble_scan_type=1,
                 ble_pairing=0):
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
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert self.ble_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()

    def ble_disconnect(self, disconnect_from="remote"):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)

    def advertise_remote_device(self):
        logger().info(f"Advertising the Remote BLE device")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.ble_dut_address,
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert self.ble_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"advertised remote BLE device")

    def advertise_dut(self):

        logger().info(f"Advertising the DUT")

        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_from_remote_device(self):
        logger().info("Initiating scan from Remote device")
        # Begin Scanning for BLE devices
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address)
        assert self.ble_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Started scan from remote BLE device")
        logger().info("\n***********{}**********\n".format(self.ble_client_address))

        for i in range(0, 3):
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))
            time.sleep(5)
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
        logger().info(f"DUT BLE address:'{self.ble_dut_address}' found in raspi scan results")
        self.ble_client.interfaces.bluetooth.stop_scanning()


    def scan_and_connect_from_dut(self):

        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address, timeout=60)

        logger().info(f"Remote device found in scan results ,BLE scanning is successful")

        self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.ble_client_address, timeout=60)
        logger().info(f"Ble connection is successful")

    def scan_and_connect_from_remote(self):

        self.scan_from_remote_device()
        self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address)
        logger().info("Connect ble_client to DUT successful")


    def run(self):
        if self.ble_test_type == "advertise":
            self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                  ble_dut_address=self.ble_dut_address,
                                                                  timeout=20)

        if self.ble_test_type == "scan":
            self.sl_collections.check_ble_scan_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                             ble_address=self.ble_dut_address,
                                                             ble_scan_type=self.ble_scan_type,
                                                             timeout=60)
        if self.ble_test_type == "start_scan_stop_scan":

            # Start scanning
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                        timeout=60)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")
            # Stop scanning
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()


        if self.ble_test_type == "slave":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.ble_dut_address,
                                                                         mode="slave", ble_pairing=self.ble_pairing)

        if self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.ble_dut_address,
                                                                         mode="master", ble_pairing=self.ble_pairing)

        if self.ble_test_type == "scan_from_remote_device":
            self.scan_from_remote_device()

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()


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
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

        }
    )
]

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_fun_ble_slave_wlan_conn_C133428(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Conenct DUT as BLE slave
          3. Join the access point and enable the dhcp
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Initiate ping from the dut

      """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                     ble_test_type="slave")
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client,
                              sl_collections=sl_collections,
                              ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_obj.disconnect()
    ble_obj.ble_disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_fun_ble_master_wlan_conn_C133429(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Conenct DUT as BLE master
          3. Join the access point and enable the dhcp
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Initiate ping from the dut

      """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                     ble_test_type="master")
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client,
                              sl_collections=sl_collections,
                              ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_obj.disconnect()
    ble_obj.ble_disconnect(disconnect_from="dut")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890', "beacon_interval": 200})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_conn_while_BLE_scan_C133430(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Scan from DUT check whether dut is able to find remote device
               2. Join the access point and enable the dhcp
               3. Enable the wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890', "beacon_interval": 500})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_conn_request_WLAN_conn_C133431(wifi_dut, wifi_sniffer, wifi_access_point,  ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Scan from DUT check whether dut is able to find remote device
               4. Initiate connection request from DUT to remote device
               5. Join the access point and enable the dhcp
               6. Enable the wlan and bt power save mode in dut after the connection
               7. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info(
            "\n******* Validating the LE connection complete print in bt_mon logs as there is no BT sniffer support currently  *******")
        logger().info("\n*******btmon started*******")
        bt_mon_log_file_name = f"reports/ble_conn_req_wlan_connection_C133431_{int(time.time())}.log"
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=bt_mon_log_file_name):
            ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                             ble_test_type="master")
            ble_obj.start()
            ble_obj.wait_for_exit()

        # Opening the btmon log and searching for the required strings in it
        with open(bt_mon_log_file_name, "r") as file_p:
            for data_line in file_p:
                if "LE Connection Complete (0x01)" in data_line:
                    con_flag = 1
                if "Slave (0x01)" in data_line:
                    role_flag = 1
                    break
            if con_flag and role_flag:
                logger().info(
                    "\n******* Found LE Connection Complete (0x01) and Slave (0x01) strings in bt_mon logs *******")
            else:
                assert con_flag, "******LE Connection Complete (0x01) string not found******"
                assert role_flag, "******Slave (0x01) string not found******"

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_conn_while_BLE_active_scan_C133432(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable active Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable the wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_type=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_conn_while_BLE_passive_scan_C133433(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable passive Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_type=0)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_scan_BLE_scan_C133445(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                             request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Initiate BLE scan from DUT and check whether dut is able to find remote device
               3. Initiate WLAN scan from DUT and check whether dut is able to find remote device
           """

    try:
        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_type=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_type="scan")
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_scan_while_WLAN_conn_C133568(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Join the access point and enable the dhcp
               3. Enable wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
               5. Advertise remote Raspi device
               6. Scan from DUT check whether dut is able to find remote device
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="start_scan_stop_scan")
        wifi_obj.join_to_ap()
        ble_obj.advertise_remote_device()
        for i in range(iter_count):
            ble_obj.start()
            ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_disconnect_BLE_slave_C133502(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Disconnect from DUT to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_disconnect_BLE_peripheral_C133466(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Disconnect from DUT to AP
               8. Connect from DUT to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_obj.join_to_ap()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_BLE_conn_disconn_slave_WLAN_conn_C133503(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Disconnect from remote BLE device
               8. Scan and reconnect from remote BLE device
               9. Repeat step 7 & 8
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        ble_obj.ble_disconnect()
        ble_client.interfaces.bluetooth.close()
        for i in range(0, iter_count):
            #ble_obj.scan_and_connect_from_remote()
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.ble_disconnect()
            ble_client.interfaces.bluetooth.close()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_conn_disconn_master_WLAN_conn_C133520(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise remote BLE device
               4. Scan from DUT device and intiate connection from DUT as master
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Disconnect from DUT BLE device
               8. Scan and reconnect from DUT
               9. Repeat step 7 & 8
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        ble_obj.ble_disconnect(disconnect_from="dut")
        ble_client.interfaces.bluetooth.close()
        for i in range(0, iter_count):
            # ble_obj.scan_and_connect_from_dut()
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.ble_disconnect(disconnect_from="dut")
            ble_client.interfaces.bluetooth.close()

        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_BLE_conn_disconn_slave_WLAN_conn_C133487(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Join the access point and enable the dhcp
               5. Enable wlan and bt power save mode in dut after the connection
               6. Scan from remote BLE device and connect to DUT
               7. Disconnect from remote BLE device
               8. Scan and reconnect from remote BLE device
               9. Repeat step 7 & 8
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.advertise_dut()

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.ble_disconnect()
        ble_client.interfaces.bluetooth.close()
        for i in range(0, iter_count):
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.ble_disconnect()
            ble_client.interfaces.bluetooth.close()

        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_TCP_UDP_TX_WPA2_BLE_slave_C133475(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,UDP-TX
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic(protocol="TCP", traffic_type="TX")
        wifi_obj.run_traffic(protocol="UDP", traffic_type="TX")
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_TCP_UDP_RX_WPA2_BLE_slave_C133476(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-RX ,UDP-RX
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic(protocol="TCP", traffic_type="RX")
        wifi_obj.run_traffic(protocol="UDP", traffic_type="RX")
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_throughput_open_BLE_slave_C133449(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on open security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, net_perf_client=net_perf_client, protocol=protocol,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_WLAN_throughput_WPA2_BLE_slave_C133450(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, net_perf_client=net_perf_client, protocol=protocol,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_all_channels_scan_time_BLE_adv_C133453(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Wlan Scan in all channels from DUT and calculate time taken to scan in all channels
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan_time"
        all_channel_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     all_channel_2_4=all_channel_2_4)

        ble_obj.advertise_dut()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan", "ble_stop_adv"])
def test_Coex_sdk_selected_channels_scan_time_BLE_slave_C133454(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Wlan Scan in all channels from DUT and calculate time taken to scan in all channels
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan_time"
        select_channel_2_4 = [1, 6, 11]

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     select_channel_2_4=select_channel_2_4)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan", "ble_stop_adv"])
def test_Coex_sdk_join_time_BLE_slave_C133458(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. WLAN scan and connect to AP with PMK and enable power save
               4. Caluculate the time taken to connect to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "join_time"

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter)
        wifi_obj.join_to_ap()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_ADV_BLE_while_WLAN_SCAN_C133551(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Wlan Scan in all channels from DUT
               2. Advertise BLE DUT
               3. Scan from remote BLE device
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"

        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_type="scan")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise")
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_ADV_BLE_while_WLAN_TCP_RX_C133552(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Wlan Scan ,connect ,ip ,powersave,ping
               4. Run TCP RX
               5. Scan from remote BLE device
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type="iperf", traffic_type="RX")
        wifi_obj.join_to_ap()

        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        ble_client.interfaces.bluetooth.close()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_TCP_RX_while_BLE_continuous_scan_C133555(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                                request, utf_constants, sl_collections, wifi_client,
                                                                sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable the wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut and run TCP RX
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type="iperf", traffic_type="RX")
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_fun_ble_slave_wlan_conn_disconn_C133554(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Conenct DUT as BLE slave
          3. Join the access point and enable the dhcp
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Initiate ping from the dut
          6. wlan disconnect
          7. Repeat steps from 3-6 for 5 iterations

      """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                     ble_test_type="slave")
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client,
                              sl_collections=sl_collections,
                              ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

    for count in range(0, iter_count):
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
    ble_obj.ble_disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_TCP_UDP_TX_WPA2_BLE_slave_C133475(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Advertise BLE DUT
               4. Scan from remote BLE device and connect to DUT
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,UDP-TX
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic(protocol="TCP", traffic_type="TX")
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_active_scan_when_WLAN_conn_C133560(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable active Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable the wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_type=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_scan_while_TCP_TX_C133573(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                request, utf_constants, sl_collections, wifi_client,
                                                sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Scan from DUT check whether dut is able to find remote device
               2. Join the access point and enable the dhcp
               3. Enable the wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter,
                                  net_perf_client=net_perf_client, protocol=protocol,
                                  test_type=test_type)
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_ble_bd_addr_wlan_TCP_TX_C133564(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                  utf_constants, sl_collections, wifi_client, sniffer_filter,
                                                  net_perf_client, protocol):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Join the access point and enable the dhcp
          3. Conenct DUT as BLE master
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Run TCP-TX
          6. query for local bd address

      """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type,
                                  net_perf_client=net_perf_client, protocol=protocol)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                        ble_test_type="scan_and_connect_from_dut")
        ble_obj.advertise_remote_device()
        wifi_obj.join_to_ap()
        wifi_obj.start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.bt_get_local_address()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.skip("SMP pairing not working")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_SMP_DUT_UDP_RX_C133443(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                         request, utf_constants, sl_collections, wifi_client,
                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Join the access point and enable the dhcp
               4. Enable wlan and bt power save mode in dut after the connection
               5. Do Wi-Fi data transfer UDP-RX
               6. Advertise BLE DUT
               7. Scan from remote BLE device and connect to DUT through smp pairing
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master", ble_pairing=1)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type, traffic_type="RX")
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip("SMP pairing not working")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_SMP_Encryption_DUT_UDP_TX_C133440(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                         request, utf_constants, sl_collections, wifi_client,
                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Join the access point and enable the dhcp
               4. Enable wlan and bt power save mode in dut after the connection
               5. Do Wi-Fi data transfer UDP-TX
               6. Advertise BLE DUT
               7. Scan from remote BLE device and connect to DUT through smp pairing
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master", ble_pairing=1)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type, traffic_type="RX")
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.skip("SMP pairing not working")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_SMP_PAIR_REQ_DUT_UDP_RX_C133441(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                         request, utf_constants, sl_collections, wifi_client,
                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Join the access point and enable the dhcp
               4. Enable wlan and bt power save mode in dut after the connection
               5. Do Wi-Fi data transfer UDP-RX
               6. Advertise BLE DUT
               7. Scan from remote BLE device and connect to DUT through smp pairing
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master", ble_pairing=1)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type, traffic_type="RX")
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.skip("SMP pairing not working")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_SMP_PAIR_RESP_DUT_TCP_TX_C133442(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client,
                                                   sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on WPA2 security
               3. Join the access point and enable the dhcp
               4. Enable wlan and bt power save mode in dut after the connection
               5. Do Wi-Fi data transfer UDP-RX
               6. Advertise BLE DUT
               7. Scan from remote BLE device and connect to DUT through smp pairing
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave", ble_pairing=1)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  sl_collections=sl_collections, protocol=protocol, ping_count=ping_count,
                                  sniffer_filter=sniffer_filter, test_type=test_type, traffic_type="RX")
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.skip("PMK connection issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv", "ble_stop_scan"])
def test_Coex_sdk_join_time_WPA2_PMK_BLE_Adv_C133460(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. WLAN scan and connect to AP with PMK and enable power save
               4. Scan from remote BLE device and connect to DUT
               5. Caluculate the time taken to connect to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "join_time"

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        ble_obj.advertise_dut()

        for i in range(0, iter_count):

            wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                         wifi_access_point=wifi_access_point, testcase=test_name,
                                         wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                         ping_count=ping_count, sniffer_filter=sniffer_filter)
            wifi_obj.start()
            ble_obj.start()
            wifi_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            logger().info("Initiating stop scan from Remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            wifi_obj.disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

