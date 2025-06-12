import time
import pytest
import pandas as pd
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
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap
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
        5. set scan ,connect, ping data transfer


    Author: Ramakrishna.Myneni
"""

ble_obj = None


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
        power_save = True
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
        logger().info(f"Validating deauthentication frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find deauthentication packets in sniffer"

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


# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

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
            index_path=None,
            http_client=None,
            https=0,
            scan_count=5,
            mac=None,
            async_socket=0,
            address=None,
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
        self.mac = mac
        self.timeout = timeout
        self.http_client = http_client
        self.http_server = http_server
        self.https = https
        self.index_path = index_path
        self.scan_count = scan_count
        self.async_socket = async_socket
        self.throughput_remote = None
        self.throughput_dut = None
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self.address = address
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, self.scan_count):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                                 channel=0)
            logger().info(f"scan results : {scan_results}")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address}")

    def set_power_save(self):

        if self.power_save:

            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        else:
            logger().info("skipping power save because power save flag set to be false in harness")

    def join_to_ap(self, skip_power_save=False):

        if not self.wifi_dut.interfaces.wifi.associated:
            logger().info("Enabling rejoin...")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=6,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )

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
                ping_before_power_save=True,
                ping_after_power_save=True,
                ping_count=self.ping_count,
                pmk_enable=self.pmk_enable,
                tcp_ip_bypass=self.tcp_ip_bypass,
                enc=self.enc,
                mac=self.mac
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

    def sniffer_validation_join(self, de_auth=False):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_join(tcp_ip_bypass=self.tcp_ip_bypass)
        if de_auth:
            sniff_obj.sniffer_validation_deauth()

    def sniffer_validation_scan(self):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_scan()

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            self.join_to_ap()
            logger().info("Initiating ping from Raspi to DUT to check stability")
            status = ping(self.device_ip, 30, size=300)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"


class BleAEThread(ThreadBase):
    def __init__(
            self,
            peripheral, adv_type, ble_dut_address,
            central=None, print_all_adv_devices=1, data_len=0, data_len_s2=None,
            pri_adv_phy=1, sec_adv_phy=1, adv_data="", adv_handle=0, duration=0, max_ae_events=0,
            min_interval=48, max_interval=48, min_interval_s2=64, max_interval_s2=64, sec_adv_max_skip=1,
            adv_async_required=0, own_address_type=0, peer_addr_type=0, random_address=None,
            random_address_s2=None, ConnIntervalMax=160, ConnIntervalMin=160,
            scan_req_notify_enable=1, scan_resp_len=0, whitelist=None, scanning_whitelist=None,
            adv_filter_policy=0, scanning_filter_policy=0, powersave_p=None, powersave_c=None,
            scanning_phys=1, adv_handle_s2=None, adv_type_s2=None, loop_count=0, adv_data_type=None,
            ble_sniffer=None, wifi_sniffer=None, bt_sniffer=None, periodic_data_len=None,
            test_case_id="nrf_logs", init_phys=7,
            test_in_progress=False, dont_cleanup=False, error_expected="*****", invalid_data_hdl=None,
            filter_duplicates=0, scan_duration=0, scan_period=0, scan_interval_pri=48, scan_interval_sec=48,
            scan_window_pri=48, scan_window_sec=30, initiator_filter_policy=0, connection_time=30,
            scan_type_pri=1, scan_type_sec=1, scan_set_2=0, stop_scan=1, ble_client_address=None, connect=None,
            ble_addr_type=0, remote_addr_type=0, sl_collections=None
    ):
        super().__init__()
        self.peripheral = peripheral
        self.adv_type = adv_type
        self.ble_dut_address = ble_dut_address
        self.central = central
        self.data_len = data_len
        self.data_len_s2 = data_len_s2
        self.pri_adv_phy = pri_adv_phy
        self.sec_adv_phy = sec_adv_phy
        self.adv_data = adv_data
        self.adv_handle = adv_handle
        self.duration = duration
        self.max_ae_events = max_ae_events
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.min_interval_s2 = min_interval_s2
        self.max_interval_s2 = max_interval_s2
        self.sec_adv_max_skip = sec_adv_max_skip
        self.adv_async_required = adv_async_required
        self.own_address_type = own_address_type
        self.peer_addr_type = peer_addr_type
        self.random_address = random_address
        self.random_address_s2 = random_address_s2
        self.ConnIntervalMax = ConnIntervalMax
        self.ConnIntervalMin = ConnIntervalMin
        self.scan_req_notify_enable = scan_req_notify_enable
        self.scan_resp_len = scan_resp_len
        self.whitelist = whitelist
        self.scanning_whitelist = scanning_whitelist
        self.adv_filter_policy = adv_filter_policy
        self.scanning_filter_policy = scanning_filter_policy
        self.powersave_p = powersave_p
        self.powersave_c = powersave_c
        self.scanning_phys = scanning_phys
        self.adv_handle_s2 = adv_handle_s2
        self.adv_type_s2 = adv_type_s2
        self.loop_count = loop_count
        self.adv_data_type = adv_data_type
        self.ble_sniffer = ble_sniffer
        self.bt_sniffer = bt_sniffer
        self.periodic_data_len = periodic_data_len
        self.test_case_id = test_case_id
        self.init_phys = init_phys
        self.dont_cleanup = dont_cleanup
        self.error_expected = error_expected
        self.invalid_data_hdl = invalid_data_hdl
        self.filter_duplicates = filter_duplicates
        self.scan_duration = scan_duration
        self.scan_period = scan_period
        self.scan_interval_pri = scan_interval_pri
        self.scan_interval_sec = scan_interval_sec
        self.scan_window_pri = scan_window_pri
        self.scan_window_sec = scan_window_sec
        self.initiator_filter_policy = initiator_filter_policy
        self.connection_time = connection_time
        self.scan_type_pri = scan_type_pri
        self.scan_type_sec = scan_type_sec
        self.stop_scan = stop_scan
        self.ble_client_address = ble_client_address
        self.connect = connect
        self.ble_addr_type = ble_addr_type
        self.remote_addr_type = remote_addr_type
        self.sl_collections = sl_collections
        self.test_in_progress = test_in_progress
        self.print_all_adv_devices = print_all_adv_devices
        self.wifi_sniffer = wifi_sniffer
        self.scan_set_2 = scan_set_2
        self.result = None

    def run(self):
        self.result = self.sl_collections.verify_adv(peripheral=self.peripheral, adv_type=self.adv_type,
                                                     ble_dut_address=self.ble_dut_address,
                                                     central=self.central,
                                                     print_all_adv_devices=self.print_all_adv_devices,
                                                     data_len=self.data_len, data_len_s2=self.data_len_s2,
                                                     pri_adv_phy=self.pri_adv_phy, sec_adv_phy=self.sec_adv_phy,
                                                     adv_data=self.adv_data, adv_handle=self.adv_handle,
                                                     duration=self.duration, max_ae_events=self.max_ae_events,
                                                     min_interval=self.min_interval, max_interval=self.max_interval,
                                                     min_interval_s2=self.min_interval_s2,
                                                     max_interval_s2=self.max_interval_s2,
                                                     sec_adv_max_skip=self.sec_adv_max_skip,
                                                     adv_async_required=self.adv_async_required,
                                                     own_address_type=self.own_address_type,
                                                     peer_addr_type=self.peer_addr_type,
                                                     random_address=self.random_address,
                                                     random_address_s2=self.random_address_s2,
                                                     ConnIntervalMax=self.ConnIntervalMax,
                                                     ConnIntervalMin=self.ConnIntervalMin,
                                                     scan_req_notify_enable=self.scan_req_notify_enable,
                                                     scan_resp_len=self.scan_resp_len, whitelist=self.whitelist,
                                                     scanning_whitelist=self.scanning_whitelist,
                                                     adv_filter_policy=self.adv_filter_policy,
                                                     scanning_filter_policy=self.scanning_filter_policy,
                                                     powersave_p=self.powersave_p, powersave_c=self.powersave_c,
                                                     scanning_phys=self.scanning_phys, adv_handle_s2=self.adv_handle_s2,
                                                     adv_type_s2=self.adv_type_s2, loop_count=self.loop_count,
                                                     adv_data_type=self.adv_data_type,
                                                     ble_sniffer=self.ble_sniffer, wifi_sniffer=self.wifi_sniffer,
                                                     bt_sniffer=self.bt_sniffer,
                                                     periodic_data_len=self.periodic_data_len,
                                                     test_case_id=self.test_case_id, init_phys=self.init_phys,
                                                     test_in_progress=self.test_in_progress,
                                                     dont_cleanup=self.dont_cleanup, error_expected=self.error_expected,
                                                     invalid_data_hdl=self.invalid_data_hdl,
                                                     filter_duplicates=self.filter_duplicates,
                                                     scan_duration=self.scan_duration, scan_period=self.scan_period,
                                                     scan_interval_pri=self.scan_interval_pri,
                                                     scan_interval_sec=self.scan_interval_sec,
                                                     scan_window_pri=self.scan_window_pri,
                                                     scan_window_sec=self.scan_window_sec,
                                                     initiator_filter_policy=self.initiator_filter_policy,
                                                     connection_time=self.connection_time,
                                                     scan_type_pri=self.scan_type_pri, scan_type_sec=self.scan_type_sec,
                                                     scan_set_2=self.scan_set_2, stop_scan=self.stop_scan,
                                                     ble_client_address=self.ble_client_address,
                                                     connect=self.connect, ble_addr_type=self.ble_addr_type,
                                                     remote_addr_type=self.remote_addr_type)


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
            capability=3,
            dev_state=8,
            conn_int=160,
            gatt=True,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.capability = capability
        self.dev_state = dev_state
        self.conn_int = conn_int
        self.gatt = gatt

        # Set up DUT for BLE advertising
        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
        else:
            # Set up DUT for BLE advertising
            logger().info("Initialising BLE")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
                set_smp=self.ble_pairing, capability=self.capability
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

    def check_scan_functionality_of_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=self.ble_scan_type,
            timeout=60,
        )

    def scan_and_connect_from_remote(self):
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state
        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
            dev_state=self.dev_state
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                timeout=20,
            )

        if self.ble_test_type == "scan":
            self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
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
                f"Remote device found in scan results ,BLE scanning is successful"
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
                min_conn_interval=self.conn_int,
                max_conn_interval=self.conn_int
            )
        if self.ble_test_type == "scan_from_remote_device":
            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
            )

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()


def calculate_offset(df):
    # Extract numeric part of *Calculated Offset using regex and convert to numeric type, handling missing values
    try:
        df['*Calculated Offset'] = df['*Calculated Offset'].apply(
            lambda x: float(re.search(r'\d+', x).group(0)) if pd.notnull(x) else None)
    except:
        df['*Calculated Offset'] = df['*Calculated Offset'].apply(
            lambda x: float(re.search(r'\d+', str(x)).group(0)) if pd.notnull(x) else None
        )

    try:
        # Extract only the required part of the Timestamp using regex
        df['Timestamp'] = df['Timestamp'].apply(lambda x: re.search(r'\d+:\d+:\d+\.\d+ \w{2}', x).group(0))
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%I:%M:%S.%f %p')
    except:
        # Extract the time part from the original 'Timestamp' column
        df['Timestamp'] = df['Timestamp'].apply(
            lambda x: re.search(r"\d+:\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%H:%M:%S.%f')

    # Function to find the pattern and calculate the required difference
    def find_pattern_and_calculate(df):
        for i in range(len(df) - 3):
            if df.loc[i, 'Chan'] == 37 and df.loc[i + 1, 'Chan'] == 38 and df.loc[i + 2, 'Chan'] == 39:
                if df.loc[i + 3, 'Chan'] not in [37, 38, 39]:
                    offset_39 = df.loc[i + 2, '*Calculated Offset']
                    timestamp_39 = df.loc[i + 2, 'Timestamp']
                    timestamp_random = df.loc[i + 3, 'Timestamp']
                    time_diff_microseconds = (timestamp_random - timestamp_39).total_seconds() * 1e6
                    if abs(offset_39 - time_diff_microseconds) <= 15:
                        return True
        return False

    return find_pattern_and_calculate(df)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2, min_interval, max_interval, min_interval_s2, max_interval_s2",
    [
        (1, 0, 120, 200, 1, 2, "C708890", 0, 1, 32, 32, 48, 48)
    ],
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_PHY_1M_2M_with_wlan_conn_C708890(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        remote_wiseconnect3,
        ble_dut,
        adv_type,
        adv_type_s2,
        data_len,
        data_len_s2,
        pri_adv_phy,
        sec_adv_phy,
        test_case_id,
        adv_handle,
        adv_handle_s2,
        min_interval,
        max_interval,
        min_interval_s2,
        max_interval_s2
):
    """
    Test case: This test will verify the Verifying advertising on two adv handles with following
    variations on DUT: public addr, adv type on hdl1= 0x0001, adv type on hdl2=0x0000, adv data length on hdl1 =120, adv data len on hdl2 =200. Ref is performing ext scan.
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        logger().info("adv_type: %s", adv_type)
        logger().info("adv_typre_s2: %s", adv_type_s2)
        logger().info("data_len: %s", data_len)
        logger().info("data_len_s2: %s", data_len_s2)
        logger().info("pri_adv_phy: %s", pri_adv_phy)
        logger().info("sec_adv_phy: %s", sec_adv_phy)
        logger().info("test_case_id: %s", test_case_id)
        logger().info("adv_handle: %s", adv_handle)
        logger().info("adv_handle_s2: %s", adv_handle_s2)
        logger().info("min_interval: %s", min_interval)
        logger().info("max_interval: %s", max_interval)
        logger().info("min_interval_s2: %s", min_interval_s2)

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                      ble_dut_address=ble_dut_address,
                                      min_interval=min_interval, max_interval=max_interval, data_len=data_len,
                                      data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                      pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id,
                                      adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                      ble_client_address=ble_client_address, central=remote_wiseconnect3,
                                      min_interval_s2=min_interval_s2, max_interval_s2=max_interval_s2)#, powersave_p=True)


        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, '\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n'
            logger().info(
                "\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (
                        data_len if adv_type == 1 else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type == 1 else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type == [2, 6] or adv_type_s2 == [2, 6]:
            # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (
                        data_len if adv_type == 1 else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type == 1 else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                                 "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [
                0] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38,
             39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
        # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
        logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
        logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_SCAN_RSP packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2",
    [
        (2, 0, 200, 120, 3, 3, "C708891", 0, 1),
    ],
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_PHY_LECoded_with_wlan_conn_C708891(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3, adv_type,
        adv_type_s2, ble_dut, data_len, data_len_s2, pri_adv_phy,
        sec_adv_phy, test_case_id, adv_handle, adv_handle_s2
):
    """
    Test case: This test will verify the advertising on two adv handles with following variations
    on DUT: public addr, adv type on hdl1= 0x0005, adv type on hdl2=0x0006, adv data length on hdl1 =31, adv data length on hdl2=31. Ref is performing ext scan.
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_dut_address = wifi_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                   min_interval=48, max_interval=48, min_interval_s2=64, max_interval_s2=64,
                                   data_len=data_len, data_len_s2=data_len_s2,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                   pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id,
                                   adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, scanning_phys=4,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3)#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_obj.sniffer_validation_join()
        #logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                                 "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38,
             39]) == False).all(), "\n\n **** Test case Failed with the reason AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
        # Assert if primary PHY is not LE CODED on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no primary PHY is LE CODED on ADV_EXT_IND packets ****\n\n"
        logger().info("\n\n **** Primary PHY is LE CODED on ADV_EXT_IND packets ****\n\n")
        # Assert if Secondary PHY is not LE CODED on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_SCAN_RSP packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (18, 0, 31, 200, "C708892", 0, 1),
    ],
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_with_wlan_conn_C708892(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,adv_type, adv_type_s2, ble_dut, data_len, data_len_s2
                                                       , test_case_id, adv_handle, adv_handle_s2,


):
    """
    Test case: This test will verify the two Ext Adv Sets with legacy adv and ext adv with mentioned parameters on DUT:
    Public Addr, Adv type on hdl1:0x0012,Adv type on hdl2:0x0000,Adv data len on hdl1=31,Adv data len on hdl2=200.Ref performing LE_Ext_Scan
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_dut_address = wifi_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=ble_dut_address,
                                   min_interval=32, max_interval=32, min_interval_s2=48, max_interval_s2=48,
                                   data_len=data_len, data_len_s2=data_len_s2,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                   test_case_id=test_case_id, adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                   ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                                 "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [16] or adv_type_s2 in [16]:
            # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Type'] == "ADV_NONCONN_IND") & (df[
                                                                       "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_NONCONN_IND advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info("\n\n **** ADV_NONCONN_IND advertising mode found and Aux Pointer is not present ****\n\n")
            # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
            assert (df[(df['Type'] == 'ADV_NONCONN_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (
                data_len if adv_type in [
                    16] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_NONCONN_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [16] else data_len_s2} in ADV_NONCONN_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [19] or adv_type_s2 in [19]:
            # Assert if there is no ADV_IND advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
                                                               "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_IND advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
            # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
            assert (df[(df['Type'] == 'ADV_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (data_len if adv_type in [
                19] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [19] else data_len_s2} in ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [18] or adv_type_s2 in [18]:
            # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Type'] == "ADV_SCAN_IND") & (df[
                                                                    "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_SCAN_IND advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info("\n\n **** ADV_SCAN_IND advertising mode found and Aux Pointer is not present ****\n\n")
            # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
            assert (df[(df['Type'] == 'ADV_SCAN_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (
                data_len if adv_type in [
                    18] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_SCAN_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [18] else data_len_s2} in ADV_SCAN_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [21] or adv_type_s2 in [21]:
            # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Type'] == "ADV_DIRECT_IND") & (df[
                                                                      "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_DIRECT_IND advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info("\n\n **** ADV_DIRECT_IND advertising mode found and Aux Pointer is not present ****\n\n")
            # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
            assert (df[(df['Type'] == 'ADV_DIRECT_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (
                data_len if adv_type in [
                    21] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_DIRECT_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [21] else data_len_s2} in ADV_DIRECT_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no primary PHY is 1M on ADV_EXT_IND packets ****\n\n"
        logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if Secondary PHY is not 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n"
        logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_SCAN_RSP packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        # (1, 2, 200, 200, "C708893", 0, 1),
        (2, 0, 200, 120, "C708893", 0, 1)

    ],
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_phy_coded_with_wlan_conn_C708893(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,adv_type, adv_type_s2, ble_dut, data_len, data_len_s2,
                                                        test_case_id, adv_handle, adv_handle_s2,


):
    """
    Test case: This test will Verify advertising on two adv handles(Two Advertising Sets with Random Addr: primary phy as LE Coded and sec phy as LE Coded) with following variations on DUT:
    public addr, adv type on hdl1= 0x0001, adv type on hdl2=0x0006, adv data length on hdl1 =120, adv data length on hdl2=200 during WLAN connection and run ping traffic
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        random_address = "11:33:33:33:33:11"
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=random_address,
                                   pri_adv_phy=3, sec_adv_phy=3, min_interval=48, max_interval=48, min_interval_s2=64,
                                   max_interval_s2=64, data_len=data_len, data_len_s2=data_len_s2,
                                   random_address=random_address, random_address_s2=random_address,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                   adv_handle=adv_handle,
                                   adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3)#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present") & (
                                      df[
                                          "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                                 "Aux Pointer"] == "Present") & (
                                      df[
                                          "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present and is advertising with random address ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                             "Aux Pointer"] == "Present") & (
                                      df[
                                          "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present and is advertising with random address ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38,
             39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets are not found ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n"
        logger().info("\n\n **** Primary PHY is LE CODED on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_SCAN_RSP packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 6, 120, 200, "C708894", 0, 1),
    ],
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_phy_coded_with_wlan_conn_C708894(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,adv_type, adv_type_s2, ble_dut, data_len, data_len_s2, pri_adv_phy,
                                                       sec_adv_phy, test_case_id, adv_handle, adv_handle_s2,


):
    """
    Test case: This test will verify two adv sets(Primary phy =1M and Sec Phy 1M) :-
    Adv set1 : Public addr,adv type=0x0001, adv_data len=120. Adv Set 2: Random addr,adv type =0x0006, adv_data len=200 during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        random_address = "11:33:33:33:33:11"
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=ble_dut_address,
                                   pri_adv_phy=1, sec_adv_phy=1, min_interval=32, max_interval=32, min_interval_s2=48,
                                   max_interval_s2=48, data_len=data_len, data_len_s2=data_len_s2,
                                   random_address_s2=random_address,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                   adv_handle=adv_handle,
                                   adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3)#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [1, 5] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                f"\n\n **** Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [1, 5] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [0, 4] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable non-scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [0, 4] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [2, 6] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable scannable advertising mode found or Aux Pointer is not present ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [2, 6] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38,
             39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets are not found ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
        # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
        logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with secondary PHY is not 1M on AUX_ADV_IND packets ****\n\n"
        logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_SCAN_RSP packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 6, 120, 200, "C528615", 0, 1),
    ],
)
@pytest.mark.config(
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
@pytest.mark.config(
    "remote_wiseconnect3",
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_adv_with_wlan_conn_C708895(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,adv_type, adv_type_s2, ble_dut, data_len, data_len_s2, pri_adv_phy,
                                                       sec_adv_phy, test_case_id, adv_handle, adv_handle_s2,


):
    """
    Test case: This test will verify two adv sets(Primary phy =1M and Sec Phy 2M) :-
    Adv set1 : Public addr,adv type=0x0001, adv_data len=120. Adv Set 2: Random addr,adv type =0x0006, adv_data len=200 during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        random_address = "11:33:33:33:33:11"
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=ble_dut_address,
                                   pri_adv_phy=1, sec_adv_phy=2, min_interval=32, max_interval=32, min_interval_s2=48,
                                   max_interval_s2=48, data_len=data_len, data_len_s2=data_len_s2,
                                   random_address_s2=random_address,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                   adv_handle=adv_handle,
                                   adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [1, 5] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found and Aux Pointer is present..! ****\n\n"
            logger().info(
                f"\n\n **** Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [1, 5] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [0, 4] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable non-scannable advertising mode found and Aux Pointer is present..! ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [0, 4] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [2, 6] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable non-scannable advertising mode found and Aux Pointer is present..! ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [2, 6] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_ADV_IND packets ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38,
             39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packets are not found..! ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
        # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no primary PHY is 1M on ADV_EXT_IND packets..! ****\n\n"
        logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with secondary PHY is not 2M on AUX_ADV_IND packets..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 6, 120, 180, "C708896", 0, 1),
    ],
)
@pytest.mark.config(
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
@pytest.mark.config(
    "remote_wiseconnect3",
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_adv_with_wlan_conn_C708896(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,adv_type, adv_type_s2, ble_dut, data_len, data_len_s2, pri_adv_phy,
                                                       sec_adv_phy, test_case_id, adv_handle, adv_handle_s2,


):
    """
    Test case: This test will Verify two adv sets(Primary phy =LE Coded and Sec Phy LE Coded) :- Adv set1 : Public addr,adv type=0x0001,
    adv_data len=120. Adv Set 2: Random addr,adv type =0x0006, adv_data len=180 during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        random_address = "11:33:33:33:33:11"
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2,
                                   ble_dut_address=ble_dut_address,
                                   pri_adv_phy=3, sec_adv_phy=3, min_interval=48, max_interval=48, min_interval_s2=64,
                                   max_interval_s2=64, data_len=data_len, data_len_s2=data_len_s2,
                                   random_address_s2=random_address, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                   test_case_id=test_case_id, adv_handle=adv_handle,
                                   adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        if adv_type in [1, 5] or adv_type_s2 in [1, 5]:
            # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [1, 5] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
            logger().info(
                f"\n\n **** Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [1, 5] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [1,
                                                                  5] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_ADV_IND packets..! ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [1, 5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [0, 4] or adv_type_s2 in [0, 4]:
            # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Non-Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [0, 4] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable non-scannable advertising mode found..! ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [0, 4] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [0,
                                                                  4] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length is not data_len in AUX_ADV_IND packets..! ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [0, 4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        if adv_type in [2, 6] or adv_type_s2 in [2, 6]:
            # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
            assert len(df.loc[
                           (df['Advertising Mode'] == "Non-Connectable Scannable") &
                           (df['Aux Pointer'] == "Present") &
                           (df.apply(
                               lambda row: row['Ext Adv Address Type'] == (
                                   "random" if adv_type_s2 in [2, 6] else "public"),
                               axis=1))
                           ]) >= 1, "\n\n **** Test case Failed with no non-connectable scannable advertising mode found..! ****\n\n"
            logger().info(
                f"\n\n **** Non-Connectable Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [2, 6] else 'public'} ****\n\n")
            # Assert if PDU length is not data_len in AUX_ADV_IND packets
            assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))][
                        'PDU Length'] > (data_len if adv_type in [2,
                                                                  6] else data_len_s2)).all(), "\n\n **** Test case Failed with no pdu length match found..! ****\n\n"
            logger().info(
                f"\n\n **** PDU length is {data_len if adv_type in [2, 6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
            # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
            assert calculate_offset(
                df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
            logger().info(
                "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
            [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df.loc[df[
                           'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                                                                                                     'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


