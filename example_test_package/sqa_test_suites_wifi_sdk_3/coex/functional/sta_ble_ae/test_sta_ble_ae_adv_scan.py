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
import random
import string


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
            # try:
            self.wifi_dut.interfaces.wifi.leave()
            # except:
            #     pass

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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_legacy_adv_conn_dir_with_wlan_Scan_C708839(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        ble_dut,

):
    """
    Test case: This test will verify legacy Adv-Connectable directed Adv while perform WLAN Scanning
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as legacy adv mode in AE
        3. Configure the DUT WLAN in scanning mode
        4. Enable the wlan and bt power save mode in dut after activities are done
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_dut_address = wifi_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, ble_dut_address=ble_dut_address, adv_type=21,
                                    min_interval=32, max_interval=32, data_len=32, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", powersave_p=True,
                                    adv_handle=0, ble_sniffer=ble_sniffer)
        wifi_obj = WifiJoinThread(
            #wifi_sniffer=wifi_sniffer,
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
        assert len(df.loc[(df['Type'] == "ADV_DIRECT_IND") & (df[
                                                                  "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_DIRECT_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_DIRECT_IND advertising mode found and Aux Pointer is not present ****\n\n")

        # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        assert all(df.loc[df['Chan'].isin([37, 38,
                                           39]), 'Type'] == 'ADV_DIRECT_IND'), "\n\n **** Test case Failed: No ADV_DIRECT_IND packet found on 37, 38, 39 channels ****\n\n"
        logger().info("\n\n **** ADV_DIRECT_IND packet found on 37,38,39 channels ****\n\n")
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
    "adv_type, test_case_id, data_len",
    [
        (19, "C708840", 1),
        (18, "C708841", 31),
        (19, "C708842", 31),
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
def test_verify_legacy_adv_conn_scannable_undir_adv_with_adv_data_len_1byte_and_31bytes_with_wlan_Conn_C708840_C708842(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer, remote_wiseconnect3,ble_dut,
        adv_type, data_len,
        test_case_id,

):
    """
    Test case: This test will verify legacy Adv-Connectable scannable undirected adv with Adv data length 1byte while perform WLAN Scanning
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as legacy adv mode in AE
        3. Configure the DUT WLAN in scanning mode
        4. Enable the wlan and bt power save mode in dut after activities are done
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"
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
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                       ble_sniffer=ble_sniffer, scanning_phys=5,
                                       pri_adv_phy=3, sec_adv_phy=3, data_len=data_len, scan_resp_len=data_len,
                                       test_case_id=test_case_id,
                                       adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                       central=remote_wiseconnect3, ble_client_address=ble_client_address)#, powersave_p=True)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
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
        # df = ble_ae_obj.result
        #
        # if adv_type in [19]:
        #     # Assert if there is no ADV_IND advertising mode found and Aux Pointer is present
        #     assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
        #                                                        "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_IND advertising mode found or Aux Pointer is not present ****\n\n"
        #     logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
        #     # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        #     assert (df[(df['Type'] == 'ADV_IND') & (df['Chan'].isin([37, 38, 39]))]['+PDU Length (LE BB)'] == str(data_len + 8) + " bytes").all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_IND packets ****\n\n"
        #     logger().info(
        #         f"\n\n **** PDU length is {data_len} in ADV_IND packets ****\n\n")
        # if adv_type in [18]:
        #     # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        #     assert len(df.loc[(df['Type'] == "ADV_SCAN_IND") & (df[
        #                                                             "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_SCAN_IND advertising mode found or Aux Pointer is not present ****\n\n"
        #     logger().info("\n\n **** ADV_SCAN_IND advertising mode found and Aux Pointer is not present ****\n\n")
        #     # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        #     assert (df[(df['Type'] == 'ADV_SCAN_IND') & (df['Chan'].isin([37, 38, 39]))]['+PDU Length (LE BB)'] == str(data_len + 8) + " bytes").all(), "\n\n **** Test case Failed with no PDU length is not data_len in ADV_SCAN_IND packets ****\n\n"
        #     logger().info(
        #         f"\n\n **** PDU length is {data_len} in ADV_SCAN_IND packets ****\n\n")
        #     # Assert if PDU length is not data_len in SCAN_RSP packets
        #     assert len(df.loc[(df['Type'] == "SCAN_RSP")])>0, "\n\n **** Test case Failed with no SCAN_RSP packets found ****\n\n"
        #     logger().info("\n\n **** SCAN_RSP packets found ****\n\n")
        #     assert (df[(df['Type'] == 'SCAN_RSP') & (df['Chan'].isin([37, 38, 39]))]['+PDU Length (LE BB)'] == str(data_len + 8) + " bytes").all(), "\n\n **** Test case Failed with PDU length is not data_len in SCAN_RSP packets ****\n\n"
        #     logger().info(f"\n\n **** PDU length is {data_len} in SCAN_RSP packets ****\n\n")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
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
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_with_wlan_conn_C708843(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_dut,
        ble_sniffer,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode in AE(Non connectable Non Scannable undirected with pri and sec PHY 1M, 1M
                         with adv data of 31 bytes)
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

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                       test_case_id="C708843",
                                       data_len=31, ble_sniffer=ble_sniffer,
                                       adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
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
        #wifi_obj.sniffer_validation_join()
        #logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
        # assert (df[
        #             '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        #
        # # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
        # def check_series(df):
        #     for i in range(len(df) - 2):
        #         if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
        #             aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
        #                 lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
        #             if aux_phy_values.nunique() == 1:
        #                 next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
        #                 if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
        #                         'ADV_EXT_IND').all():
        #                     continue
        #                 else:
        #                     return False
        #             else:
        #                 return False
        #     return True
        #
        # result = check_series(df)
        # assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 41 in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
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
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_with_wlan_conn_C708844(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode(Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M
                         with adv data of 31 bytes)
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
            #wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            #sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=0, adv_handle=1,
                                 ble_dut_address=ble_dut_address,
                                 test_case_id="C708844",
                                 pri_adv_phy=1, sec_adv_phy=2, data_len=31,
                                 ble_sniffer=ble_sniffer,
                                 adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_obj.sniffer_validation_join()
        #logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
        # assert (df[~df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
        # # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 11 in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
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
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_with_wlan_conn_C708845(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data of 31 bytes during WiFi is in idle connection
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=0, adv_handle=1,
                                 ble_dut_address=ble_dut_address,
                                 test_case_id="C708845",
                                 pri_adv_phy=3, sec_adv_phy=3,
                                 data_len=31, ble_sniffer=ble_sniffer,
                                 adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_obj.sniffer_validation_join()
        #logger().info("sniffer validation is successful")
        #df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
        # assert (df[
        #             '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 41 in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.skip("Debug is required for this test case")
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
@pytest.mark.ble_sniffer("frontline_sniffer")

def test_verify_AE_non_conn_non_scan_ADV_with_wlan_conn_C708846(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data of 0 bytes and max ae events: 0x32 ie.50 during WiFi is in idle connection
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=0, adv_handle=1,
                                 ble_dut_address=ble_dut_address,
                                 test_case_id="C708846",
                                 pri_adv_phy=1, sec_adv_phy=2,
                                 data_len=0, ble_sniffer=ble_sniffer,
                                 adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # # Assert if there is no non-connectable non-scannable advertising mode found
        # assert len(df.loc[(df[
        #                        'Advertising Mode'] == "Non-Connectable Non-Scannable")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # assert df['Chan'].value_counts().get(39,
        #                                      0) == 50, "\n\n **** Test case Failed with DUT not advertising with the defined max ae events 50 ****\n\n"
        # logger().info("\n\n **** DUT advertising with the defined max ae events 50 ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_Scannable_undirected_ADV_with_wlan_conn_C708847(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will Verify Ext Adv - Scannable undirected adv, with data length max adv data length,
    scan_response_notification_enable =0x01 and primary phy is 1M, sec phy is 1M during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                   pri_adv_phy=1, sec_adv_phy=1, data_len=200, scan_resp_len=1,
                                   test_case_id="C708847",
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL",
                                   scan_req_notify_enable=1, adv_handle=0,
                                   ble_sniffer=ble_sniffer, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        #df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
        #                                                                                  "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
        # assert (df[
        #             '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        #
        # # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
        # def check_series(df):
        #     for i in range(len(df) - 2):
        #         if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
        #             aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
        #                 lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
        #             if aux_phy_values.nunique() == 1:
        #                 next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
        #                 if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
        #                         'ADV_EXT_IND').all():
        #                     continue
        #                 else:
        #                     return False
        #             else:
        #                 return False
        #     return True
        #
        # result = check_series(df)
        # assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 11 in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len + 10).all(), f"\n\n **** Test case Failed with PDU length is not {data_len + 10} in AUX_ADV_IND packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {data_len + 10} in AUX_ADV_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_undirected_ADV_with_wlan_conn_C708848(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        remote_wiseconnect3,
        ble_sniffer,
):
    """
    Test case  : This test case will Verify Ext Adv - Scannable undirected adv, with data length max adv data length,
    scan_response_notification_enable =0x01 and primary phy is 1M, sec phy is 2M during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
            #wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                   ble_sniffer=ble_sniffer,
                                   pri_adv_phy=1, sec_adv_phy=2, data_len=200, scan_resp_len=200,
                                   test_case_id="C708848",
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=0,
                                   adv_handle=0, ble_client_address=ble_client_address, central=remote_wiseconnect3,
                                   scanning_phys=1, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
        #                                                                                  "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '1M').any(), '\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n'
        # logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
        # assert (df[~df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '2M').any(), '\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n'
        # logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not data_len in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] == data_len + 8).all(), f"\n\n **** Test case Failed with PDU length is not {data_len + 8} in AUX_SCAN_RSP packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {data_len + 8} in AUX_SCAN_RSP packets ****\n\n")
        # # assert if PUD length is not dat_len in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len + 10).any(), f"\n\n **** Test case Failed with PDU length is not {data_len + 10} in AUX_ADV_IND packets ****\n\n"
        # # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
        # assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin([37, 38,
        #                                                        39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_Scannable_undirected_ADV_with_wlan_conn_C708849(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will Verify Ext Adv - Scannable undirected adv, with data length max adv data length,
    scan_response_notification_enable =0x01 and primary phy is LE Coded, sec phy is LE Coded during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                               ble_sniffer=ble_sniffer, scanning_phys=4,
                               pri_adv_phy=3, sec_adv_phy=3, data_len=200, scan_resp_len=200,
                               test_case_id="C708849",
                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                               scan_req_notify_enable=1, adv_handle=0,
                               central=remote_wiseconnect3, ble_client_address=ble_client_address, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
        #                                                                                  "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i
        #     in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
        # assert (df[
        #             '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
        # logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1,
        #                                                                    raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(
        #     False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not data_len in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len + 10).any(), f"\n\n **** Test case Failed with PDU length is not {data_len + 10} in AUX_ADV_IND packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {data_len + 10} in AUX_ADV_IND packets ****\n\n")
        # # Assert if PDU length is not data_len in AUX_ADV_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] == data_len + 8).all(), f"\n\n **** Test case Failed with PDU length is not {data_len + 8} in AUX_SCAN_RSP packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {data_len + 8} in AUX_SCAN_RSP packets ****\n\n")
        # # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
        # assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        #     [37, 38,
        #      39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
        # logger()
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_filter_policy_with_wlan_conn_C708850(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        remote_wiseconnect3,
        wifi_client,
        sniffer_filter,
        ble_dut,
        ble_sniffer,
):
    """
    Test case  : This test case will verify filter policy = 0x03, during LE_Ext_Adv for connectable & scannable adv type during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                   data_len=31, whitelist=1, adv_filter_policy=3,
                                   test_case_id="C708850", adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                   adv_handle=0, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address,
                                   central=remote_wiseconnect3, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # if test_case_id == "C528575":
        #     # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        #     assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        #     logger().info(
        #         "\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        #     # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        #     assert calculate_offset(
        #         df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        #     logger().info(
        #         "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # else:
        #     # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        #     assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        #     logger().info(
        #         "\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        #     # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        #     assert calculate_offset(
        #         df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        #     logger().info(
        #         "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if primary PHY is not 1M on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '1M').any(), '\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n'
        # logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
        # # Assert if Secondary PHY is not 1M on AUX_ADV_IND packets
        # assert (df[~df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == '1M').any(), '\n\n **** Test case Failed with Secondary PHY is not 1M on AUX_ADV_IND packets ****\n\n'
        # logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
        # assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        #     [37, 38,
        #      39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C708851", 1, 1),
        (0, "C708852", 1, 2),
        (0, "C708853", 3, 3),
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)

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
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_periodic_Adv_Sync_undirected_non_conn_non_scan_with_wlan_conn_C708851_C708853(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        ble_dut,
        adv_type,
        test_case_id,
        pri_adv_phy,
        sec_adv_phy,
):
    """
    Test case  : This test case will verify the periodic advertising for adv type = non con non scan undirected adv type
    for the below : periodic adv data = 200 bytes, ext adv data = 200 bytes, pri phy = 1M,2M and coded, sec phy=1M,2M and coded phy during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                   pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200, scan_resp_len=1,
                                   test_case_id=test_case_id,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                   ble_sniffer=ble_sniffer, powersave_p=True, adv_data_type=2, periodic_data_len=200)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_obj.sniffer_validation_join()
        #logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if primary PHY is not expected PHY on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == (
        #             '1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k')).all(), f"\n\n **** Test case Failed with primary PHY is not {'1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k'} on ADV_EXT_IND packets ****\n\n"
        # logger().info(
        #     f"\n\n **** Primary PHY is {'1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k'} on ADV_EXT_IND packets ****\n\n")
        # # Assert if Secondary PHY is not expected PHY on AUX_ADV_IND packets
        # assert (df[~df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == (
        #             '1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k')).all(), f"\n\n **** Test case Failed with Secondary PHY is not {'1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k'} on AUX_ADV_IND packets ****\n\n"
        # logger().info(
        #     f"\n\n **** Secondary PHY is {'1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k'} on AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 203 in AUX_SYNC_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_SYNC_IND', 'PDU Length'] == 203).all(), f"\n\n **** Test case Failed with PDU length is not {203} in AUX_ADV_IND packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {203} in AUX_ADV_IND packets ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets
        # assert calculate_sync_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C708854", 1, 1),
        (0, "C708855", 1, 2),
        (0, "C708856", 3, 3),
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_periodic_Adv_Sync_directed_non_conn_non_scan_with_wlan_conn_C708854_C708856(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        # ble_sniffer,
        ble_dut,
        adv_type,
        test_case_id,
        pri_adv_phy,
        sec_adv_phy,

):
    """
    Test case  : This test case will verify the periodic advertising and on DUT for adv type = non con non scan directed adv type
    for the below : periodic adv data = 200 bytes, adv data = 200 bytes, pri phy = 1M, 2M and LE coded, sec phy=1M, 2M and LE coded phy during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT BLE as adv mode
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
        random_address = "11:22:33:44:55:66"
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=200))
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type, ble_dut_address=random_address,
                                   random_address=random_address,
                                   pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200, scan_resp_len=1,
                                   test_case_id=test_case_id,
                                   adv_data=adv_data, adv_handle=0,
                                adv_data_type=2, periodic_data_len=200)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present with random address
        # assert len(
        #     df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df["Aux Pointer"] == "Present") &
        #            (df[
        #                 "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present and is advertising with random address ****\n\n")
        # # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
        # assert all(df.loc[df['Chan'].isin([37, 38,
        #                                    39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
        # logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
        # # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
        # assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
        #                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        # logger().info(
        #     "\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        # assert calculate_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
        # # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
        # assert any(
        #     (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        #     range(
        #         len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
        # logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
        # # Assert if primary PHY is not expected PHY on ADV_EXT_IND packets
        # assert (df[df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == (
        #             '1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k')).all(), f"\n\n **** Test case Failed with primary PHY is not {'1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k'} on ADV_EXT_IND packets ****\n\n"
        # logger().info(
        #     f"\n\n **** Primary PHY is {'1M' if pri_adv_phy == 1 else '2M' if pri_adv_phy == 2 else '125k'} on ADV_EXT_IND packets ****\n\n")
        # # Assert if Secondary PHY is not expected PHY on AUX_ADV_IND packets
        # assert (df[~df['Chan'].isin([37, 38, 39])][
        #             '+PHY Type (LE BB)'] == (
        #             '1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k')).all(), f"\n\n **** Test case Failed with Secondary PHY is not {'1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k'} on AUX_ADV_IND packets ****\n\n"
        # logger().info(
        #     f"\n\n **** Secondary PHY is {'1M' if sec_adv_phy == 1 else '2M' if sec_adv_phy == 2 else '125k'} on AUX_ADV_IND packets ****\n\n")
        # # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
        # assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        #     False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        #     -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        #     bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
        # logger().info(
        #     "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
        # # Assert if PDU length is not 203 in AUX_SYNC_IND packets
        # assert (df.loc[df[
        #                    'Type'] == 'AUX_SYNC_IND', 'PDU Length'] == 203).all(), f"\n\n **** Test case Failed with PDU length is not {203} in AUX_ADV_IND packets ****\n\n"
        # logger().info(f"\n\n **** PDU length is {203} in AUX_ADV_IND packets ****\n\n")
        # # Assert if the calculated offset does not match with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets
        # assert calculate_sync_offset(
        #     df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets ****\n\n"
        # logger().info(
        #     "\n\n **** Calculated Offset matches with the time difference between the AUX_ADV_IND and AUX_SYNC_IND packets ****\n\n")
        # logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.parametrize(
    "scan_interval_pri, scan_window_pri, test_case_id,",
    [
        (160,80, "C708857"),
        (64000,48000, "C708858")
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )

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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_scan_with_wlan_conn_C708857_C708858(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        ble_dut,
        remote_wiseconnect3,
        test_case_id,
        scan_window_pri,
        scan_interval_pri,
):
    """
    Test case  : This test case will verify the BLE AE scan using scan interval-100ms,40secs and scan window -50ms, 30secs during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. DUT is performing Central role with different scan Interval and Scan window
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, adv_type=2, ble_dut_address=ble_dut_address,
                                   ble_sniffer=ble_sniffer, scanning_phys=5,test_case_id=test_case_id,
                                   pri_adv_phy=1, sec_adv_phy=2, data_len=1, scan_resp_len=1,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,scan_interval_pri=scan_interval_pri,scan_window_pri=scan_window_pri,
                                   central=remote_wiseconnect3, peripheral=ble_dut, ble_client_address=ble_client_address)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        assert len(df.loc[(df['Type'] == 'AUX_SCAN_RSP') & (~df['Chan'].isin(
            [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
            [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.end_state(
#     "wifi_dut",
#     wifi=[
#         "bt_powersave_disable",
#         "wifi_powersave_disable",
#         "disassociated",
#     ],
# )
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_ext_scan_filter_policy_0x01_with_wlan_scan_C708859(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        remote_wiseconnect3,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will verify filter policy = 0x01 for LE Ext Scan during WLAN is in Scanning state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT WLAN is in scanning mode
        4. Enable the wlan and bt power save mode in dut

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, adv_type_s2=2, ble_dut_address=ble_dut_address,scanning_phys=5,scanning_whitelist=1,
                                    min_interval=32, max_interval=32, data_len=32, data_len_s2=32, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=3,scan_type_sec=1,scan_type_pri=1,scan_interval_pri=256,scan_window_pri=80,test_case_id="C708859",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer,scan_interval_sec=256,scan_window_sec=80,scanning_filter_policy=1,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=48, max_interval_s2=48)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
# @pytest.mark.end_state(
#     "wifi_dut",
#     wifi=[
#         "bt_powersave_disable",
#         "wifi_powersave_disable",
#         "disassociated",
#     ],
# )
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_ext_scan_filter_policy_0x03_with_wlan_conn_C708860(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        remote_wiseconnect3,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case  : This test case will verify filter policy = 0x03 for LE Ext Scan during WLAN is in connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT WLAN is in connected state
        4. Enable the wlan and bt power save mode in dut

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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, adv_type_s2=2, ble_dut_address=ble_dut_address,scanning_phys=5,scanning_whitelist=1,
                                    min_interval=32, max_interval=32, data_len=32, data_len_s2=32, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=3,scan_type_sec=1,scan_type_pri=1,scan_interval_pri=256,scan_window_pri=80,test_case_id="C708860",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer,scan_interval_sec=256,scan_window_sec=80,scanning_filter_policy=3,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=48, max_interval_s2=48)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        #     [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.parametrize(
    "scanning_phys, pri_adv_phy, sec_adv_phy, scan_interval_pri, scan_window_pri, test_case_id,",
    [
        #(1, 1, 2, 1850, 462, "C708861"),
        (4, 3, 3, 1850, 925, "C708862")
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )

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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_passive_ext_scan_with_wlan_conn_C708861_C708862(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        ble_dut,
        remote_wiseconnect3,
        scanning_phys,
        pri_adv_phy,
        sec_adv_phy,
        scan_interval_pri,
        scan_window_pri,
        test_case_id
):
    """
    Test case: This test will Verify the Passive ext scan for 25% duty cycle for the mentioned : scan phy = 1M,scan interval = <2s, scan window = <2s ;
    Ref Advertiser: pri phy = 1M and coded, sec phy =2M and coded, Advertise Type = Scannable Undirected during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                   ble_sniffer=ble_sniffer, scanning_phys=scanning_phys,scan_type_pri=0,test_case_id=test_case_id,
                                   pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=1, scan_resp_len=1,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,scan_interval_pri=scan_interval_pri,scan_window_pri=scan_window_pri,
                                   central=remote_wiseconnect3, ble_client_address=ble_client_address)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        #         [37, 38, 39]))]) == 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.parametrize(
    "scanning_phys, pri_adv_phy, sec_adv_phy, scan_interval_pri, scan_window_pri, test_case_id,",
    [
        (1, 1, 2, 1850, 462, "C708863"),
        (4, 3, 3, 1850, 925, "C708864"),
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )

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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_active_ext_scan_diff_duty_cycle_with_wlan_conn_C708863_C708864(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
        ble_dut,
        remote_wiseconnect3,
        scanning_phys,
        pri_adv_phy,
        sec_adv_phy,
        scan_interval_pri,
        scan_window_pri,
        test_case_id,
):
    """
    Test case: This test will verify the Active ext scan for 25% duty cycle for the mentioned :
    scan phy = 1M, scan interval = <2s, scan window = <2s ; Ref Advertiser: pri phy = 1M and coded sec phy =2M and coded, Advertise Type = Scannable
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                   ble_sniffer=ble_sniffer, scanning_phys=scanning_phys,scan_type_pri=1,test_case_id=test_case_id,
                                   pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=1, scan_resp_len=1,
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,scan_interval_pri=scan_interval_pri,scan_window_pri=scan_window_pri,
                                   central=remote_wiseconnect3, ble_client_address=ble_client_address)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        # df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        #     [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_passive_ext_scan_adv_two_sets_with_wlan_conn_C708865(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        remote_wiseconnect3,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case: Verify passive Ext Scan : adv set1 : pri phy = 1M, sec phy = 2M
    adv type = Conn Undir . adv set2 : pri phy = 1M, sec phy = 2M adv type = scan undirected during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1, adv_type_s2=2, ble_dut_address=ble_dut_address,scanning_phys=5,
                                    min_interval=32, max_interval=32, data_len=32, data_len_s2=32, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=1, test_case_id="C708865",scan_type_sec=0,scan_type_pri=0,scan_interval_pri=256,scan_window_pri=80,
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer,scan_interval_sec=256,scan_window_sec=80,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=48, max_interval_s2=48) #powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
            [37, 38, 39]))]) == 0, "\n\n **** Test case Failed with AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.Skip("Debug is required for this test case")
def test_verify_AE_Active_ext_scan_adv_two_sets_with_wlan_conn_C708866(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ble_sniffer,
):
    """
    Test case: 	This test case will verify active Ext Scan : adv set1 : pri phy = 1M, sec phy = 2M
    adv type = Conn Undir . adv set2 : pri phy = 1M, sec phy = 2M adv type = scan undirected during WLAN is in idle connected state
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
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
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1, adv_type_s2=2, ble_dut_address=ble_dut_address,scanning_phys=5,
                                    min_interval=32, max_interval=32, data_len=32, data_len_s2=32, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C708866",scan_type_sec=1,scan_type_pri=1,scan_interval_pri=256,scan_window_pri=80,
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer,scan_interval_sec=256,scan_window_sec=80,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=48, max_interval_s2=48)#, powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
            [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)







