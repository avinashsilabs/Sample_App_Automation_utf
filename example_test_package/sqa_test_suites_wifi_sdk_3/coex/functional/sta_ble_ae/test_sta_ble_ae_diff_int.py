import time
import pytest
import pandas as pd
import os

from utf.interfaces.iperf.fixtures import net_perf_client
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
import random, string


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

    def run_traffic(self, protocol="TCP", traffic_type="TX", packet_size_tcp=1460, packet_size_udp=1470):

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
            buffer_size_tcp=packet_size_tcp,
            buffer_size_udp=packet_size_udp,
            async_socket=self.async_socket,

        )

    def run_http_download(self):

        logger().info("http download")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=self.device_ip,
            https=self.https
        )

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            self.join_to_ap()
            logger().info("Initiating ping from Raspi to DUT to check stability")
            status = ping(self.device_ip, 30, size=300)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

        if self.test_type == "http":
            if not self.wifi_dut.interfaces.wifi.associated:
                self.join_to_ap()
            logger().info("http download")
            self.run_http_download()


class BleAEThread(ThreadBase):
    def __init__(
            self,
            peripheral=None, adv_type=None, ble_dut_address=None, ble_dut=None, wifi_dut=None,
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
        self.ble_dut = ble_dut
        self.wifi_dut = wifi_dut
        self.result = None

    def run(self):
        self.result = self.verify_adv(peripheral=self.peripheral, adv_type=self.adv_type,
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

    def ble_start(self):
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=0, set_smp=1)

    def verify_adv(self, peripheral, adv_type, ble_dut_address,
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
                   ble_addr_type=0, remote_addr_type=0, expected_state=8):

        try:
            own_address_temp = ble_dut_address
            local_address = random_address if random_address and adv_handle == 0 else random_address_s2 if random_address_s2 and adv_handle == 1 else ble_dut_address
            logger().info(f"Local Device Address: {local_address}")

            if central:
                logger().info(f"BLE Client address: {ble_client_address}")
                assert ble_client_address, "failed to initiate ble in remote device"
            else:
                ble_client_address = "00:00:00:00:00:00"

            adv_set = 2 if adv_handle_s2 else 1
            # peripheral.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=adv_set)
            for i in range(adv_set):
                logger().info(f"\n\n ** ADV Set : {i + 1} **\n\n")
                handle = adv_handle_s2 if i == 1 else adv_handle  # configuring handle as per adv_sets, 0=set1 and 1=set2
                adv_event_prop = adv_type_s2 if i == 1 else adv_type  # configuring adv_type as per adv sets
                data_len = data_len_s2 if i == 1 else data_len  # configuring data len as per adv set
                min_interval = min_interval_s2 if i == 1 else min_interval
                max_interval = max_interval_s2 if i == 1 else max_interval

                if whitelist:
                    peripheral.interfaces.bluetooth.ble_add_white_list(remote_dev_addr=ble_client_address,
                                                                       remote_addr_type=0)

                if scanning_whitelist:
                    central.interfaces.wifi.ble_add_white_list(remote_dev_addr=ble_dut_address, remote_addr_type=0)

                if (random_address and i == 0) or (random_address_s2 and i == 1):
                    own_address_type = 1

                self.sl_collections.ble_ae_set_params(pheripheral_dev=peripheral, adv_event_prop=adv_event_prop,
                                                      own_address_type=own_address_type,
                                                      peer_addr_type=peer_addr_type, peer_address=ble_client_address,
                                                      adv_handle=handle,
                                                      pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                                      scan_req_notify_enable=scan_req_notify_enable,
                                                      adv_filter_policy=adv_filter_policy,
                                                      adv_min_interval=min_interval,
                                                      adv_max_interval=max_interval,
                                                      sec_adv_max_skip=sec_adv_max_skip)
                if adv_data_type == 2:
                    peripheral.interfaces.bluetooth.ble_app_set_periodic_ae_params(max_interval=max_interval,
                                                                                   min_interval=min_interval,
                                                                                   properties=64)

                if (random_address and i == 0) or (random_address_s2 and i == 1):
                    peripheral.interfaces.bluetooth.set_ae_set_random_address(
                        adv_handle=adv_handle if i == 0 else adv_handle_s2,
                        random_address=random_address if random_address else random_address_s2)
                    ble_dut_address = random_address if random_address else random_address_s2

                if adv_data:
                    if invalid_data_hdl:
                        self.sl_collections.ble_set_ae_data(ble_dut=peripheral, dut_address=ble_dut_address,
                                                            adv_data_type=1,
                                                            data_len=data_len, adv_data=adv_data,
                                                            adv_handle=invalid_data_hdl)
                    if adv_data_type == 2:
                        self.sl_collections.ble_set_ae_data(ble_dut=peripheral, dut_address=ble_dut_address,
                                                            adv_data_type=1,
                                                            data_len=data_len, adv_data=adv_data, adv_handle=handle)
                        self.sl_collections.ble_set_ae_data(ble_dut=peripheral, dut_address=ble_dut_address,
                                                            adv_data_type=2,
                                                            data_len=periodic_data_len, adv_data=adv_data, operation=3,
                                                            adv_handle=handle)
                    else:
                        self.sl_collections.ble_set_ae_data(ble_dut=peripheral, dut_address=ble_dut_address,
                                                            adv_data_type=1,
                                                            data_len=data_len, adv_data=adv_data, adv_handle=handle)
                        self.sl_collections.ble_set_ae_data(ble_dut=peripheral, dut_address=ble_dut_address,
                                                            adv_data_type=3,
                                                            data_len=data_len, adv_data=adv_data, adv_handle=handle,
                                                            scan_resp_len=scan_resp_len)
                peripheral.interfaces.wifi.ble_get_max_adv_data_len(max_data_len=data_len)

                if ble_sniffer and i == 0:
                    ble_sniffer.interfaces.sniffer.init_sniffer()
                    ble_sniffer.interfaces.sniffer.start_capture()
                    time.sleep(5)

                if bt_sniffer:
                    bt_sniffer.interfaces.sniffer.init_sniffer()
                    bt_sniffer.interfaces.sniffer.start_capture(capture_file="ellisys/" + test_case_id)

                if not loop_count:
                    self.sl_collections.ble_ae_start_advertising(ble_dut=peripheral, dut_address=ble_dut_address,
                                                                 duration=duration,
                                                                 max_ae_events=max_ae_events,
                                                                 adv_handle=handle,
                                                                 adv_async_required=adv_async_required)
                    if adv_data_type == 2:
                        peripheral.interfaces.bluetooth.ble_app_set_periodic_ae(enable=1, handle=0)

                    if powersave_p:
                        logger().info("\n\nenable power save in ble dut")
                        peripheral.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                        psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
                        peripheral.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                    time.sleep(60)

                if loop_count:  ##adding a condition to perform multiple iteration test case
                    previous_pkt_count = 0
                    for j in range(loop_count):
                        logger().info(f"\n\n ** Iteration  : {j + 1} **\n\n")
                        self.sl_collections.ble_ae_start_advertising(ble_dut=peripheral, dut_address=ble_dut_address,
                                                                     duration=duration,
                                                                     max_ae_events=max_ae_events,
                                                                     adv_handle=handle,
                                                                     adv_async_required=adv_async_required)
                        if adv_data_type == 2:
                            peripheral.interfaces.bluetooth.ble_app_set_periodic_ae(enable=1, handle=0)

                        if powersave_p:
                            logger().info("\n\nenable power save in ble dut")
                            peripheral.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
                            peripheral.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                        time.sleep(60)

                        if not max_ae_events:
                            # stopping AE advertising
                            self.sl_collections.ble_ae_start_advertising(ble_dut=peripheral,
                                                                         dut_address=ble_dut_address, adv_enable=0,
                                                                         adv_handle=adv_handle)
                            if adv_data_type == 2:
                                peripheral.interfaces.bluetooth.ble_app_set_periodic_ae(enable=0, handle=0)

            time.sleep(10)

            if ble_sniffer:
                # Mapping Master and Slave Address for Adding devices for sniffer
                ble_dut_address_hex = re.split(":", ble_dut_address)
                ble_client_address_hex = re.split(":", ble_client_address)
                master_address = "0x"
                for hex_data_part in ble_dut_address_hex:
                    master_address = master_address + hex_data_part
                slave_address = "0x"
                for hex_data_part in ble_client_address_hex:
                    slave_address = slave_address + hex_data_part
                if random_address != random_address_s2:
                    own_address_temp_hex = re.split(":", own_address_temp)
                    own_address_temp_ = "0x"
                    for hex_data_part in own_address_temp_hex:
                        own_address_temp_ = own_address_temp_ + hex_data_part
                    ble_sniffer.interfaces.sniffer.select_bt_devices(
                        [own_address_temp_, slave_address, master_address])
                elif random_address:
                    ble_sniffer.interfaces.sniffer.select_bt_devices(
                        [slave_address, master_address])
                else:
                    ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])

            if bt_sniffer:
                bt_sniffer.interfaces.sniffer.stop_capture()
                log_file_size = os.path.getsize(bt_sniffer.interfaces.sniffer.capture_file)
                assert log_file_size > 0, "Sniffer didn't capture any packets...Setup Issue"
            if central and not loop_count:
                central.interfaces.wifi.ble_ae_set_scan_params(ble_addr_type=ble_addr_type,
                                                               scanning_phys=scanning_phys,
                                                               scanning_filter_policy=scanning_filter_policy,
                                                               scan_type=scan_type_pri,
                                                               scan_type_sec=scan_type_sec,
                                                               ScanInterval=scan_interval_pri,
                                                               ScanWindow=scan_window_pri,
                                                               remote_addr_type=remote_addr_type,
                                                               scan_interval_sec=scan_interval_sec,
                                                               scan_window_sec=scan_window_sec, )

                status = central.interfaces.wifi.ble_ae_set_scan_enable(enable=1,
                                                                        filter_duplicates=filter_duplicates,
                                                                        duration=scan_duration,
                                                                        period=scan_period,
                                                                        remote_address=ble_dut_address)
                logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
                if "259" in str(status):
                    central.interfaces.wifi.is_dut_bad_state = True
                elif "19980" in str(status):
                    central.interfaces.wifi.ble_ae_set_scan_enable(enable=0,
                                                                   filter_duplicates=filter_duplicates,
                                                                   duration=scan_duration, period=scan_period,
                                                                   remote_address=ble_dut_address)
                    status = central.interfaces.wifi.ble_ae_set_scan_enable(enable=1,
                                                                            filter_duplicates=filter_duplicates,
                                                                            duration=scan_duration,
                                                                            period=scan_period,
                                                                            remote_address=ble_dut_address)
                    logger().info(f"\n\n *** Scanning status: {status} ***\n\n")

                if powersave_c:
                    logger().info("\n\nenable power save in ble dut")
                    central.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
                    central.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')

                time.sleep(30)
                if stop_scan:
                    try:
                        status = central.interfaces.wifi.ble_ae_set_scan_enable(enable=0,
                                                                                filter_duplicates=filter_duplicates,
                                                                                duration=scan_duration,
                                                                                period=scan_period,
                                                                                remote_address=ble_dut_address)
                        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
                        if "259" in str(status):
                            central.interfaces.wifi.is_dut_bad_state = True
                    except:
                        pass
                if connect:
                    central.interfaces.wifi.ble_extended_connect_with_params(remote_dev_addr=ble_dut_address,
                                                                             remote_addr_type=remote_addr_type,
                                                                             initiator_filter_policy=initiator_filter_policy,
                                                                             init_phys=init_phys,
                                                                             ConnIntervalMin=ConnIntervalMin,
                                                                             ConnIntervalMax=ConnIntervalMax)
                    time.sleep(60)
                    logger().info("\nChecking connection status of BLE")
                    logger().info("print3")
                    state = central.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    assert state_int == expected_state, "DUT BLE device is not in connected state"
                    # assert state_int == BLEDeviceState.Connected_ext, "DUT BLE device is not in connected state"
                    logger().info(f"\nDevice state: {state_int}")
                    time.sleep(connection_time)
                    central.interfaces.wifi.ble_disconnect(ble_dut_address)
                    time.sleep(10)
                    logger().info("\nChecking connection status of BLE after disconnection")
                    state = central.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    logger().info(f"\nDevice state: {state_int}")

            if ble_sniffer:
                ble_sniffer.interfaces.sniffer.stop_capture()
                captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

                time.sleep(30)
                exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")
                for captured_file in captured_files:
                    captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                    file_size = os.path.getsize(captured_file)
                    assert file_size > 0

                exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(exported_csv_file)
                assert file_size > 0
                sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
                logger().info(sniffer_data_df.head())
                assert sniffer_data_df is not None
        except Exception as e:
            if error_expected in str(e):
                logger().info(f"Got Expected error: {str(e)}")
            elif "Expected 'RSI_APP_EVENT_AE_ADV_REPORT'" in str(e):
                central.interfaces.wifi.ble_ae_set_scan_enable(enable=1,
                                                               filter_duplicates=filter_duplicates,
                                                               duration=scan_duration,
                                                               period=scan_period)
                assert False, "Test case failed with Excepton {}".format(str(e))
            elif "No such file or directory: '/app/reports/ellisys/":
                logger().info(f"Got Exception : {str(e)}")
                assert False, f"Setup Issue... {str(e)}... close Ellysis application and reopen alos power reset the Ellysis device"
            else:
                logger().info(f"Got Exception : {str(e)}")
                assert False, "Test case failed with Excepton {}".format(str(e))
        finally:
            try:
                if not loop_count and not dont_cleanup:
                    if adv_data_type == 2:
                        peripheral.interfaces.bluetooth.ble_app_set_periodic_ae(enable=0, handle=0)
                    try:
                        logger().info(
                            "\n\n ****  Stopping Advertisement_test  ****\n\n")
                        # self.ble_ae_start_advertising(ble_dut=peripheral, dut_address=ble_dut_address, adv_enable=0,
                        #                               adv_handle=adv_handle)
                        if adv_handle_s2:
                            # self.ble_ae_start_advertising(ble_dut=peripheral, dut_address=ble_dut_address, adv_enable=0,
                            #                               adv_handle=adv_handle_s2)
                            logger().info("test_code")

                    except Exception as e:
                        logger().info(f"Got Exception : {str(e)}")
            except:
                pass
            try:
                if peripheral:
                    peripheral.interfaces.bluetooth.ble_app_adv_set_clear_or_remove(type=2, handle=0)
                    if adv_handle_s2:
                        peripheral.interfaces.bluetooth.ble_app_adv_set_clear_or_remove(type=2, handle=1)
                time.sleep(2)
            except:
                pass

            try:
                if peripheral:
                    peripheral.interfaces.bluetooth.ble_app_adv_set_clear_or_remove(type=2, handle=0)
                    if adv_handle_s2:
                        peripheral.interfaces.bluetooth.ble_app_adv_set_clear_or_remove(type=2, handle=1)
                time.sleep(2)
            except:
                pass

            if ble_sniffer:
                return sniffer_data_df

    def verify_advertisement(self):
        self.ble_dut.interfaces.bluetooth.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)

        adv_type = 1
        self.sl_collections.ble_ae_set_params(
            pheripheral_dev=self.ble_dut, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0, adv_handle=0,
            pri_adv_phy=1, sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=self.ble_dut_address, adv_data_type=1,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=self.ble_dut_address, adv_data_type=3,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising(ble_dut=self.ble_dut, dut_address=self.ble_dut_address,
                                                     duration=0,
                                                     max_ae_events=0, adv_handle=0, adv_async_required=0)

    def stop_advertising(self):
        self.sl_collections.ble_ae_start_advertising(
            ble_dut=self.ble_dut, dut_address=self.ble_dut_address, adv_enable=0, no_of_sets=1, adv_handle=0,
            duration=0, max_ae_events=0)

    def stop_scanning(self):
        self.wifi_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0)

    def start_scanning(self):
        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1, ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0)


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
                set_smp=self.ble_pairing, two_evk=1)
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
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768291", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768291')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_TCP_Tx_C768291(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will verify BLE Ext Connection as Master, connection initiated from DUT
    and legacy adv on Ref with adv type = conn scan undirected during WLAN connection and ping traffic
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
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
@pytest.mark.test_src_map_id('C768317')
def test_verify_BLE_task_ena_dis_with_wlan_Scan_C768317(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        # ble_sniffer,
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
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_ae_obj = BleAEThread(sl_collections=sl_collections, ble_dut=ble_dut, wifi_dut=wifi_dut, adv_type=1)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.start()
        ble_ae_obj.ble_start()
        ble_ae_obj.verify_advertisement()
        ble_ae_obj.start_scanning()
        ble_ae_obj.stop_scanning()
        ble_ae_obj.stop_advertising()
        wifi_obj.wait_for_exit()

        wifi_obj.disconnect()
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
@pytest.mark.test_src_map_id('C768318')
def test_verify_BLE_task_ena_dis_with_wlan_Conn_C768318(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        # ble_sniffer,
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
        test_type = "ping"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_ae_obj = BleAEThread(sl_collections=sl_collections, ble_dut=ble_dut, wifi_dut=wifi_dut, adv_type=1)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.start()
        ble_ae_obj.ble_start()
        ble_ae_obj.verify_advertisement()
        ble_ae_obj.start_scanning()
        ble_ae_obj.stop_scanning()
        ble_ae_obj.stop_advertising()
        wifi_obj.wait_for_exit()

        wifi_obj.disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.test_src_map_id('C768319')
def test_verify_BLE_task_ena_dis_with_wlan_TCP_Tx_C768319(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        utf_constants,
        net_perf_client,
        protocol,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        # ble_sniffer,
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
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_ae_obj = BleAEThread(sl_collections=sl_collections, ble_dut=ble_dut, wifi_dut=wifi_dut, adv_type=1)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX",
        )

        wifi_obj.start()
        ble_ae_obj.ble_start()
        ble_ae_obj.verify_advertisement()
        ble_ae_obj.start_scanning()
        ble_ae_obj.stop_scanning()
        ble_ae_obj.stop_advertising()
        wifi_obj.wait_for_exit()

        wifi_obj.disconnect()
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
@pytest.mark.parametrize(
    "scan_interval_pri, scan_window_pri, test_case_id,",
    [

        (256, 80, "C768320"),
        (1000, 1000, "C768321"),

    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C768321')
def test_verify_AE_Scan_diff_intervals_with_wlan_TCP_Tx_C768320_C768321(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        test_case_id,
        # sniffer_filter,
        # ble_sniffer,
        scan_interval_pri,
        scan_window_pri,
):
    """
    Test case: 	This test case will verify BLE AE scan using scan interval and scan window(1:3) and 1:1 during WLAN TCP Tx
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT WLAN in scanning mode
        3. Configure DUT BLE in Central role
        4. Enable the wlan and ble power save mode
        5. Run the WLAN TCP Tx traffic and BLE scan

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            net_perf_client=net_perf_client,
            protocol=protocol,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX"
        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1,
                                 ble_dut_address=ble_dut_address,
                                 scanning_phys=5, test_case_id=test_case_id,
                                 pri_adv_phy=3, sec_adv_phy=3, data_len=1, scan_resp_len=1,
                                 adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                 scan_interval_pri=scan_interval_pri, scan_window_pri=scan_window_pri,
                                 central=remote_wiseconnect3, ble_client_address=ble_client_address)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_RSP') & (~df['Chan'].isin(
        # [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        # [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"

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
@pytest.mark.parametrize(
    "scan_interval_pri, scan_window_pri, test_case_id,",
    [

        (1000, 250, "C768326"),

    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C768326')
def test_verify_AE_Scan_diff_intervals_with_wlan_TCP_Tx_C768326(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        test_case_id,
        # sniffer_filter,
        # ble_sniffer,
        scan_interval_pri,
        scan_window_pri,
):
    """
    Test case: 	This test case will verify BLE AE scan using scan interval and scan window(1:4) during WLAN TCP Tx
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure DUT WLAN in scanning mode
        3. Configure DUT BLE in Central role
        4. Enable the wlan and ble power save mode
        5. Run the WLAN TCP Tx traffic and BLE scan

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            net_perf_client=net_perf_client,
            protocol=protocol,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX"
        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1,
                                 ble_dut_address=ble_dut_address,
                                 scanning_phys=5, test_case_id=test_case_id,
                                 pri_adv_phy=1, sec_adv_phy=2, data_len=1, scan_resp_len=1,
                                 adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                 scan_interval_pri=scan_interval_pri, scan_window_pri=scan_window_pri,
                                 central=remote_wiseconnect3, ble_client_address=ble_client_address)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_RSP') & (~df['Chan'].isin(
        # [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        # [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"

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
@pytest.mark.parametrize(
    "adv_type, ConnIntervalMin, ConnIntervalMax, test_case_id, pri_adv_phy, sec_adv_phy, random_address, init_phys, connection_time",
    [
        (1, 80, 160, "C708880", 1, 2, None, 1, 900),
        (1, 4000, 4000, "C708881", 1, 2, None, 3, 900),
    ]
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C708881')
def test_verify_AE_Conn_as_Central_diff_conn_intervals_with_wlan_conn_C708880_C708881(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        remote_wiseconnect3,
        ble_dut,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, ConnIntervalMax, ConnIntervalMin, test_case_id, pri_adv_phy, sec_adv_phy, random_address, init_phys,
        connection_time,
):
    """
    Test case: 	This test case will verify the BLE Ext Central connection when 7.5ms interval used,
    adv type = conn unirected, addr type = public, initiating phy = coded, pri phy =1M, sec phy = 2M during WLAN is in idle connected state
    This test case will verify the BLE Ext Central connection when 4000ms interval used, adv type = conn unirected,
    addr type = public, initiating phy = coded, pri phy =coded, sec phy = coded during WLAN connection and ping traffic
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        random_address = "11:33:33:33:33:11"
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address,
                                 pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,
                                 min_interval=32, max_interval=40,
                                 data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                 adv_handle=0,
                                 random_address=random_address, init_phys=init_phys, connection_time=connection_time,
                                 ConnIntervalMin=ConnIntervalMin, ConnIntervalMax=ConnIntervalMax,
                                 ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys=5,
                                 connect=True, stop_scan=True,
                                 remote_addr_type=1 if random_address != None else 0, dont_cleanup=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768291", 0, 1, 0),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768292')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_HTTP_DL_C768292(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	Verify AE ADV (2 ADV sets) + AE scan with BLE central connection during WLAN HTTP download
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Run the WLAN HTTP download traffic and BLE AE scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768314", 0, 1, 0),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768314')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_HTTP_DL_BLE_Conn_First_C768314(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 		Verify AE ADV (2 ADV sets) + AE scan + BLE Central connection functionality
    by doing BLE activity first and WLAN connection and HTTP download activity next
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Run the WLAN HTTP download traffic and BLE AE scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)

        ble_ae_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()

        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768316", 0, 1, 0),
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768316')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_TCP_Tx_BLE_Conn_First_C768316(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) + AE scan + BLE Central connection functionality
    by doing BLE activity first and WLAN connection and TCP data transfer activity next
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)

        ble_ae_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794200", 0, 1, 0),
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
@pytest.mark.test_src_map_id('C794200')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_scan_C794200(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will verify WLAN continuous scan during BLE AE Central connection and data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the WLAN scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            # traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794201", 0, 1, 0),
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794201')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_TCP_Rx_C794201(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will verify AE ADV (2 ADV sets) with BLE central connection during WLAN TCP Rx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Rx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="RX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794203", 0, 1, 0),
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794203')
def test_verify_AE_2SETS_Conn_as_Master_with_wlan_UDP_Tx_C794203(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will verify AE ADV (2 ADV sets) with BLE central connection during WLAN UDP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the UDP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [

        (1, 32, 40, "C768277", 1, 2, None),
        (1, 32, 40, "C768278", 3, 3, "11:33:33:33:33:11"),
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768278')
def test_verify_BLE_Conn_as_Master_1M_2M_and_coded_phys_with_wlan_TCP_Tx_C768277_C768278(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    """
    Test case: 	Verify BLE Ext connection as Master with Ext adv on Ref for adv type = connectable undirected ,
    addr_type = random, initiating phy = 2M, pri phy = 1M, sec phy = 2M during WLAN TCP Tx
    This test case will Verify BLE Ext connection as Master with Ext adv on Ref for adv type = connectable undirected ,
    addr_type = public, initiating phy = coded phy , primary phy = coded, sec phy = coded during WLAN TCP Tx

    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the UDP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address,
                                 pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,
                                 min_interval=min_interval, max_interval=max_interval,
                                 data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 test_case_id=test_case_id, adv_handle=0,
                                 random_address=random_address,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, scanning_phys=5, connect=True, stop_scan=True,
                                 remote_addr_type=1 if random_address != None else 0, dont_cleanup=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [

        (1, 32, 40, "C768279", 1, 2, "11:33:33:33:33:11"),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768279')
def test_verify_BLE_Conn_as_Slave_1M_2M_with_wlan_TCP_Tx_C768279(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    """
    Test case: 	This test case will verify BLE Ext connection as Slave with Ext adv on DUT for
    adv type = connectable undirected , addr_type = random, initiating phy = 2M, pri phy = 1M, sec phy = 2M during WLAN TCP Tx
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in slave role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address,
                                 pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,
                                 min_interval=min_interval, max_interval=max_interval,
                                 data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                 adv_handle=0,
                                 random_address=random_address,
                                 ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys=5,
                                 connect=True, stop_scan=True,
                                 remote_addr_type=1 if random_address != None else 0, dont_cleanup=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [

        (1, 32, 40, "C768280", 1, 2, None),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768280')
def test_verify_BLE_Conn_as_Slave_coded_phy_with_wlan_HTTP_DL_C768280(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    """
    Test case: 	This test case will BLE Ext connection as Slave with Ext adv on DUT for adv type = connectable undirected ,
    addr_type = public, initiating phy = coded phy , primary phy = coded, sec phy = coded during WLAN HTTP download
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in slave role
        3. Enable the wlan and bt power save mode
        4. Start the HTTP download traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address,
                                 pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,
                                 min_interval=min_interval, max_interval=max_interval,
                                 data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                 adv_handle=0,
                                 random_address=random_address,
                                 ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys=5,
                                 connect=True, stop_scan=True,
                                 remote_addr_type=1 if random_address != None else 0, dont_cleanup=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768293", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768293')
def test_verify_AE_2SETS_Conn_as_Slave_with_wlan_TCP_Tx_C768293(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will verify AE ADV (2 ADV sets) + AE scan with
    BLE peripheral connection during WLAN TCP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768294", 0, 1, 0),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768294')
def test_verify_AE_2SETS_Conn_as_Slave_with_wlan_HTTP_DL_C768294(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	Verify AE ADV (2 ADV sets) + AE scan with BLE central connection during WLAN HTTP download
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Run the WLAN HTTP download traffic and BLE AE scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768299", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768299')
def test_verify_AE_2SETS_Conn_as_central_with_wlan_TCP_Tx_C768299(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: Verify AE ADV (2 ADV sets) + AE scan+BLE central connection with notifications during WLAN TCP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768300", 0, 1, 0),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768300')
def test_verify_AE_2SETS_Conn_as_central_with_wlan_HTTP_DL_C768300(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: Verify AE ADV (2 ADV sets) + AE scan + BLE central connection with notifications during WLAN HTTP download
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Run the WLAN HTTP download traffic and BLE AE scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768301", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C768301')
def test_verify_AE_2SETS_Conn_as_peripheral_with_wlan_TCP_Tx_C768301(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: Verify AE ADV (2 ADV sets) + AE scan + BLE peripheral connection with notifications during WLAN TCP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C768302", 0, 1, 0),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
@pytest.mark.test_src_map_id('C768302')
def test_verify_AE_2SETS_Conn_as_peripheral_with_wlan_HTTP_DL_C768302(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        http_server,
        index_path,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: Verify AE ADV (2 ADV sets) + AE scan + BLE peripheral connection with notifications during WLAN HTTP download
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in central role
        3. Enable the wlan and bt power save mode
        4. Run the WLAN HTTP download traffic and BLE AE scan with 2 ADV sets

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            http_server=http_server,
            index_path=index_path,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
# @pytest.mark.Skip("Debug is required for this test case")
@pytest.mark.test_src_map_id('C779565')
def test_verify_AE_adv_scan_adv_two_sets_with_wlan_scan_C779565(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        # ble_sniffer,
):
    """
    Test case: 	This test case will verify BLE AE adv, Scan functionality during WiFi continuous Scan  : adv set1 : pri phy = 1M, sec phy = 2M
    adv type = Conn Undir . adv set2 : pri phy = 1M, sec phy = 2M adv type = scan undirected
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Keep the DUT in scan state
        3. Start the BLE AE adv with 2 ADV sets and AE scan
        4. Enable the wlan and bt power save mode in dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=1, adv_type_s2=2,
                                 ble_dut_address=ble_dut_address, scanning_phys=5,
                                 min_interval=32, max_interval=32, data_len=32, data_len_s2=32,
                                 adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 pri_adv_phy=1, sec_adv_phy=2, test_case_id="C779565", scan_type_sec=0, scan_type_pri=0,
                                 scan_interval_pri=256, scan_window_pri=80,
                                 adv_handle=0, adv_handle_s2=1, scan_interval_sec=256, scan_window_sec=80,
                                 ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=48,
                                 max_interval_s2=48)  # , powersave_p=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        wifi_obj.disconnect()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
        # assert len(df.loc[(df['Type'] == 'AUX_SCAN_REQ') & (~df['Chan'].isin(
        #     [37, 38, 39]))]) > 0, "\n\n **** Test case Failed with no AUX_SCAN_REQ packets found..! ****\n\n"
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [

        (1, 32, 40, "C794202", 1, 2, "11:33:33:33:33:11"),
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
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
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
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794202')
def test_verify_BLE_two_sets_Conn_as_Central_1M_2M_with_wlan_TCP_Rx_C794202(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) with BLE central connection
    along with notifications enabled during WLAN TCP Rx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in master role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="RX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address,
                                 pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,
                                 min_interval=min_interval, max_interval=max_interval,
                                 data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id,
                                 adv_handle=0,
                                 random_address=random_address,
                                 ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys=5,
                                 connect=True, stop_scan=True,
                                 remote_addr_type=1 if random_address != None else 0, dont_cleanup=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794204", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794204')
def test_verify_AE_2SETS_Conn_as_Slave_with_wlan_TCP_Rx_C794204(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) with BLE peripheral connection during WLAN TCP Rx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Rx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="RX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794205", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794205')
def test_verify_AE_2SETS_Conn_as_Slave_with_notify_wlan_TCP_Rx_C794205(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) with BLE peripheral connection along with notifications during WLAN TCP Rx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the TCP Rx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="RX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794206", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794206')
def test_verify_AE_2SETS_Conn_as_Slave_and_wlan_UDP_Tx_C794206(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) with BLE peripheral connection during WLAN UDP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the UDP Tx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, adv_filter_policy",
    [
        (19, 0, 31, 200, "C794207", 0, 1, 0),
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
# @pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.test_src_map_id('C794207')
def test_verify_AE_2SETS_Conn_as_Slave_with_notify_wlan_UDP_Tx_C794207(
        # wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_dut,
        remote_wiseconnect3,
        net_perf_client,
        protocol,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        # sniffer_filter,
        adv_type, test_case_id, adv_filter_policy, adv_type_s2, data_len, data_len_s2, adv_handle, adv_handle_s2,
):
    """
    Test case: 	This test case will Verify AE ADV (2 ADV sets) with BLE peripheral connection along with notifications during WLAN UDP Tx data transfer
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the AP in WPA2 security mode
        3. Configure DUT BLE in peripheral role
        3. Enable the wlan and bt power save mode
        4. Start the UDP Rx traffic on DUT WLAN

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        # logger().info("configuring the Sniffer with the channel")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # logger().info(
        #     "start capturing with Sniffer by giving the test case name as filename"
        # )
        #
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            net_perf_client=net_perf_client,
            protocol=protocol,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            traffic_type="TX",
            test_type=test_type,

        )
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
        ble_ae_obj = BleAEThread(sl_collections=sl_collections, peripheral=ble_dut, adv_type=adv_type,
                                 ble_dut_address=ble_dut_address, adv_type_s2=adv_type_s2,
                                 data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy,
                                 test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                 adv_handle=adv_handle, adv_handle_s2=adv_handle_s2,
                                 ble_client_address=ble_client_address,
                                 central=remote_wiseconnect3, connect=True, stop_scan=True)
        wifi_obj.start()
        ble_ae_obj.start()
        wifi_obj.wait_for_exit()
        ble_ae_obj.wait_for_exit()
        # wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
        df = ble_ae_obj.result
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



