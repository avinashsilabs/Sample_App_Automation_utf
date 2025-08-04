import pytest
import re
from utf.interfaces.bluetooth import BLEDeviceState
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
    Si91xConfigFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
import time
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import random
import string
import threading


def logger():
    return get_logger(__name__)


class WifiJoinThread(ThreadBase):
    dut_addr = {}

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            net_perf_client=None,
            protocol=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            region=None,
            switch=None,
            pmk_enable=False,
            tcp_ip_bypass=False,
            capture_filename=None,
            enc="ccmp",
            timeout=30,
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.pmk_enable = pmk_enable
        self.tcp_ip_bypass = tcp_ip_bypass
        self.enc = enc
        self.timeout = timeout
        self.capture_filename = capture_filename

    def run(self):
        WifiJoinThread.dut_addr = self.sl_collections.join_to_wifi_network(
            self.wifi_dut, self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3)

    def configure_sniffer(self):
        logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

    def wlan_rejoin_enable(self):
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0)


class BleAEThread(ThreadBase):
    ble_dut_address = {}
    ble_client_address = {}
    def __init__(
            self,
            central=None, print_all_adv_devices=1, data_len=0, data_len_s2=None,
            pri_adv_phy=1, sec_adv_phy=1, adv_data="", adv_handle=0, duration=0, max_ae_events=0,
            min_interval=48, max_interval=48, min_interval_s2=64, max_interval_s2=64, sec_adv_max_skip=1,
            adv_async_required=0, own_address_type=0, peer_addr_type=0, random_address=None,
            random_address_s2=None, ConnIntervalMax=160, ConnIntervalMin=160, set_smp=None, set_smp_remote1=None,
            scan_req_notify_enable=1, scan_resp_len=0, whitelist=None, scanning_whitelist=None,
            adv_filter_policy=0, scanning_filter_policy=0, powersave_p=None, powersave_c=None, ble_client_address_2=None,
            scanning_phys=1, adv_handle_s2=None, loop_count=0, adv_data_type=None, ble_dut_address=None,
            ble_sniffer=None, wifi_sniffer=None, bt_sniffer=None, periodic_data_len=None, write_handle=None,
            test_case_id="nrf_logs", init_phys=7, ble_dut=None, wifi_dut=None, set_smp_remote2=None,
            test_in_progress=False, dont_cleanup=False, error_expected="*****", invalid_data_hdl=None,
            filter_duplicates=0, scan_duration=0, scan_period=0, scan_interval_pri=48, scan_interval_sec=48,
            scan_window_pri=48, scan_window_sec=30, initiator_filter_policy=0, connection_time=30,
            scan_type_pri=1, scan_type_sec=1, scan_set_2=0, stop_scan=1, ble_client_address=None, connect=None,
            ble_addr_type=0, remote_addr_type=0, sl_collections=None, remote_wiseconnect3=None, remote_wiseconnect3s=None
    ):
        super().__init__()
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
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.remote_wiseconnect3s = remote_wiseconnect3s
        self.ble_dut = ble_dut
        self.wifi_dut = wifi_dut
        self.set_smp = set_smp
        self.set_smp_remote1 = set_smp_remote1
        self.set_smp_remote2 = set_smp_remote2
        self.write_handle = write_handle
        self.ble_client_address_2 = ble_client_address_2
        self.result = None

    def configure_ble_device(self):
        BleAEThread.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)
        assert (BleAEThread.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {BleAEThread.ble_dut_address}")

    def configure_ble_remote_device_1(self):
        logger().info(" ble-started-remote-side 1")
        address = self.remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp_remote1)
        BleAEThread.ble_client_address = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
        assert BleAEThread.ble_client_address, "failed to initiate ble in remote dut"
        logger().info(f" BLE CLIENT ADDRESS 1 : {BleAEThread.ble_client_address}")

    def configure_ble_remote_device_2(self):
        logger().info(" ble-started-remote-side 2")
        address = self.remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=self.set_smp_remote2)
        self.ble_client_address_2 = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
        assert self.ble_client_address_2, "failed to initiate ble in remote dut"
        logger().info(f" BLE CLIENT ADDRESS 2 : {self.ble_client_address_2}")

    def ble_add_service_dut(self):
        self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)

    def ble_add_services_remote_1(self):
        self.remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        self.remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        self.remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)

    def ble_resolve_services_remote(self):
        logger().info(f"******************** get all profiles ********************")
        uuids = self.remote_wiseconnect3.interfaces.wifi.ble_get_profiles_async(
            ble_remote_dev_address=BleAEThread.ble_dut_address)
        logger().info(f"******************** Profiles are {uuids} ********************")

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.remote_wiseconnect3.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=BleAEThread.ble_dut_address, uuid=int(str(uuids[0]), 16))

        logger().info(f"start_handle:{start_handle} end_handle:{end_handle} data:{data}")
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.remote_wiseconnect3.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=BleAEThread.ble_dut_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        index = char_uuids.index('0x1aa1')
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"

        self.write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{self.write_handle}")
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def ble_resolve_services_dut(self):
        logger().info(f"******************** get all profiles ********************")
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
            ble_remote_dev_address=self.ble_client_address_2)
        logger().info(f"******************** Profiles are {uuids} ********************")

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address_2, uuid=int(str(uuids[2]), 16))

        logger().info(f"start_handle:{start_handle} end_handle:{end_handle} data:{data}")
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address_2,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        index = char_uuids.index('0x2a1e')
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"

        self.write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{self.write_handle}")
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def att_value_enable_dut(self):
        self.wifi_dut.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address_2, handle=(self.write_handle + 1), enable_notify=1)

    def att_value_disable_dut(self):
        self.ble_dut.interfaces.bluetooth.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address_2, handle=(self.write_handle + 1), enable_notify=0)

    def att_value_enable_remote(self):
        self.remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=BleAEThread.ble_dut_address, handle=(self.write_handle + 1), enable_notify=1)

    def att_value_disable_remote(self):
        self.remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=BleAEThread.ble_client_address, handle=(self.write_handle + 1), enable_notify=0)

    def configure_buffer_mode_1(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address_2,
                                                                buffer_mode=mode,
                                                                buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def configure_buffer_mode_2(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=BleAEThread.ble_client_address,
                                                                buffer_mode=mode,
                                                                buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def ae_ble_slave(self, no_adv_sets_slave=None):
        self.remote_wiseconnect3.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=no_adv_sets_slave)
        adv_type = 1
        self.sl_collections.ble_ae_set_params(
            pheripheral_dev=self.ble_dut, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=BleAEThread.ble_client_address, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1, scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address, adv_data_type=1,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address, adv_data_type=3,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address, duration=0,
                                                     max_ae_events=0, adv_handle=0, adv_async_required=0)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1, ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_dut_address)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0,remote_address=BleAEThread.ble_dut_address)

        logger().info("getting the device state")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        self.remote_wiseconnect3.interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=BleAEThread.ble_dut_address, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)

        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def ae_two_ble_slave(self):
        self.remote_wiseconnect3.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=2)
        adv_type = 1
        self.sl_collections.ble_ae_set_params(
            pheripheral_dev=self.ble_dut, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=BleAEThread.ble_client_address, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                            adv_data_type=1,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                            adv_data_type=3,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0,
                                            scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                                     duration=0,
                                                     max_ae_events=0, adv_handle=0, adv_async_required=0)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_dut_address)

        self.remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_dut_address)

        logger().info("getting the device state")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        self.remote_wiseconnect3.interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=BleAEThread.ble_dut_address, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)

        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        # assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        """**** starting adv again from main dut and second remote dut will scan and connect ****"""

        self.remote_wiseconnect3s[0].interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=2)
        adv_type = 1
        self.sl_collections.ble_ae_set_params(
            pheripheral_dev=self.ble_dut, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=self.ble_client_address_2, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                            adv_data_type=1,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        self.sl_collections.ble_set_ae_data(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                            adv_data_type=3,
                                            data_len=len(adv_data), adv_data=adv_data, adv_handle=0,
                                            scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising(ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address,
                                                     duration=0,
                                                     max_ae_events=0, adv_handle=0, adv_async_required=0)

        self.remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_dut_address)

        self.remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_dut_address)

        logger().info("getting the device state")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        self.remote_wiseconnect3s[0].interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=BleAEThread.ble_dut_address, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)

        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        # assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def ae_ble_master(self, no_adv_sets=None):
        logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
        self.ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=no_adv_sets)
        adv_type = 1
        logger().info("SET PARAMS FROM REMOTE WISECONNECT3 TO BLE DUT")
        self.sl_collections.ble_ae_set_params_from_remote(
            pheripheral_dev=self.remote_wiseconnect3s[0], adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=BleAEThread.ble_dut_address, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1, scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)
        logger().info("\n ***** Successfully Configured AE advertising parameters ***** \n\n")

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        logger().info(f"adv_data: {adv_data}")

        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, adv_data_type=1,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        logger().info(
            f"\n\n ***** AE advertising Data configured successfully on {self.ble_client_address_2} with data type: BLE_AE_ADV_DATA_TYPE***** \n\n")
        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, adv_data_type=3,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, duration=0, max_ae_events=0,
            adv_handle=0, adv_async_required=0)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1, ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=self.ble_client_address_2)

        self.ble_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=self.ble_client_address_2)

        self.ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(
            remote_dev_addr=self.ble_client_address_2, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)
        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def ae_two_ble_master(self, no_adv_sets=None):
        logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
        self.ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=no_adv_sets)
        adv_type = 1
        logger().info("SET PARAMS FROM REMOTE WISECONNECT3 TO BLE DUT")
        self.sl_collections.ble_ae_set_params_from_remote(
            pheripheral_dev=self.remote_wiseconnect3s[0], adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=BleAEThread.ble_dut_address, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1, scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)
        logger().info("\n ***** Successfully Configured AE advertising parameters ***** \n\n")

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        logger().info(f"adv_data: {adv_data}")

        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, adv_data_type=1,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        logger().info(
            f"\n\n ***** AE advertising Data configured successfully on {self.ble_client_address_2} with data type: BLE_AE_ADV_DATA_TYPE***** \n\n")
        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, adv_data_type=3,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising_from_remote(
            ble_dut=self.remote_wiseconnect3s[0], dut_address=self.ble_client_address_2, duration=0, max_ae_events=0,
            adv_handle=0, adv_async_required=0)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1, ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=self.ble_client_address_2)

        self.ble_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=self.ble_client_address_2)

        self.ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(
            remote_dev_addr=self.ble_client_address_2, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)
        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        """**** starting adv again from remote device 1 and main dut will scan and connect **** """

        logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
        self.ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=no_adv_sets)
        adv_type = 1
        logger().info("SET PARAMS FROM REMOTE WISECONNECT3 TO BLE DUT")
        self.sl_collections.ble_ae_set_params_from_remote(
            pheripheral_dev=self.remote_wiseconnect3, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0,
            peer_address=BleAEThread.ble_dut_address, adv_handle=0, pri_adv_phy=1, sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)
        logger().info("\n ***** Successfully Configured AE advertising parameters ***** \n\n")

        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        logger().info(f"adv_data: {adv_data}")

        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3, dut_address=BleAEThread.ble_client_address, adv_data_type=1,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0)

        logger().info(
            f"\n\n ***** AE advertising Data configured successfully on {BleAEThread.ble_client_address} with data type: BLE_AE_ADV_DATA_TYPE***** \n\n")
        self.sl_collections.ble_set_ae_data_from_remote(
            ble_dut=self.remote_wiseconnect3, dut_address=BleAEThread.ble_client_address, adv_data_type=3,
            data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)

        self.sl_collections.ble_ae_start_advertising_from_remote(
            ble_dut=self.remote_wiseconnect3, dut_address=BleAEThread.ble_client_address, duration=0, max_ae_events=0,
            adv_handle=0, adv_async_required=0)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0, scanning_phys=1, scanning_filter_policy=0, scan_type=1, scan_type_sec=1, ScanInterval=48,
            ScanWindow=48, remote_addr_type=0, scan_interval_sec=48, scan_window_sec=30)

        self.ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_client_address)

        self.ble_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=BleAEThread.ble_client_address)

        self.ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(
            remote_dev_addr=BleAEThread.ble_client_address, remote_addr_type=0, initiator_filter_policy=0, init_phys=7,
            ConnIntervalMin=160, ConnIntervalMax=160)
        time.sleep(60)
        logger().info("\nChecking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

    def ble_cleanup_disconn(self):
        self.sl_collections.ble_ae_start_advertising(
            ble_dut=self.ble_dut, dut_address=BleAEThread.ble_dut_address, adv_enable=0, no_of_sets=1, adv_handle=0,
                                 duration=0, max_ae_events=0)

        # self.sl_collections.ble_ae_start_advertising(
        #     ble_dut=self.remote_wiseconnect3s[0], dut_address=BleAEThread.ble_dut_address, adv_enable=0, no_of_sets=1,
        #     adv_handle=0, duration=0, max_ae_events=0)

        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=BleAEThread.ble_client_address)
            time.sleep(5)
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address_2)
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
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=BleAEThread.ble_client_address)
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address_2)
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=BleAEThread.ble_client_address)
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address_2)
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True
        logger().info(" *************DUT Cleanup Success *******************")

    def ble_remove_services_dut(self):
        logger().info("******* ble_remove_service from DUT ******")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_remove_services_remote(self):
        logger().info("******* ble_remove_service from DUT ******")
        self.remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()

class TxNotificationFunctionality(BleAEThread, ThreadBase):
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, wifi_dut=None,
                 remote_wiseconnect3=None, address=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.wifi_dut = wifi_dut
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.address = address

    def run(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 20:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=BleAEThread.ble_client_address, data=self.data, data_address=self.address)
            time.sleep(1)
            events = self.remote_wiseconnect3.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"******* BLE EVENT DATA RECEIVED ON REMOTE DUT : {event.event_data} ******")
                    received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                    logger().info(f"******* Received Data on Remote DUT : {received_data} ********")
                    assert received_data == [self.data], "data mismatched"
        time.sleep(5)


class RxNotificationFunctionality(BleAEThread, ThreadBase):
    def __init__(self, ble_dut=None, ble_clients=None, ble_dut_address=None, data=None, address=None,
                 remote_wiseconnect3s=None, wifi_dut=None):

        super().__init__()
        # Define all the parameters
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = ble_dut_address
        self.data = data
        self.address = address
        self.remote_wiseconnect3s = remote_wiseconnect3s
        self.wifi_dut = wifi_dut

    def run(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 20:
            self.remote_wiseconnect3s[0].interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=BleAEThread.ble_dut_address, data=self.data, data_address=self.address)
            time.sleep(1)
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"***** BLE EVENT DATA RECEIVED ON PRIMARY DUT : {event.event_data} ******")
                    received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                    logger().info(f"******* Received Data on Primary DUT : {received_data} ********")
                    assert received_data == [self.data], "data mismatched"


class BleIndicationFunctionality(BleAEThread, ThreadBase):
    def __init__(self, ble_dut=None, ble_clients=None, ble_dut_address=None, data=None, address=None,
                 remote_wiseconnect3=None, wifi_dut=None, data_length=None):

        super().__init__()
        # Define all the parameters
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = ble_dut_address
        self.data = data
        self.address = address
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.wifi_dut = wifi_dut
        self.data_length = data_length

    def run(self):
        logger().info(f"****** Indication Start *******")
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            self.ble_dut.interfaces.bluetooth.ble_indicate_value(
                ble_remote_dev_address=BleAEThread.ble_client_address, handle=12, data=self.data,
                data_length=self.data_length, data_address=self.address)
            time.sleep(5)

            events = self.remote_wiseconnect3.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"******* BLE EVENT DATA RECEIVED ON REMOTE DUT : {event.event_data} ******")
                    received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                    logger().info(f"******* Received indication Data on Remote DUT : {received_data} ********")
                    assert received_data == [self.data], "data mismatched"

        time.sleep(5)


class WifiRejoinThread(WifiJoinThread, ThreadBase):

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            sl_collections=None,
            ping_count=None,
            switch=None
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.switch = switch

    def run(self):
        logger().info("Turning off the AP")
        self.switch.interfaces.pdu_switch.turn_off(delay=20)

        logger().info("Successfully powered off AP")

        logger().info("Again turning on the AP")
        self.switch.interfaces.pdu_switch.turn_on(delay=100)

        logger().info("Successfully powered on AP")
        logger().info("Pinging to DUT to check rejoin process is completed or not")
        status = self.sl_collections.ping(WifiJoinThread.dut_addr['device_ip'], 30, 5)
        assert status, "Pinging to DUT is failed, DUT not rejoined to AP"


class Iperf(WifiJoinThread, ThreadBase):
    def __init__(self, wifi_dut=None, net_perf_client=None, wifi_client=None, protocol=None, traffic=None,
                 wifi_access_point=None, qos=None, capture_filename=None, wifi_sniffer=None, sl_collections=None,
                 sniffer_filter=None, result=None, host_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.traffic = traffic
        self.wifi_access_point = wifi_access_point
        self.qos = qos
        self.capture_filename = capture_filename
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.ap_mac_address = None
        self.host_ip = host_ip
        self.result = result

    def run(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address('eth1')
        logger().info(f"******** HOST IP {host_ip} *******")

        self.net_perf_client.interfaces.net_perf.init_server(
            host_ip=host_ip, device_ip=WifiJoinThread.dut_addr['device_ip'], protocol=self.protocol,
            tos_value='0xc8')
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=WifiJoinThread.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=120, throughput_type=1, qos=0, timeout=150)
        logger().info("**** data transfer is successful ****")


class HTTPDownloadThread(WifiJoinThread, ThreadBase):

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            http_server=None,
            index_path=None,
            https=0
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.http_server = http_server
        self.index_path = index_path
        self.https = https

    def run(self):
        logger().info("**** Method to run http download ****")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut, http_server=self.http_server, index_path=self.index_path,
            device_ip=WifiJoinThread.dut_addr['device_ip'], https=self.https)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_dual_role_and_ping_traffic_c708887(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter):
    """ Verify the BLE AE DUAL Role connection and data transfer during WLAN connection and ping traffic
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        tx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        rx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_ble_master(no_adv_sets=1)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj.ae_ble_slave(no_adv_sets_slave=1)

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()
        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        tx_obj.start()
        tx_obj.wait_for_exit()

        rx_obj.start()
        rx_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_dut()
        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.skip()
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
def test_wifi_sdk_dual_role_and_wlan_rejoin_c708888(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, switch):
    """ Verify the WiFi rejoin functionality during BLE AE DUAL Role connection established
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        tx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        rx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        rejoin_obj = WifiRejoinThread(
            wifi_dut=wifi_dut, sl_collections=sl_collections, switch=switch, wifi_access_point=wifi_access_point)

        wifi_obj.configure_sniffer()
        wifi_obj.wlan_rejoin_enable()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_ble_master(no_adv_sets=1)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj.ae_ble_slave(no_adv_sets_slave=1)

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()
        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        tx_obj.start()
        tx_obj.wait_for_exit()

        rx_obj.start()
        rx_obj.wait_for_exit()

        rejoin_obj.start()
        rejoin_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_dut()
        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_dual_role_and_tcp_tx_traffic_c768305(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, wifi_client, net_perf_client, protocol):
    """ Verify AE ADV (2 ADV sets) + AE scan + (Dual role connection) connections with notifications during WLAN
    TCP Tx data transfer
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        tx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        rx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        tcp_tx_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic='0x00', wifi_access_point=wifi_access_point, qos=0,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_ble_master(no_adv_sets=2)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj.ae_ble_slave(no_adv_sets_slave=2)

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()
        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        tcp_tx_obj.start()
        tcp_tx_obj.wait_for_exit()

        tx_obj.start()
        tx_obj.wait_for_exit()
        rx_obj.start()
        rx_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_dut()
        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()

@pytest.mark.skip("HTTP download is not working and getting 0x1 error")
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
def test_wifi_sdk_dual_role_and_http_download_c768306(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, wifi_client, http_server, index_path):
    """ Verify AE ADV (2 ADV sets) + AE scan + (Dual role connection) connections with notifications
    during WLAN HTTP download
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        tx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        http_obj = HTTPDownloadThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections, sniffer_filter=sniffer_filter, wifi_client=wifi_client, ping_count=10,
            http_server=http_server, index_path=index_path, https=0)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_ble_master(no_adv_sets=2)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj.ae_ble_slave(no_adv_sets_slave=2)

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()
        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        http_obj.start()
        time.sleep(20)
        tx_obj.start()
        tx_obj.wait_for_exit()
        http_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_dut()
        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_two_peripheral_and_tcp_tx_traffic_c768304(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, wifi_client, net_perf_client, protocol):
    """ Verify AE ADV (2 ADV sets) + AE scan + BLE peripheral connections(2) with notifications during WLAN TCP Tx
    data transfer
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0, set_smp_remote1=1,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        tx_obj = TxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2)

        tcp_tx_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic='0x00', wifi_access_point=wifi_access_point, qos=0,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_two_ble_slave()

        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        tcp_tx_obj.start()
        tcp_tx_obj.wait_for_exit()
        tx_obj.start()
        tx_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.ble_remove_services_dut()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.skip("Rx Notification not working - receiving one byte data always")
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=0) |
                             Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=2) |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_two_central_and_tcp_tx_traffic_c768303(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, wifi_client, net_perf_client, protocol):
    """ Verify AE ADV (2 ADV sets) + AE scan + BLE central connections(2) with notifications during WLAN
    TCP Tx data transfer
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=0, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        rx_obj = RxNotificationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s, address=address2)

        tcp_tx_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic='0x00', wifi_access_point=wifi_access_point, qos=0,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_two_ble_master()

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()

        tcp_tx_obj.start()
        tcp_tx_obj.wait_for_exit()
        rx_obj.start()
        rx_obj.wait_for_exit()

        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.skip("Invalid handle Range - Need to Debug")
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
)
@pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0: {
                "oper_mode": 0,
                "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                            Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
                "custom_features": Si91xCustomFeatureBitMap.Default,
                "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                                       Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                       Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
                "bt_features": Si91xBTFeatureBitMap.Default,
                "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                           Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
                "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                             Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                             Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                             Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
                "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
                "thread_config": {
                    "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                    "ble": {"count": 1, "stack_len": 2048, "priority": 8},
                },
            },
        },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_dual_role_and_indication_and_tcp_tx_traffic_c768311(
        ble_dut, remote_wiseconnect3s, sl_collections, wifi_dut, request, wifi_access_point, remote_wiseconnect3,
        wifi_sniffer, sniffer_filter, wifi_client, net_perf_client, protocol):
    """ Verify AE ADV (2 ADV sets) + AE scan + (Dual role) connections with indications during WLAN TCP Tx data transfer
    """
    ble_obj = None
    try:
        capture_filename = request.node.name
        logger().info("TESTCASE EXECUTION STARTED")

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj = BleAEThread(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1, set_smp_remote1=0,
                              set_smp_remote2=1, ble_dut=ble_dut, remote_wiseconnect3s=remote_wiseconnect3s,
                              remote_wiseconnect3=remote_wiseconnect3)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data_length = len(data)
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        indication_obj = BleIndicationFunctionality(
            wifi_dut=wifi_dut, data=data, ble_dut=ble_dut, remote_wiseconnect3=remote_wiseconnect3, address=address2,
            data_length=data_length)

        tcp_tx_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic='0x00', wifi_access_point=wifi_access_point, qos=0,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.configure_sniffer()

        ble_obj.configure_ble_device()
        ble_obj.configure_ble_remote_device_1()
        ble_obj.configure_ble_remote_device_2()
        ble_obj.ble_add_service_dut()
        ble_obj.ble_add_services_remote_1()

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.ae_ble_master(no_adv_sets=2)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj.ae_ble_slave(no_adv_sets_slave=2)

        ble_obj.ble_resolve_services_dut()
        ble_obj.att_value_enable_dut()
        ble_obj.ble_resolve_services_remote()
        ble_obj.att_value_enable_remote()

        tcp_tx_obj.start()
        tcp_tx_obj.wait_for_exit()

        indication_obj.start()
        indication_obj.wait_for_exit()

        ble_obj.att_value_disable_remote()
        ble_obj.att_value_disable_dut()

        ble_obj.ble_remove_services_dut()
        ble_obj.ble_remove_services_remote()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup_disconn()