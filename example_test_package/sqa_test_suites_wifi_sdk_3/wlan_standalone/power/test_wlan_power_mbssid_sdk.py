import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
from utf.utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xOperatingMode,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xRegion,
    Si91xRegionCode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xModuleType,
)
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
from collections import Counter
from utf.utils.thread_base import ThreadBase
import os
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.power_meter.nrf_ppk2.nrf_power_profiler_mp import NRFPowerProfiler
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties

""" Test Steps:
        1. Configure the DUT in 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Verify the MBSSID's in scan list and validate through wifi sniffer for exact configured of MBSSID's.
        3. Initiate the connection with third party Access Point T & NT Profile.
        4. Start the power meter graph.
        5. Verify the power values in the graph.  

    setup requirement:
        1. DUT(SiWG917)
        2. Key Sight Power Meter
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Wifi-Sniffer

    Author: Benazeer@Silabs 
"""


def logger():
    return get_logger(__name__)


def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data):
        sw = Stopwatch()
        previously_found_devices = {}
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices

            if (
                    bt_dut_address in found_devices
                    and found_devices[bt_dut_address] == adv_data
            ):
                return True
        return False


class Power_Device:

    def __init__(self) -> None:
        pass

    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=60, power_analyzer=None):

        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim, capture_time=capture_time, power_analyzer=power_analyzer)
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        power_obj.get_power_value()


class power_number_output():
    def __init__(self, power_meter=None, dtim=None, capture_time=60, power_analyzer=None):
        super().__init__()
        self.power_meter = power_meter
        self.dtim = dtim
        self.capture_time = capture_time
        self.power_analyzer = power_analyzer

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info(f"initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info(f"setting output channels")

        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
                [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
                  "trace_power": False}])

        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1",
                                                                                   "emulation_mode": "2 Quadrant Power Supply",
                                                                                   "voltage": "3.3000",
                                                                                   "current_limit": "1.00000",
                                                                                   "voltage_slew": "MAX",
                                                                                   "voltage_meter_range": "Auto",
                                                                                   "current_meter_range": "Auto",
                                                                                   "trace_current": True,
                                                                                   "trace_power": True}])
        time.sleep(10)
        # start capture power meter datalog/scope
        logger().info(f"starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info(f"parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        if self.power_analyzer is not None:
            csvfile = str(parsed_result["Dlg File Name"]).replace(".dlg",".csv")
            self.power_analyzer.interfaces.power_analyzer.generate_report(csvfile)


class ppk_power_number_output():
    def __init__(self, power_meter=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        # Start Capture
        logger().info("Starting PPK capture")
        self.power_meter.interfaces.power_meter.start_capture()
        # Process Output
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)


class WifiSockthread(ThreadBase):

    def __init__(self, remote_socket=None, wifi_dut=None, wifi_access_point=None, device2_ip=None, m4_deep_sleep=False,
                 tcp_ka_time=240, send_data=False, send_ka=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device2_ip = device2_ip
        self.remote_socket = remote_socket
        self.m4_deep_sleep = m4_deep_sleep
        self.tcp_ka_time = tcp_ka_time
        self.send_data = send_data
        self.send_ka = send_ka

    def run(self):
        data_size = 42
        data = "tcpdatastartedtcpdatastartedtcpdatastarted"
        no_of_iterations = 2
        device2_ip = self.device2_ip
        self.remote_socket.interfaces.socket.time_limit = 3600

        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        logger().info(f"Remote device ip :{server_ip}")
        server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(f"Starting tcp server remotely at port number 5001")
        self.remote_socket.interfaces.socket.start_server()

        # DUT opens tcp client socket
        sock_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET",
                                                       stream_type="SOCK_STREAM",
                                                       protocol="IPPROTO_TCP")
        assert sock_id == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock_id} which is expected")

        # Socket binds at (device2_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(socket_fd=sock_id,
                                           device_ip=device2_ip,
                                           server_port=server_port)
        # tcp socket opened in DUT connects to the tcp server
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock_id,
                                                       server_ip=server_ip,
                                                       server_port=server_port)
        if self.send_ka:
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock_id,
                                                          option_level='SOL_SOCKET',
                                                          option_name='SO_KEEPALIVE',
                                                          option_val=str(self.tcp_ka_time))

        elif self.send_data:
            for i in range(1, no_of_iterations):
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id,
                                                            data=data)
                data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size)
                time.sleep(self.tcp_ka_time)

        time.sleep(2)
        if not self.m4_deep_sleep:
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            assert b"success" in result, "unable to close opened tcp socket"
        self.remote_socket.interfaces.socket.socket_close_indication(1)


class WlanThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 dtim=10, listen_interval=0, dtim_based=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.listen_interval = listen_interval
        self.device_ip = None
        self.dtim_based = dtim_based

    def run(self):
        if self.dtim_based:
            logger().info(f"Configuring Access Point with dtim : {self.dtim}")
            self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)
            time.sleep(5)
            logger().info(f"######=========>>>>>>DUT is going Connecting to N Profile")
            dictionary = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                listen_interval=self.listen_interval,
                power_save=False,
                retry_count=3
            )
            self.device_ip = dictionary['device_ip']
        else:
            logger().info(f"######=========>>>>>>DUT is going Connecting to N Profile")
            dictionary = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                listen_interval=1100,
                power_save=False,
                retry_count=3
            )
            self.device_ip = dictionary['device_ip']

    def getter(self):
        return self.device_ip


class M4_Sleep_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, m4_sleep_time=100000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info(f"Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0,
                                                                      sleep_time=self.m4_sleep_time)
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=150)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info(f'DUT is leaving the AP')


class Power_Measurement_Thread(ThreadBase, Power_Device):

    def __init__(self, power_meter=None, capture_time=60, power_analyzer=None):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time
        self.power_analyzer = power_analyzer

    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter,
                                       capture_time=self.capture_time, power_analyzer=self.power_analyzer)


class StandBy_Associated(ThreadBase):
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None,
                 deep_sleep=False, dtim_aligned_type=1, test_case_id=None, wifi_sniffer=None, test_name=None,
                 remote_socket=None, send_data=False, capture_time=60, m4_sleep_time=120000, bcast_filter=True,
                 tcp_ka_time=240, send_ka=False, listen_case=False, sniffer_filter=None, listen_based=None,
                 dtim_based=None, power_analyzer=None):
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_access_point = wifi_access_point
        self.power_meter = power_meter
        self.deep_sleep = deep_sleep
        self.remote_socket = remote_socket
        self.send_data = send_data
        self.send_ka = send_ka
        self.test_name = test_name
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        self.bcast_filter = bcast_filter
        self.tcp_ka_time = tcp_ka_time
        self.dtim_aligned_type = dtim_aligned_type
        self.listen_case = listen_case
        self.test_case_id = test_case_id
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.listen_based = listen_based
        self.dtim_based = dtim_based
        self.power_analyzer = power_analyzer
        self.security_dict = {
            "OPEN": 0,
            "WPA2": 2,
            "WPA3": 7,
            "WPA2ENTERPRISE": 5,
            "WPA2WPA3MIXEDMODE": 8,
        }

    def find_ssid_list_from_dut_scan(self, scan_type=False):
        # collect all ssid from DUT scan list
        ssid_list = []
        if scan_type:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=2,
                                                                bg_scan_periodicity=10)
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )
        else:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan()
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )

        for i in range(0, len(self.scan_list)):
            ssid_list.append(self.scan_list[i].ssid)
        return ssid_list

    def find_mbssid_vaps(self):
        # Regular expression pattern to match ssid and bssid
        packet_filter = "                    SSID:"
        count = 0
        ssid_list = []
        final_ssid_list = []

        filter_file = open(f"./reports/filter2_file.txt", "r")
        line = filter_file.readlines()

        logger().info(
            f"\n\n *** Trying to collect all T & NT based SSID from beacon packet *** \n\n"
        )
        for x in line:
            if packet_filter in x:
                print(x)
                ssid_list.append(x)
                output = ssid_list[count].strip().split(":")[1].strip().replace('"', "")
                final_ssid_list.append(output)
                count = count + 1
        return final_ssid_list

    def compare_list(self, list1, list2):
        """Returns True if list1(sniffer based ssid list) contains all elements of list2(scan based ssid list),
        False otherwise."""
        counter1 = Counter(list1)
        counter2 = Counter(list2)
        logger().info(f"***** Counter1 = {counter1}")
        logger().info(f"***** Counter2 = {counter2}")

        # Check if counter2 is a subset of counter1
        return all(counter2[element] <= counter1[element] for element in counter1)

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
        # Check the ssid list from DUT scan list
        assert len(ssid_list) > 0, "DUT scan list is empty"
        time.sleep(2)
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                radio_ch=self.wifi_access_point.interfaces.wifi.channel,
                filter_name="beacon_mbssid",
            )
        )
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1, packet_filter2=packet_filter2
        )[
            "packet_count"
        ], "Unable to find MBSSID bit enable in extended capability field in sniffer capture"

        vap_list = self.find_mbssid_vaps()
        """ Start verification for T & NT based scan list is available in DUT scan list """
        assert self.compare_list(
            vap_list, ssid_list
        ), "Unable to match DUT ssid list with configured VAP list"
        logger().info("\n\n ***** DUT is able to scan all VAP's info ***** \n\n")
        return vap_list

    def get_security_numbers(self, security_type):
        # Define a dictionary to map security types to numbers
        for value in self.security_dict.keys():
            if value == security_type:
                return self.security_dict[value]
        return None  # Return None if the number does not match any key

    def validate_for_same_rssi_values_for_all_ssid(self, scan_results, ssid_dict):
        # Create a mapping of SSID to RSSI from Scan Results
        scan_results_ssid_rssi = scan_results
        ssid_dict_ssids = set(ssid_dict.values())

        # Find RSSI values for SSIDs in ssid_dict
        rssi_values = {}
        for ssid in ssid_dict_ssids:
            if ssid in scan_results_ssid_rssi:
                rssi_values[ssid] = scan_results_ssid_rssi[ssid]
            else:
                rssi_values[
                    ssid
                ] = None  # or some default value if the SSID isn't found in scan_results

        pass_test_case = len(set(rssi_values.values())) == 1

        # Print the results
        logger().info("RSSI values for SSIDs in ssid_dict:")
        for ssid, rssi in rssi_values.items():
            logger().info(f"{ssid}: {rssi}")

        if pass_test_case:
            log_message = "RSSI values are same for all SSID"
        else:
            log_message = "RSSI values are not same for all SSID"

        logger().info(log_message)
        return pass_test_case

    def validate_rssi_channel_security(self):
        # Validate same RSSI values for all T & MT based ssid, and configured channel & security values matching with
        # DUT scan list
        channel_dict = {}
        security_dict = {}

        # Define a dictionary to store SSID and BSSID values
        ssid_dict = {
            "main_bssid": self.wifi_access_point.interfaces.wifi.ssid,
            "vap0_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[0][
                "ssid"
            ],
            "vap1_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[1][
                "ssid"
            ],
            "vap2_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[2][
                "ssid"
            ],
        }
        logger().info(f"\n\n *** SSID Dictionary = {ssid_dict} ***\n\n")

        # Define a dictionary to store channel and security values
        channel_dict[
            ssid_dict["main_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.channel
        channel_dict[
            ssid_dict["vap0_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[0]["channel"]
        channel_dict[
            ssid_dict["vap1_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[1]["channel"]
        channel_dict[
            ssid_dict["vap2_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[2]["channel"]

        # Define a dictionary to store security values
        security_dict[
            ssid_dict["main_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.security.name.upper()
        security_dict[
            ssid_dict["vap0_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[0][
            "security"
        ].name.upper()
        security_dict[
            ssid_dict["vap1_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[1][
            "security"
        ].name.upper()
        security_dict[
            ssid_dict["vap2_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[2][
            "security"
        ].name.upper()

        # Define a dictionary to store security numbers for each SSID
        main_vap_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["main_bssid"]]
        )
        main_vap0_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap0_bssid"]]
        )
        main_vap1_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap1_bssid"]]
        )
        main_vap2_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap2_bssid"]]
        )

        ssid_rssi_dict = {}
        for entry in self.scan_list:
            ssid_rssi_dict[entry.ssid] = entry.rssi

        # Validate that the RSSI values are same for all SSID
        assert self.validate_for_same_rssi_values_for_all_ssid(
            ssid_rssi_dict, ssid_dict
        ), "RSSI values are not same for all SSID"

        # Define a list of VAP configurations to iterate over
        vap_configs = [
            ("main_bssid", main_vap_sec_num, "Main BSSID"),
            ("vap0_bssid", main_vap0_sec_num, "VAP 0"),
            ("vap1_bssid", main_vap1_sec_num, "VAP 1"),
            ("vap2_bssid", main_vap2_sec_num, "VAP 2"),
        ]

        # Initialize flag to count matches
        flag = 0

        # Find matches
        matching_cells = []
        for key, ssid in ssid_dict.items():
            for cell in self.scan_list:
                if cell.ssid == ssid:
                    matching_cells.append(cell)
                    break  # Exit loop once a match is found

        # Print the matching cells
        logger().info("Matching Cells:")
        for match in matching_cells:
            logger().info(match)

        # # Iterate over each VAP configuration
        for vap_key, sec_num, vap_name in vap_configs:
            for scan_item in matching_cells:
                if scan_item.ssid == ssid_dict[vap_key]:
                    if (
                            scan_item.rf_channel == channel_dict[ssid_dict[vap_key]]
                            and scan_item.security_mode == sec_num
                    ):
                        logger().info(
                            f"\n\n\n {vap_name} channel={channel_dict[ssid_dict[vap_key]]} & "
                            f"Security={self.get_keys_from_value(self.security_dict, sec_num)} match\n\n"
                        )
                        flag += 1
                        break  # Exit inner loop once a match is found

        # Logging the flag value
        logger().info(f"\n\n\n Flag Value = {flag}\n\n\n")
        # Assertion to ensure all VAPs were matched
        assert flag == len(
            vap_configs
        ), "Unable to match all configured VAPs with DUT scan list"

    def get_keys_from_value(self, dictionary, val):
        keys = []
        for key, value in dictionary.items():
            if value == val:
                keys.append(key)
        return keys

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=self.test_name
        )
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
        self.validate_rssi_channel_security()
        self.wifi_dut.interfaces.wifi.scan()
        time.sleep(2)
        logger().info(f"M4-TA secure handshake")
        self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        time.sleep(2)
        if self.dtim_based:
            logger().info(f"#######===========>>>>>>>Configuring the DTIM Interval")
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                interface='client',
                join_feature_bitmap=Si91xJoinFeatureBitMap.Default
            )
        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                              sl_collections=self.sl_collections)
        if dut != "si917_ncp_sl_wifi":
            if self.deep_sleep:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time,
                                         deep_sleep_without_ret=True)
            else:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
            pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time, power_analyzer=self.power_analyzer)
        if self.listen_based:
            logger().info(f"#########=========>>>>>>>>Configuring the Listen Interval")
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                             Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=1100)

        if self.test_case_id == 219305:
            wlan_obj.start()
            wlan_obj.wait_for_exit()
        else:
            if self.dtim_based:
                logger().info(f"Configuring Access Point with dtim : {self.dtim}")
                self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)
                time.sleep(10)
                logger().info(f"#############===========>>>>>>> Connecting to NT Profile")
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                                                       "passphrase"],
                                                   security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                                                       "security"].name.lower(), )

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False, power_save=False,
                                                                         ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True, retry_count=3, )
            else:
                logger().info(f"#############===========>>>>>>> Connecting to NT Profile")
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                                                       "passphrase"],
                                                   security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                                                       "security"].name.lower(), )

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False, power_save=False,
                                                                         ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True, retry_count=3, )

        if self.send_data or self.send_ka:
            device2_ip = wlan_obj.getter()
            wifisock_obj = WifiSockthread(remote_socket=self.remote_socket, wifi_dut=self.wifi_dut,
                                          wifi_access_point=self.wifi_access_point, device2_ip=device2_ip,
                                          m4_deep_sleep=True, tcp_ka_time=self.tcp_ka_time, send_ka=self.send_ka,
                                          send_data=self.send_data)
            wifisock_obj.start()

        time.sleep(2)

        if self.bcast_filter:
            logger().info(f"Setting filter broadcast command")
            self.wifi_dut.interfaces.wifi.set_filter_broadcast()

        time.sleep(2)
        if self.dtim_based:
            logger().info(f"Enabling TA power save")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save",
                                                                  dtim_aligned_type=self.dtim_aligned_type)
        else:
            logger().info(f"Enabling TA power save")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", listen_interval=1100,
                                                                  dtim_aligned_type=self.dtim_aligned_type)
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()

        if self.listen_case:
            time.sleep(35)
            self.wifi_access_point.interfaces.wifi.stop_ap()

        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        if self.send_data:
            wifisock_obj.wait_for_exit()

        time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219305')
def test_wlan_standby_conn_DTIM_based_with_T_profile_C219305(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                             request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, dtim_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_480K_M4SS_192K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219306')
def test_wlan_standby_conn_DTIM_based_with_NT_profile_C219306(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                              request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, dtim_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_480K_M4SS_192K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219307')
def test_wlan_standby_conn_DTIM_based_with_T_profile_C219307(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                             request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, dtim_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_416K_M4SS_256K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219308')
def test_wlan_standby_conn_DTIM_based_with_NT_profile_C219308(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                              request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, dtim_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_416K_M4SS_256K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219309')
def test_wlan_standby_conn_DTIM_based_with_T_profile_C219309(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                             request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, dtim_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219310')
def test_wlan_standby_conn_DTIM_based_with_NT_profile_C219310(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, dtim, wifi_sniffer, sniffer_filter,
                                                              request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name, power_analyzer=power_analyzer,
                                     wifi_sniffer=wifi_sniffer, dtim_based=True)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219303')
def test_wlan_standby_con_Listen_based_with_T_profile_C219303(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_480K_M4SS_192K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219304')
def test_wlan_standby_con_Listen_based_with_NT_profile_C219304(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_480K_M4SS_192K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219311')
def test_wlan_standby_con_Listen_based_with_T_profile_C219311(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_416K_M4SS_256K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219312')
def test_wlan_standby_con_Listen_based_with_NT_profile_C219312(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_416K_M4SS_256K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219313')
def test_wlan_standby_con_Listen_based_with_T_profile_C219313(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                             sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to T profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, test_case_id=219305, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.power_analyzer("keysight_analyzer")
@pytest.mark.test_src_map_id('C219314')
def test_wlan_standby_con_Listen_based_with_NT_profile_C219314(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                              sl_collections, wifi_sniffer, sniffer_filter, request, performance_data, custom_performance_fixture, power_analyzer):
    '''
    Measure the WLAN stand by power when DUT connects to NT profile BSSID(DTIM based)
    '''
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name_csv = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name
    test_name = request.node.name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    standby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, power_meter=power_meter,
                                     sniffer_filter=sniffer_filter, test_name=test_name,
                                     wifi_sniffer=wifi_sniffer, listen_based=True, power_analyzer=power_analyzer)
    standby_obj.start()
    standby_obj.wait_for_exit()
    
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name_csv, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

# ********************************************************************************************************************
