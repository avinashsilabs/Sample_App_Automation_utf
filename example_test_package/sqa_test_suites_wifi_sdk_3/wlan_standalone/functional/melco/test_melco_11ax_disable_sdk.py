from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utf_config import UtfConfig
from collections import Counter


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Test Steps:

        1. Configure the DUT in 2G.
        2. Association of Third party AP's
        3. Configure the IPv6 addresses.
        4. Ping to the specified IPv6 address.
        5. Validate the Sniffer Checks.

     Author:
      - Sairam S V N
"""

import ipaddress
import random


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_sniffer=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, ping_before_power_save=True, ping_after_power_save=True,
                 ipv6_addr_type="global", addr_type = "global",  wifi_clients=None, channel=None, security=None, password=None,
                 dtim_count=None, beacon_interval=None, ping_count=None, no_of_clients=None, sniffer_filter=None,
                 leave=None, network_interface=None, switch=None):
        super().__init__()
        self.sniffer_filter = sniffer_filter
        self.addr_type=addr_type
        self.wifi_clients = wifi_clients
        self.network_interface = network_interface
        self.channel = channel
        self.security = security
        self.password = password
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.ping_count = ping_count
        self.no_of_clients = no_of_clients
        self.leave = leave
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_before_power_save = ping_before_power_save
        self.ping_after_power_save = ping_after_power_save
        self.ipv6_addr_type = ipv6_addr_type
        self.switch = switch
        self.dut_add_dict = {}
        self.info_attr = {}
        self.security_dict = {
            "OPEN": 0,
            "WPA2": 2,
            "WPA3": 7,
            "WPA2ENTERPRISE": 5,
            "WPA2WPA3MIXEDMODE": 8,
        }
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_capture(self, mode: str = None):
        if mode == 'start':
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        else:
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def ping_async(self, ip_addr):

        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(20)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def dut_sta_mac_addr_in_concur_mode(self):
        dut_sta_mac_addr = self.dut_addr_dict["dut_mac_address"]
        logger().info(f"The STA Mac address is {dut_sta_mac_addr}")
        return dut_sta_mac_addr

    def third_party_ap_mac_address(self):
        self.dut_addr_dict['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid
        ap_mac_addr = self.dut_addr_dict['ap_mac_address']
        logger().info(f"third_party_ap_mac_address is {ap_mac_addr}")
        return ap_mac_addr

    def check_he_params_from_beacon(self, a):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.third_party_ap_mac_address(),
            filter_name="beacon_with_he_info")
        logger().info(f"Validating the HE Params in Beacon frames {packet_filter1}")
        if a is True:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']

    def check_he_params_in_probe_request(self, a):
        packet_filter1= self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="probe_req_he_info")
        logger().info(f"Validating the HE Params in probe request {packet_filter1}")
        if a is True:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']

    def check_he_params_in_probe_response(self, a):
        packet_filter1= self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ap_mac=self.third_party_ap_mac_address(),
            da_addr=self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="probe_response_he_info")
        logger().info(f"Validating the HE Params in probe response {packet_filter1}")
        if a is True:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']

    def check_he_params_in_assoc_request(self, a):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="assoc_req_he_info")
        logger().info(f"Validating the HE Params in Asscoc request {packet_filter1}")
        if a is True:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']


    def check_he_params_in_assoc_response(self, a):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.third_party_ap_mac_address(),
            da_addr=self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="assoc_response_he_info")
        logger().info(f"Validating the HE Params in Assoc response {packet_filter1}")
        if a is True:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']

    def dut_sta_conn(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.sniffer_capture(mode='start')
        # staring the code

        self.dut_addr_dict = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                      wifi_access_point=self.wifi_access_point,
                                                                      associated=self.wifi_dut.interfaces.wifi.associated,
                                                                      power_save=False, retry_count=3,
                                                                      ping_before_power_save=False,
                                                                      ping_after_power_save=False,
                                                                      )
        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version="ipv6")
        logger().info(f"printing device ip {ip_config[1]}")
        self.network_interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
        logger().info(f"printing the newly added interface {self.network_interface}")
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type,
                                                                    network_interface=self.network_interface)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.ping_async(ip_addr=ip_addr)

    def dut_ap_conn(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_ap_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                       channel=11, ssid="917_AP",
                                                                       security="wpa2", password="12345678",
                                                                       dtim_count=3,
                                                                       beacon_interval=100,
                                                                       ht_caps=1,
                                                                       ping_count=10,
                                                                       no_of_clients=1
                                                                       )

    def compare_list(self, list1, list2):
        """Returns True if list1(sniffer based ssid list) contains all elements of list2(scan based ssid list),
        False otherwise."""
        counter1 = Counter(list1)
        counter2 = Counter(list2)
        logger().info(f"***** Counter1 = {counter1}")
        logger().info(f"***** Counter2 = {counter2}")

        # Check if counter2 is a subset of counter1
        return all(counter2[element] <= counter1[element] for element in counter1)

    def find_ssid_list_from_dut_scan(self, scan_type=False):
        # collect all ssid from DUT scan list
        ssid_list = []
        if scan_type:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=2, bg_scan_periodicity=10)
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

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
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

    def get_keys_from_value(self, dictionary, val):
        keys = []
        for key, value in dictionary.items():
            if value == val:
                keys.append(key)
        return keys

    def validate_rssi_channel_security(self):
        # Validate same RSSI values for all T & NT based ssid, and configured channel & security values matching with
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

    def mbssid_verfication(self):
        if self.test_id in [557306, 557307]:
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
            self.validate_rssi_channel_security()
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.scan()
            if self.test_id == 557306:
                self.sl_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                    associated=self.wifi_dut.interfaces.wifi.associated, ping_after_power_save=False)
            elif self.test_id == 557307:
                self.wifi_dut.interfaces.wifi.join(
                    ssid=vap_list[0], passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0]["passphrase"],
                    security=self.wifi_access_point.interfaces.wifi.guest_networks[0]["security"].name.lower())

    def join_to_wifi_network(self):
        self.dut_add_dict = self.sl_collections.join_to_wifi_network(
        self.wifi_dut, wifi_access_point=self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated,
        power_save=False, retry_count=3, ping_before_power_save=False, ping_after_power_save=False)

        ip_status, ip_config = self.sl_collections.configure_ip(
            self.wifi_dut, ip_status=False, retry_count=1, ip_version="ipv6")
        logger().info(f"printing device ip {ip_config[1]}")

    def rejoin_ping_success(self):
        # Step 1: Ping the DUT
        logger().info("Pinging the DUT to check initial connectivity...")
        status = self.sl_collections.ping(self.dut_add_dict['device_ip'], 30, 5)
        assert status, "Initial ping to DUT failed. DUT is not reachable."

        logger().info("Turning off the AP")
        self.switch.interfaces.pdu_switch.turn_off(delay=20)
        logger().info("Successfully powered off AP")

        logger().info("Again turning on the AP")
        self.switch.interfaces.pdu_switch.turn_on(delay=100)
        logger().info("Successfully powered on AP")

        time.sleep(25)

        logger().info("Pinging to DUT to check rejoin process is completed or not")
        status = self.sl_collections.ping(self.dut_add_dict['device_ip'], 30, 5)
        assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

#
# | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT
pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.ConcurrentMode,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                        | Si91xFeatureBitMap.OpenMode
                        | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server  | Si91xTCPIPFeatureBitMap.DHCPv4Server
                              | Si91xTCPIPFeatureBitMap.DHCPv4Client,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                                   | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        }
    )
]


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "standard": 'bgnax'
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_sdk_Verifying_the_sta_connectivity_with_11ax_disabled_C557301(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                            sl_collections, request, sniffer_filter,
                                                                            wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557301,
                              wifi_client=wifi_client, sniffer_filter = sniffer_filter)
        wlan_obj.dut_sta_conn()
        wlan_obj.sniffer_capture(mode='stop')
        logger().info("checking the log for 11ax parameters")
        wlan_obj.check_he_params_in_assoc_request(a=False)
        wlan_obj.check_he_params_in_assoc_response(a=False)
        wlan_obj.check_he_params_from_beacon(a=True)
        wlan_obj.check_he_params_in_probe_request(a=False)
        wlan_obj.check_he_params_in_probe_response(a=True)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "standard": 'n'
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_sdk_Verifying_the_sta_connectivity_with_non_11ax_AP_11ax_disabled_C557302(wifi_dut, wifi_access_point,
                                                                                        wifi_sniffer,
                                                                                        sl_collections, request,
                                                                                        sniffer_filter,
                                                                                        wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557302,
                              wifi_client=wifi_client, sniffer_filter = sniffer_filter)
        wlan_obj.dut_sta_conn()
        wlan_obj.sniffer_capture(mode='stop')
        logger().info("checking the log for 11ax parameters")
        wlan_obj.check_he_params_in_assoc_request(a=False)
        wlan_obj.check_he_params_in_assoc_response(a=False)
        wlan_obj.check_he_params_from_beacon(a=False)
        wlan_obj.check_he_params_in_probe_request(a=False)
        wlan_obj.check_he_params_in_probe_response(a=False)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "standard": 'bgnax'
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled", )
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_wifi_sdk_sta_Connectivity_in_concurrent_with_11ax_disabled_C557303(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                            sl_collections, request, sniffer_filter,
                                                                            wifi_client, wifi_clients):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557303,
                              wifi_client=wifi_client, sniffer_filter = sniffer_filter, channel=11, wifi_clients = wifi_clients)
        wlan_obj.dut_sta_conn()
        wlan_obj.dut_ap_conn()
        wlan_obj.sniffer_capture(mode='stop')
        logger().info("checking the log for 11ax parameters")
        wlan_obj.check_he_params_in_assoc_request(a=False)
        wlan_obj.check_he_params_in_assoc_response(a=False)
        wlan_obj.check_he_params_from_beacon(a=True)
        wlan_obj.check_he_params_in_probe_request(a=False)
        wlan_obj.check_he_params_in_probe_response(a=True)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "standard": 'bgn'
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_sdk_Verifying_the_sta_connectivity_with_non_11ax_AP_11ax_disabled_C557304(wifi_dut, wifi_access_point,
                                                                                        wifi_sniffer,
                                                                                        sl_collections, request,
                                                                                        sniffer_filter,
                                                                                        wifi_client, wifi_clients):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557304,
                              wifi_client=wifi_client, sniffer_filter = sniffer_filter, channel=11, wifi_clients=wifi_clients)
        wlan_obj.dut_sta_conn()
        wlan_obj.dut_ap_conn()
        wlan_obj.sniffer_capture(mode='stop')
        logger().info("checking the log for 11ax parameters")
        wlan_obj.check_he_params_in_assoc_request(a=False)
        wlan_obj.check_he_params_in_assoc_response(a=False)
        wlan_obj.check_he_params_from_beacon(a=False)
        wlan_obj.check_he_params_in_probe_request(a=False)
        wlan_obj.check_he_params_in_probe_response(a=False)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "passphrase": "12345678",
        "channel": 3,
        "ssid": "917_AP",
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
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"]
)
def test_wifi_sdk_mbssid_T_profile_c557306(
    wifi_sniffer, wifi_access_point, wifi_dut, request, sniffer_filter, sl_collections, wifi_client):
    test_name = request.node.name

    """Check STAUT Connectivity to Transmitted BSSID with 11ax Disable in Concurrent Mode"""

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_id=557306,
                          wifi_client=wifi_client, sniffer_filter=sniffer_filter)
    try:
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
        wlan_obj.mbssid_verfication()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "passphrase": "12345678",
        "channel": 3,
        "ssid": "917_AP",
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
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"]
)
def test_wifi_sdk_mbssid_NT_profile_c557307(
    wifi_sniffer, wifi_access_point, wifi_dut, request, sniffer_filter, sl_collections, wifi_client):
    test_name = request.node.name

    """Check STAUT Connectivity to Non-Transmitted BSSID with 11ax Disable in Concurrent Mode"""

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_id=557307,
                          wifi_client=wifi_client, sniffer_filter=sniffer_filter)
    try:
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
        wlan_obj.mbssid_verfication()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "12345678", "channel": 11, "standard": 'bgnax'})
def test_wifi_sdk_rejoin_11ax_disable_for_staut_conc_mode_C557305(
        wifi_dut, wifi_access_point, wifi_sniffer, sl_collections, request, sniffer_filter, wifi_client, switch,
        wifi_clients):

    """Check the WLAN Re- Connectivity to 11ax AP with 11ax Disabled for STAUT in Concurrent Mode"""

    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557301,
                              wifi_client=wifi_client, sniffer_filter = sniffer_filter, switch=switch,
                              wifi_clients=wifi_clients)
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.sniffer_capture(mode='start')

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac address is :{ap_mac_address}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'ap mac address is :{dut_mac_address}')

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0)

        wlan_obj.dut_ap_conn()
        wlan_obj.join_to_wifi_network()
        wlan_obj.rejoin_ping_success()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info(f"Checking for the HE Params Assoc Req packets in the sniffer.")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='assoc_req_he_info')

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert not snif_pkt_count, "packets are not captured in the sniffer"

        logger().info(f"Checking for the HE Params Assoc Resp packets in the sniffer.")
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address, da_addr=dut_mac_address, filter_name='assoc_response_he_info')

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert not snif_pkt_count, "packets are not captured in the sniffer"

        logger().info(f"Checking for the HE Params Probe Req packets in the sniffer.")
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='probe_req_he_info')

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert not snif_pkt_count, "packets are not captured in the sniffer"

        logger().info(f"Checking for the HE Params Probe Resp packets in the sniffer.")
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ap_mac=ap_mac_address, da_addr=dut_mac_address, filter_name='probe_response_he_info')

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "packets are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("**** finally turning on the AP ****")
        switch.interfaces.pdu_switch.turn_on(delay=100)
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()