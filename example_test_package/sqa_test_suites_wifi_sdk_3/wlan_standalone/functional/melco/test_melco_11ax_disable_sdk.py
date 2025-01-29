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
                 leave=None, network_interface=None):
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
        self.dut_add_dict = {}
        self.info_attr = {}
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
