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
      - Achal Raghav 
      - Swathi Chinthala
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
                 ipv6_addr_type="global"):
        super().__init__()
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

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.sniffer_capture(mode='start')

        info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                             wifi_access_point=self.wifi_access_point,
                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                             ip_version='ipv6',
                                                             ping_before_power_save=self.ping_before_power_save,
                                                             ping_after_power_save=self.ping_after_power_save,
                                                             ipv6_type=self.ipv6_addr_type,
                                                             retry_count=3,
                                                             power_save=self.power_save)

        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        if self.test_id == 119358:
            ip_addr = ip_addr.exploded
        if self.test_id == 119362:
            self.logger.info(f"The 128 bit IPv6 address is {ip_addr.exploded}")
            ip_addr = ip_addr.compressed
        self.client_info['ip_address'] = ip_addr

        if self.test_id in [119358, 119362, 119393, 119394, 119399, 119400]:
            self.ping_async(ip_addr=ip_addr)

        if self.test_id in [119359, 119402, 119403]:

            device_ip = info_attr['device_ip']
            logger().info(f"device_ip : {device_ip}")

            if self.ipv6_addr_type == "link":
                interface = self.wifi_client.interfaces.wifi.config["interface"]
                device_ip = f"{device_ip}%{interface}"

            status = ping(device_ip, 10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        self.dut_info['mac_address'] = info_attr['dut_mac_address']
        self.dut_info['ip_address'] = info_attr['device_ip']


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ipv6_packet_from_dut_c119345(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections, request,
                                               sniffer_filter,
                                               wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client, test_id=119345)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(type=129,
                                                                                        filter_name='icmpv6_msg_type')

        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_stateless_dhcpv6_configuration_c119348(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119348,
                              wifi_client=wifi_client,
                              ping_after_power_save=False,
                              ping_before_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        # Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=WLanThread.dut_info.get("mac_address"),
            filter_name='router_solicitation')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=WLanThread.dut_info.get("mac_address"),
            filter_name='router_advertisement')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_stateful_dhcpv6_procedure_c119349(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                           sniffer_filter, request,
                                                           wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client, test_id=119349,
                              ping_after_power_save=False,
                              ping_before_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        # Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=WLanThread.dut_info.get("mac_address"),
            filter_name='router_solicitation')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=WLanThread.dut_info.get("mac_address"),
            filter_name='router_advertisement')
        # Stateful IPv6 address
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("mac_address"),
            filter_name='stateful_ipv6_address')
        logger().info(f"The filter is {packet_filter3}")
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_ping_with_128_bit_ipv6_address_c119358(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                   sl_collections,
                                                                   wifi_client, request, sniffer_filter):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119358,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_check_ping_with_128_bit_ipv6_address_c119359(wifi_dut, wifi_sniffer, wifi_access_point,
                                                               sl_collections,
                                                               wifi_client, request, sniffer_filter):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119359,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_ping_with_possible_shortest_ipv6_address_c119362(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                             sl_collections, request, sniffer_filter,
                                                                             wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119362,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_dut_stateless_dhcpv6_configuration_c119396(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                     sl_collections, request, sniffer_filter,
                                                                     wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119396,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_dut_stateful_dhcpv6_configuration_c119397(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                    sl_collections, request, sniffer_filter,
                                                                    wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119397,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_AP_global_stateless_dhcpv6_configuration_C119393(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                           sl_collections, request, sniffer_filter,
                                                                           wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119393,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_AP_global_stateful_dhcpv6_configuration_C119394(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                          sl_collections, request, sniffer_filter,
                                                                          wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119394,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_AP_linklocal_stateless_dhcpv6_configuration_C119399(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119399,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_AP_linklocal_stateful_dhcpv6_configuration_C119400(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                             sl_collections, request, sniffer_filter,
                                                                             wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119400,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_DUT_linklocal_stateless_dhcpv6_configuration_C119402(wifi_dut, wifi_access_point,
                                                                               wifi_sniffer,
                                                                               sl_collections, request, sniffer_filter,
                                                                               wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119402,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_to_DUT_linklocal_stateful_dhcpv6_configuration_C119403(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119403,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=WLanThread.dut_info.get("ip_address"),
            da_addr=WLanThread.client_info.get("ip_address"),
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

#
