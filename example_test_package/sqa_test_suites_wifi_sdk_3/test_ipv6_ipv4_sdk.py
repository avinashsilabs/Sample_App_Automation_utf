from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
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
    
     Authors:
      - Achal Raghav 
      - Swathi Chinthala 
"""


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type

    def ping_async(self):

        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
        ip_addr = ipaddress.ip_address(remote_ip)
        logger().info(f"Remote device ip:{ip_addr}")
        logger().info(f"Ping from DUT to remote")
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, num_ping_attempts=self.ping_count,
                                           ping_timeout=10,  ip_version='ipv6', ping_size=64)
        time.sleep(10)
        logger().info(f"Ping successful")

    def run(self):

        dut_add_dict = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                 wifi_access_point=self.wifi_access_point,
                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                 power_save=False,
                                                 retry_count=3)

        # configure_ip tries to assign IP ADDRESS through DHCP
        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                 ip_version="ipv6")
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        dut_ipv6_addr = ip_config[1]
        logger().info(f"dut_ipv6_addr: {dut_ipv6_addr}")

        # we fetch the ip address and mac_address
        dut_add_dict['device_ipv6'] = dut_ipv6_addr

        logger().info(
            f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} "
            f"DUT IPV4 ADDRESS : {dut_add_dict['device_ip']}"
            f"DUT IPV6 ADDRESS : {dut_add_dict['device_ipv6']}")

        logger().info(f"....Applying performance profile mode : power_save_low_latency")
        self.wifi_dut.interfaces.wifi.set_performance_profile('power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        if self.test_type == "ping":

            if self.ping_from == "remote":
                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=dut_add_dict['device_ipv6'],
                                                  ping_count=self.ping_count,
                                                  retry_count=3)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")

            if self.ping_from == "dut":
                self.ping_async()

            if self.ping_from == "both":
                self.ping_async()
                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=self.ping_count)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateless_dhcpv6_WPA2_C156954(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter, utf_constants,
                                                          wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460", "ipv6_state": "1"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateful_dhcpv6_WPA3_C156955(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter,
                                                         utf_constants, wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count,wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateless_dhcpv6_WPA2_C156957(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter, utf_constants,
                                                          wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections,
                              test_type="ping", ping_from="dut",
                              ping_count=ping_count, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460", "ipv6_state": "1"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateful_dhcpv6_WPA3_C156958(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                         request,
                                                         sniffer_filter, utf_constants,wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460", "ipv6_state": "1"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateful_dhcpv6_WPA3_C156959(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                         request,
                                                         sniffer_filter, utf_constants,
                                                         wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_from="dut", ping_count=ping_count, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateless_dhcpv6_WPA2_C156960(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter, utf_constants,
                                                          wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections,
                              test_type="ping", ping_from="remote",wifi_client=wifi_client,
                              ping_count=ping_count)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_sim_ping_ipv4_ipv6_stateless_dhcpv6_WPA2_C156961(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter,utf_constants,
                                                                   wifi_client):
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client,
                              test_type="ping", ping_from="both",
                              ping_count=ping_count)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)











