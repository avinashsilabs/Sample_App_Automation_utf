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
from utf.utils.iperf.iperf_utils import ping
from threading import Thread
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
    
     Authors: 
      - Swathi Chinthala 
"""
import ipaddress
import random

def random_ipv6_addr(subnet):
    network = ipaddress.ip_network(subnet)
    max_value = int(network.network_address) + network.num_addresses - 1
    random_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), max_value))
    return str(random_ip)


class WLanThread(ThreadBase):
    """
    Thread class for WLAN operations.
    """
    client_info, dut_info = {"mac_address": None, "ip_address": None},{"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None, test_type=None, ping_from="remote", ping_count=10,
                 ipv6_addr_type="global", ping_before_power_save=None, ping_after_power_save=None):

        super().__init__()
        self.wifi_dut, self.wifi_access_point, self.sl_collections, self.test_name, self.wifi_client, self.test_id, \
        self.ping_from, self.ping_count, self.test_type, self.ipv6_addr_type, self.ping_before_power_save, self.ping_after_power_save= \
            wifi_dut, wifi_access_point, sl_collections, test_name, wifi_client,\
            test_id, ping_from, ping_count, test_type, ipv6_addr_type, ping_before_power_save, ping_after_power_save

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def ping(self, ip_address=None, ping_from="remote", ping_count=10, ip_version="ipv4"):
        """
        Ping the given IP address.
        """
        if ping_from == "remote":
            status = self.sl_collections.ping(device_ip=ip_address, ping_count=ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if ping_from == "dut":
            self.wifi_dut.interfaces.wifi.ping(server_ip=ip_address, ip_version=ip_version, ping_size=64,
                                                      num_ping_attempts=10)

    def run(self):
        """
        Runs the thread.
        """
        dut_add_dict = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                wifi_access_point=self.wifi_access_point,
                                                                associated=self.wifi_dut.interfaces.wifi.associated,
                                                                power_save=False, retry_count=3,
                                                                ping_before_power_save=False,
                                                                ping_after_power_save=False,
                                                                )
        if self.test_id in [156971]:

            static_ipv6 = random_ipv6_addr("2401:3500:133c:1341::/64")
            remote_ipv6 = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
            logger().info(f"remote_ipv6: {remote_ipv6}")

            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=0,
                                                               static_ipv6_address=static_ipv6,
                                                               ipv6_gw_address=static_ipv6)
            dut_add_dict['device_ipv6_global'] = ip_config[1]
            logger().info(f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']}\n"
                          f"DUT IPV4 ADDRESS : {dut_add_dict['device_ip']}\n"
                          f"DUT IPV6 ADDRESS : {dut_add_dict['device_ipv6_global']}\n")

        else:

            ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                    ip_version="ipv6")
            assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
            dut_add_dict['device_ipv6_global'] = ip_config[1]
            dut_add_dict['device_ipv6_link'] = ip_config[0]
            logger().info(f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']}\n"
                          f"DUT IPV4 ADDRESS : {dut_add_dict['device_ip']}\nDUT IPV6 GLOBAL ADDRESS : {dut_add_dict['device_ipv6_global']}\n"
                          f"DUT IPV6 LINK LOCAL ADDRESS : {dut_add_dict['device_ipv6_link']}\n")

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile('power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        else:
            logger().info("skip power save mode configuration as in harness power_save flag is set to False")

        time.sleep(20)

        remote_ipv6 = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ipv6: {remote_ipv6}")
        remote_ipv6 = ipaddress.ip_address(remote_ipv6)
        remote_ipv4 = self.wifi_client.interfaces.wifi.get_ip_address(version=4)
        logger().info(f"remote_ipv4: {remote_ipv4}")
        remote_ipv6 = ipaddress.ip_address(remote_ipv6)

        if self.test_id in [156957, 156959]:
            self.ping(ip_address=remote_ipv4, ping_from="dut", ping_count=self.ping_count, ip_version="ipv4")
            logger().info("IPV6 ping successful")

            self.ping(ip_address=remote_ipv6, ping_from="dut", ping_count=self.ping_count, ip_version="ipv6")
            logger().info("IPV6 ping successful")

        if self.test_id in [156954, 156955, 156958, 156975, 156971]:
            logger().info("ping from remote to DUT")
            self.ping(ip_address=dut_add_dict['device_ip'], ping_from="remote", ping_count=self.ping_count)
            logger().info("IPV4 ping successful")

            self.ping(ip_address=dut_add_dict['device_ipv6_global'], ping_from="remote", ping_count=self.ping_count)
            logger().info("IPV6 ping successful")

        if self.test_id in [156960, 156961, 156962]:

            interface = self.wifi_client.interfaces.wifi.config["interface"]
            ping_link_local_addr = f"{dut_add_dict['device_ipv6_link']}%{interface}"

            logger().info("ping from remote to DUT")
            client_thread1 = Thread(target=self.ping, args=(remote_ipv4, "dut", self.ping_count, "ipv4"), )
            client_thread1.start()
            self.ping(ip_address=dut_add_dict['device_ipv6_global'], ping_from="remote", ping_count=self.ping_count)
            logger().info(" ping to IPV6 global successful")
            self.ping(ip_address=ping_link_local_addr, ping_from="remote", ping_count=self.ping_count)
            logger().info(" ping to IPV6 link local successful")
            client_thread1.join()
            logger().info("ping to IPV4 successful")




def wifi_dut_config(extra_features):
    return {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | extra_features,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }

@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateless_dhcpv6_WPA2_C156954(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter, utf_constants,
                                                          wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(Si91xExtCustomFeatureBitMap.IEEE802_11W))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460",
                               "ipv6_state": "1", "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateful_dhcpv6_WPA3_C156955(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter,
                                                         utf_constants, wifi_client):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Configure AP on WPA3 security with ipv6 stateful dhcpv6
            3. Join the access point and enable the dhcpv4 and dhcpv6
            4. Enable wlan and bt power save mode in dut after the connection
            5. Ping from remote to DUT IPV6 address

        """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460",
                               "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateless_dhcpv6_WPA2_C156957(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter, utf_constants,
                                                          wifi_client):
    """
            Test Steps:
                1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
                2. Configure AP on WPA2 security with ipv6 stateless dhcpv6
                3. Join the access point and enable the dhcpv4 and dhcpv6
                4. Enable wlan and bt power save mode in dut after the connection
                5. Ping from DUT to remote IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections,
                              test_type="ping", ping_from="dut",
                              ping_count=ping_count, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(Si91xExtCustomFeatureBitMap.IEEE802_11W))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460",
                               "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])

def test_wifi_sdk_ipv4_ipv6_stateful_dhcpv6_WPA3_C156958(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                         request,
                                                         sniffer_filter, utf_constants, wifi_client):
    """
            Test Steps:
                1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
                2. Configure AP on WPA3 security with ipv6 stateful dhcpv6
                3. Join the access point and enable the dhcpv4 and dhcpv6
                4. Enable wlan and bt power save mode in dut after the connection
                5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_id=156958,
                              ping_count=ping_count, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(Si91xExtCustomFeatureBitMap.IEEE802_11W))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460",
                               "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
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
                              test_name=test_name, sl_collections=sl_collections, test_id=156959,
                              ping_count=ping_count, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460",
                               "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
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
                              test_id=156960, wifi_client=wifi_client,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              ping_count=ping_count)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(Si91xExtCustomFeatureBitMap.IEEE802_11W))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460",
                               "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_sim_ping_ipv4_ipv6_stateless_dhcpv6_WPA3_C156961(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sl_collections, request,
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
                              wifi_client=wifi_client,
                              test_id=156961,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              ping_count=ping_count)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460",
                               "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_sim_ping_ipv4_ipv6_stateless_dhcpv6_WPA2_C156962(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
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
                              test_id=156962,
                              ping_count=ping_count,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460",
                               "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ip_assign_dut_while_conn_disc_C156975(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                          request,
                                                          sniffer_filter,utf_constants,
                                                                   wifi_client):
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ping_count = utf_constants.get("ping_count")
        for i in range(15):
            wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  test_name=test_name, sl_collections=sl_collections,
                                  wifi_client=wifi_client,
                                  test_id=156975,
                                  ping_count=ping_count,
                                  ping_before_power_save=False,
                                  ping_after_power_save=False,
                                  )
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config(0))
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460",
                               "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3:3444::/64")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_static_ip_DUT_stateful_dhcpv6_WPA2_C156971(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                             request,
                                                             sniffer_filter, utf_constants,
                                                             wifi_client):
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ping_count = utf_constants.get("ping_count")

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client,
                              test_id=156971,
                              ping_count=ping_count,
                              ping_before_power_save=False,
                              ping_after_power_save=False,
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)











