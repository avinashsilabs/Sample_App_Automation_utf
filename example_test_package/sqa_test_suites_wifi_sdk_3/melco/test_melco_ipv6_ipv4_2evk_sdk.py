from utf.utils.logger import get_logger
import pytest
import string
import time
from retry import retry
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
    Si91xExtCustomFeatureBitMap,
    Si91xJoinFeatureBitMap
)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from threading import Thread
from utf.utf_config import UtfConfig
from test_melco_ipv6_ipv4_sdk import IperfThraed, WLanConThread


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




def wifi_dut_marker(ext_custom_bit=0, thread_count=1, tcp_feat_bit=0, ca_cert=None):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | tcp_feat_bit,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


def remote_wiseconnect3_config():
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "Concurent_AP", "passphrase": "Automation@123", "channel": 11
    }

    return pytest.mark.config("remote_wiseconnect3", wifi=config)


@wifi_dut_marker()
@remote_wiseconnect3_config()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_ipv4_ipv6_ping_C557354(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                               request, remote_wiseconnect3,
                                               sniffer_filter, utf_constants,
                                               wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 set_power_save=True,
                                 remote_type="dut"

                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@remote_wiseconnect3_config()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_melco_sdk_ipv4_ipv6_ping_C557356(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                               request, remote_wiseconnect3,
                                               sniffer_filter, utf_constants,
                                               wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 set_power_save=True,
                                 remote_type="dut"
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@remote_wiseconnect3_config()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_melco_sdk_ipv4_ipv6_ping_STA_LI_powersave_C557357(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections,
                                                                request, remote_wiseconnect3,
                                                                sniffer_filter, utf_constants,
                                                                wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 set_power_save=True, listen_interval=True,
                                 ipv6_addr_type="link",
                                 remote_type="dut"
                                 )

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@remote_wiseconnect3_config()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_melco_sdk_ipv4_ipv6_ping_STA_DTIM_powersave_C557358(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                  sl_collections,
                                                                  request, remote_wiseconnect3,
                                                                  sniffer_filter, utf_constants,
                                                                  wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 set_power_save=True,
                                 ipv6_addr_type="link",
                                 ping_from="remote",
                                 remote_type="dut"
                                 )

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
