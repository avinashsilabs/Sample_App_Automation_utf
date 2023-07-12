import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
import ipaddress
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.wifi import WlanError
import random
import string
from random import randint
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116OperatingMode, RS9116Band, SocketOptions, \
    SocketType, Cipher, DeviceConstants,RS9116StoreConfiguration
from utf import UtfDatabaseProperties


"""
    1. Configure the DUT in Wlan coex mode for 2.4Ghz
    2. Join the access point and enable the dhcpv6 address
    3. Enable the wlan and bt power save mode in dut after the connection
    4. Initiate ping from the dut
    
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Harshitha 
"""

""" Below test Cases are depended on Jira - https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1493"""

def logger():
    return get_logger(__name__)


def join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel):

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file)

    logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
    time.sleep(3)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address is : {dut_mac_address}")

    logger().info(f"====== Firmware version ========")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info("============ Associating the dut to AP ================")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

def power_save(wifi_dut):

    logger().info("=======Initiating power save======")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
         wifi= {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.DHCPv6Client |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        }
    )
]
@pytest.mark.config('wifi_access_point',wifi={ "ssid": "ipv6_C119345", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dut_ipv6_check_C119345(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel

        capture_file = "test_dut_ipv6_check_C119345"

        ping_count = utf_constants.get("ping_count")

        join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("======= Fetching the ip address of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f" The prefix value is : {str(prefix_length)}")
        logger().info(f" The link local address is {linklocaladdr}")
        logger().info(f"The global unicast address is  {global_addr}")
        logger().info(f" The gateway address is {gateway_addr}")

        power_save(wifi_dut)

        logger().info("======Initiating Ping to DUT=======")
        status = ping(global_addr, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'ip.version ==6 && icmpv6.type ==129'
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

@pytest.mark.config('wifi_access_point',wifi={ "ssid": "stateless_C119348", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_verify_stateless_dhcpv6_protocol_C119348(wifi_sniffer, wifi_dut, wifi_access_point):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel

        capture_file = "test_verify_stateless_dhcpv6_protocol_C119348"

        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")

        dut_mac_address = join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("========Fetching the ip of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f"the prefix value is {str(prefix_length)}")
        logger().info(f"the link local address is {linklocaladdr}")
        logger().info(f"the global uni-cast address {global_addr}")
        logger().info(f"the gateway address is {gateway_addr}")

        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'ip.version ==6 && wlan.sa =={dut_mac_address} && icmpv6.type == 133'
        # packet_filter1 = f"ip.version == 6 && wlan.da == {dut_mac_address} && icmpv6.type == 134"

        # wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)

        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as Ex:
        logger().info(f"Exception: {str(Ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise Ex
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

@pytest.mark.config('wifi_access_point',wifi={ "ssid": "linklocal_C119403", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ping_functionality_linklocaladdr_stateful_C119403(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants):
    try:
        validation = True
        capture_file = "test_ping_functionality_linklocaladdr_stateful_C119403"

        channel = wifi_access_point.interfaces.wifi.channel

        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file)

        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {dut_mac_address}")

        logger().info(f"====== Firmware version ========")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")

        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f"the prefix value is {str(prefix_length)}")
        logger().info(f"the link local address is {linklocaladdr}")
        logger().info(f"the global uni-cast address {global_addr}")
        logger().info(f"the gateway address is {gateway_addr}")

        logger().info(f"======Initiating power save======")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info(f"======Pinging to DUT=======")
        status = ping(global_addr, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'(icmpv6.type == 128 || icmpv6.type == 129) && ((ipv6.src == {global_addr} && ' \
                        f'ipv6.dst == {gateway_addr}) || (ipv6.src == {gateway_addr} && ipv6.dst == {global_addr}))'
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

@pytest.mark.config('wifi_access_point',wifi={ "ssid": "stateful_C119394", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ping_functionality_global_unicast_address_stateful_C119394(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    try:
        validation = True
        capture_file = "test_ping_functionality_global_unicast_address_stateful_C119394"

        channel = wifi_access_point.interfaces.wifi.channel

        ping_count = utf_constants.get("ping_count")

        join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("========Fetching the ip of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f"the prefix value is {str(prefix_length)}")
        logger().info(f"the link local address is {linklocaladdr}")
        logger().info(f"the global uni-cast address {global_addr}")
        logger().info(f"the gateway address is {gateway_addr}")

        power_save(wifi_dut)

        logger().info("======Initiating Ping to DUT=======")
        status = ping(global_addr, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'(icmpv6.type == 128 || icmpv6.type == 129) && ((ipv6.src == {global_addr} && ' \
                         f'ipv6.dst == {gateway_addr}) || (ipv6.src == {gateway_addr} && ipv6.dst == {global_addr}))'
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config('wifi_access_point',wifi={ "ssid": "stateless_C119393", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ping_functionality_global_unicast_address_stateless_C119393(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    try:
        validation = True
        capture_file = "test_ping_functionality_global_unicast_address_stateless_C119393"

        channel = wifi_access_point.interfaces.wifi.channel

        ping_count = utf_constants.get("ping_count")

        join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("========Fetching the ip of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f"the prefix value is {str(prefix_length)}")
        logger().info(f"the link local address is {linklocaladdr}")
        logger().info(f"the global uni-cast address {global_addr}")
        logger().info(f"the gateway address is {gateway_addr}")

        power_save(wifi_dut)

        logger().info("======Initiating Ping to DUT=======")
        status = ping(global_addr, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'(icmpv6.type == 128 || icmpv6.type == 129) && ((ipv6.src == {global_addr} && ' \
                         f'ipv6.dst == {gateway_addr}) || (ipv6.src == {gateway_addr} && ipv6.dst == {global_addr}))'
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config('wifi_access_point',wifi={ "ssid": "shortest_C119362", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ping_functionality_shortest_ipv6_address_C119362(wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants):
    try:
        validation = True
        capture_file = "test_ping_functionality_shortest_ipv6_address_C119362"

        channel = wifi_access_point.interfaces.wifi.channel

        ping_count = utf_constants.get("ping_count")

        join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("======= Fetching the ip address of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f" The prefix value is : {str(prefix_length)}")
        logger().info(f" The link local address is {linklocaladdr}")
        logger().info(f"The global unicast address is  {global_addr}")
        logger().info(f" The gateway address is {gateway_addr}")

        power_save(wifi_dut)

        logger().info("======Initiating Ping to DUT=======")
        status = ping(global_addr, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'(icmpv6.type == 128 || icmpv6.type == 129) && ((ipv6.src == {global_addr} && ' \
                         f'ipv6.dst == {gateway_addr}) || (ipv6.src == {gateway_addr} && ipv6.dst == {global_addr}))'
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()



@pytest.mark.config('wifi_access_point',wifi={ "ssid": "stateful_C119349", "security": "WPA2","passphrase": "test1234"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_verify_stateful_dhcpv6_protocol_C119349(wifi_sniffer, wifi_dut, wifi_access_point):
    try:
        validation = True

        channel = wifi_access_point.interfaces.wifi.channel

        capture_file = "test_verify_stateful_dhcpv6_protocol_C119349"

        dut_mac_address = join_ap(wifi_dut, wifi_sniffer, wifi_access_point, capture_file, channel)
        time.sleep(2)

        logger().info("========Fetching the ip of dhcp6 address=======")
        prefix_length, linklocaladdr, global_addr, gateway_addr = wifi_dut.interfaces.wifi.start_ip(version=6)
        logger().info(f"the prefix value is {str(prefix_length)}")
        logger().info(f"the link local address is {linklocaladdr}")
        logger().info(f"the global uni-cast address {global_addr}")
        logger().info(f"the gateway address is {gateway_addr}")

        power_save(wifi_dut)

        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'ip.version ==6 && wlan.sa =={dut_mac_address} && icmpv6.type == 133'

        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    except Exception as ex:
        logger().info(f"Exception: {str(ex)}")
        wifi_dut.interfaces.wifi.leave()
        raise ex
    finally:
        wifi_dut.interfaces.wifi.leave()




