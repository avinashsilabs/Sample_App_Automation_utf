import pytest
import time
import re
from datetime import datetime, date
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import (
    Cipher,
    SecurityMode,
    Standard,
    Bandwidth,
    Rate,
    Channel,
    CountryCode,
    WirelessBand,
    WiFiScanResult,
)
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xJoinFeatureBitMap, \
    Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.security_enhancements.test_wpa3_enterprise_sdk import WPA3Enterprise

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Get wireless stats using sl_wifi_get_wireless_info()

    Author: Shailesh Kharecha

"""



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wireless_get_info_in_wpa2_11n_c777564(wifi_dut,request, wifi_access_point, sl_collections,utf_constants):
    """Verify whether the device is able to get the
       wireless information in WAP2 security-station mode)"""
    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       ping_after_power_save=True, retry_count=3,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       pmk_enable=True)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        data = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=100)
        logger().info(f"\n Wireless DUT Stats: {data} \n")
        stats = {}
        # Number of stations connected
        stats['Number_of_stations_connected'] = re.findall(r"(?<=Number of stations connected\s:)\d+", str(data))[0]
        # Channel number
        stats['Channel number'] = re.findall(r"(?<=Channel number\s:)\d+", str(data))[0]
        # SSID
        stats['ssid'] = re.findall(r"(?<=ssid\s:)[^\n]+", str(data))[0]
        # MAC address
        stats['MAC_address'] = re.findall(r"(?<=MAC address\s:)[0-9a-fA-F:]+", str(data))[0]
        # Security type
        stats['Security_type'] = re.findall(r"(?<=Security type\s:)\d+", str(data))[0]
        # PMF
        stats['pmk'] = re.findall(r"(?<=\n)\w+(?=ipv4_address)", str(data))[0]
        # IPv4 address
        # stats['ipv4_address'] = re.findall(r"(?<=ipv4_address:)[0-9\.]+", str(data))[0]
        stats['ipv4_address'] = re.findall(r"(?<=ipv4_address:)[0-9\:]+", str(data))[0]
        stats['ipv4_address'] = stats['ipv4_address'].replace(":", ".")

        logger().info(
            f"Validation of wireless_info API")

        if int(stats['Channel number']) == int(wifi_access_point.interfaces.wifi.channel):
            logger().info(
                f"Channel number validation passed: {stats['Channel number']} == {wifi_access_point.interfaces.wifi.channel}")
        else:
            logger().error(
                f"Channel number validation failed: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}")
            assert False, f"Channel number mismatch: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}"

        if stats['ssid'] == wifi_access_point.interfaces.wifi.ssid:
            logger().info(f"SSID validation passed: {stats['ssid']} == {wifi_access_point.interfaces.wifi.ssid}")
        else:
            logger().error(f"SSID validation failed: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}")
            assert False, f"SSID mismatch: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}"

        # Compare MAC addresses and log the result
        if stats['MAC_address'].lower() == dut_mac_address.lower():
            logger().info(f"MAC address validation passed: {stats['MAC_address']} == {dut_mac_address}")
        else:
            logger().error(f"MAC address validation failed: {stats['MAC_address']} != {dut_mac_address}")
            assert False, f"MAC address mismatch: {stats['MAC_address']} != {dut_mac_address}"

        dut_security_type = int(wifi_dut.interfaces.wifi.convert_security_mode('wpa2'))
        stats_security_type = int(stats['Security_type'])

        if stats_security_type == dut_security_type:
            logger().info(f"Security type validation passed: {stats_security_type} == {dut_security_type}")
        else:
            logger().error(f"Security type validation failed: {stats_security_type} != {dut_security_type}")
            assert False, f"Security type mismatch: {stats_security_type} != {dut_security_type}"

        logger().info(f"PMK value from get wireless info API : {stats['pmk']}")

        ip_address = str(wifi_dut.interfaces.wifi.get_ip_address())
        if ip_address == str(stats['ipv4_address']):
            logger().info(f"IP address validation passed: {ip_address} == {stats['ipv4_address']}")
        else:
            logger().error(f"IP address validation failed: {ip_address} != {stats['ipv4_address']}")
            assert False, f"IP address mismatch: {ip_address} != {stats['ipv4_address']}"

        logger().info(f"Note: Since the Get Wireless Info API in automation does not return the BSSID and 802.11 wireless standard information, these details were obtained directly from the access point.: ")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"BSSID info: {da_addr}")

        w_standard = wifi_access_point.interfaces.wifi.standard
        logger().info(f"802.11 wireless Standard info: {w_standard}")

        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA3',
                                               "protected_management_frame": "Capable", })
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_wireless_get_info_in_wpa3_personal_11ax_c777565(wifi_dut, request, utf_constants, wifi_sniffer,
                                                             sniffer_filter, wifi_access_point, sl_collections):
    """Verify whether the device is able to get the
       wireless information in WPA3 security-station mode"""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, power_save=True,
                                            mode=mode, ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        data = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=100)
        logger().info(f"\n Wireless DUT Stats: {data} \n")
        stats = {}
        # Number of stations connected
        stats['Number_of_stations_connected'] = re.findall(r"(?<=Number of stations connected\s:)\d+", str(data))[0]
        # Channel number
        stats['Channel number'] = re.findall(r"(?<=Channel number\s:)\d+", str(data))[0]
        # SSID
        stats['ssid'] = re.findall(r"(?<=ssid\s:)[^\n]+", str(data))[0]
        # MAC address
        stats['MAC_address'] = re.findall(r"(?<=MAC address\s:)[0-9a-fA-F:]+", str(data))[0]
        # Security type
        stats['Security_type'] = re.findall(r"(?<=Security type\s:)\d+", str(data))[0]
        # PMF
        stats['pmk'] = re.findall(r"(?<=\n)\w+(?=ipv4_address)", str(data))[0]
        # IPv4 address

        stats['ipv4_address'] = re.findall(r"(?<=ipv4_address:)[0-9\:]+", str(data))[0]
        stats['ipv4_address'] = stats['ipv4_address'].replace(":", ".")

        logger().info(
            f"Validation of wireless_info API")

        if int(stats['Channel number']) == int(wifi_access_point.interfaces.wifi.channel):
            logger().info(
                f"Channel number validation passed: {stats['Channel number']} == {wifi_access_point.interfaces.wifi.channel}")
        else:
            logger().error(
                f"Channel number validation failed: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}")
            assert False, f"Channel number mismatch: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}"

        if stats['ssid'] == wifi_access_point.interfaces.wifi.ssid:
            logger().info(f"SSID validation passed: {stats['ssid']} == {wifi_access_point.interfaces.wifi.ssid}")
        else:
            logger().error(f"SSID validation failed: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}")
            assert False, f"SSID mismatch: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}"

        # Compare MAC addresses and log the result
        if stats['MAC_address'].lower() == dut_mac_address.lower():
            logger().info(f"MAC address validation passed: {stats['MAC_address']} == {dut_mac_address}")
        else:
            logger().error(f"MAC address validation failed: {stats['MAC_address']} != {dut_mac_address}")
            assert False, f"MAC address mismatch: {stats['MAC_address']} != {dut_mac_address}"

        dut_security_type = int(wifi_dut.interfaces.wifi.convert_security_mode('wpa3'))
        stats_security_type = int(stats['Security_type'])

        if stats_security_type == dut_security_type:
            logger().info(f"Security type validation passed: {stats_security_type} == {dut_security_type}")
        else:
            logger().error(f"Security type validation failed: {stats_security_type} != {dut_security_type}")
            assert False, f"Security type mismatch: {stats_security_type} != {dut_security_type}"

        logger().info(f"PMK value from get wireless info API : {stats['pmk']}")

        ip_address = str(wifi_dut.interfaces.wifi.get_ip_address())
        if ip_address == str(stats['ipv4_address']):
            logger().info(f"IP address validation passed: {ip_address} == {stats['ipv4_address']}")
        else:
            logger().error(f"IP address validation failed: {ip_address} != {stats['ipv4_address']}")
            assert False, f"IP address mismatch: {ip_address} != {stats['ipv4_address']}"

        logger().info(
            f"Note: Since the Get Wireless Info API in automation does not return the BSSID and 802.11 wireless standard information, these details were obtained directly from the access point.: ")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"BSSID info: {da_addr}")

        w_standard = wifi_access_point.interfaces.wifi.standard
        logger().info(f"802.11 wireless Standard info: {w_standard}")

        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])

def test_wifi_sdk_wireless_get_info_in_wpa3_enterprise_11ax_c777567(wifi_dut, wifi_access_point,
                                                             radius_server, sl_collections, request,
                                                              wifi_client):
    """Verify whether the device is able to get the wireless information in WPA3 enterprise security-station mode """
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679996", wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        data = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=100)
        logger().info(f"\n Wireless DUT Stats: {data} \n")
        stats = {}
        # Number of stations connected
        stats['Number_of_stations_connected'] = re.findall(r"(?<=Number of stations connected\s:)\d+", str(data))[0]
        # Channel number
        stats['Channel number'] = re.findall(r"(?<=Channel number\s:)\d+", str(data))[0]
        # SSID
        stats['ssid'] = re.findall(r"(?<=ssid\s:)[^\n]+", str(data))[0]
        # MAC address
        stats['MAC_address'] = re.findall(r"(?<=MAC address\s:)[0-9a-fA-F:]+", str(data))[0]
        # Security type
        stats['Security_type'] = re.findall(r"(?<=Security type\s:)\d+", str(data))[0]
        # PMF
        stats['pmk'] = re.findall(r"(?<=\n)\w+(?=ipv4_address)", str(data))[0]
        # IPv4 address
        # stats['ipv4_address'] = re.findall(r"(?<=ipv4_address:)[0-9\.]+", str(data))[0]
        stats['ipv4_address'] = re.findall(r"(?<=ipv4_address:)[0-9\:]+", str(data))[0]
        stats['ipv4_address'] = stats['ipv4_address'].replace(":", ".")

        logger().info(
            f"Validation of wireless_info API")

        if int(stats['Channel number']) == int(wifi_access_point.interfaces.wifi.channel):
            logger().info(
                f"Channel number validation passed: {stats['Channel number']} == {wifi_access_point.interfaces.wifi.channel}")
        else:
            logger().error(
                f"Channel number validation failed: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}")
            assert False, f"Channel number mismatch: {stats['Channel number']} != {wifi_access_point.interfaces.wifi.channel}"

        if stats['ssid'] == wifi_access_point.interfaces.wifi.ssid:
            logger().info(f"SSID validation passed: {stats['ssid']} == {wifi_access_point.interfaces.wifi.ssid}")
        else:
            logger().error(f"SSID validation failed: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}")
            assert False, f"SSID mismatch: {stats['ssid']} != {wifi_access_point.interfaces.wifi.ssid}"

        # Compare MAC addresses and log the result
        if stats['MAC_address'].lower() == dut_mac_address.lower():
            logger().info(f"MAC address validation passed: {stats['MAC_address']} == {dut_mac_address}")
        else:
            logger().error(f"MAC address validation failed: {stats['MAC_address']} != {dut_mac_address}")
            assert False, f"MAC address mismatch: {stats['MAC_address']} != {dut_mac_address}"

        dut_security_type = int(wifi_dut.interfaces.wifi.convert_security_mode('wpa3_enterprise'))
        stats_security_type = int(stats['Security_type'])

        if stats_security_type == dut_security_type:
            logger().info(f"Security type validation passed: {stats_security_type} == {dut_security_type}")
        else:
            logger().error(f"Security type validation failed: {stats_security_type} != {dut_security_type}")
            assert False, f"Security type mismatch: {stats_security_type} != {dut_security_type}"

        logger().info(f"PMK value from get wireless info API : {stats['pmk']}")

        ip_address = str(wifi_dut.interfaces.wifi.get_ip_address())
        if ip_address == str(stats['ipv4_address']):
            logger().info(f"IP address validation passed: {ip_address} == {stats['ipv4_address']}")
        else:
            logger().error(f"IP address validation failed: {ip_address} != {stats['ipv4_address']}")
            assert False, f"IP address mismatch: {ip_address} != {stats['ipv4_address']}"

        logger().info(
            f"Note: Since the Get Wireless Info API in automation does not return the BSSID and 802.11 wireless standard information, these details were obtained directly from the access point.: ")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"BSSID info: {da_addr}")

        w_standard = wifi_access_point.interfaces.wifi.standard
        logger().info(f"802.11 wireless Standard info: {w_standard}")

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
