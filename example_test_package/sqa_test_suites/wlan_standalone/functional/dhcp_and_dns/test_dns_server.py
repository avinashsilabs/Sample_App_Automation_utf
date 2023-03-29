from utf.interfaces.wifi import WlanError

from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116PowerSaveProcedureTypes, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G 
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BT
        6. Issue DNS query
        7. Stop the sniffer  
        8. Analyizing all sniffer capture packets and find the dns packets in sniffer file.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    Author: Benazeer K
"""

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 3, "security": 'OPEN'})
def test_dns_server_ip_with_dhcp_hs_c19297(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"********Query DNS server IP address when DNS IP address is obtained through dhcp hs********")
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_server_ip_with_dhcp_hs_c19297')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    packet_filter4 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    packet_filter3 = f'dhcp.hw.mac_addr == {mac_address}'

    logger().info(f"***** Enabling Power save mode ******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, 5)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info("=======DNS SERVER WITH DHCP========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
    logger().info(result.decode())
    time.sleep(2)
    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"DHCP decryption is in progress {decryption_key}")
    wifi_sniffer.interfaces.capture.get_dhcp_list(mac_address, decryption_key, ["dhcp"])
    logger().info(f"*****##### Sniffer validation for DHCP packets #####******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']
    if result is False:
        logger().info('Unable to find DNS packet')
        assert True
    elif result is True:
        logger().info('Found DNS packet')
        assert True


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_dns_server_ip_when_set_statically_c19298(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"****Query DNS server IP address when DNS server IP addresses are set statically****")
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_server_ip_when_set_statically_c19298')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    packet_filter3 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    logger().info(f"***** Enabling Power save mode ******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, 5)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info("=======DNS SERVER WITH DHCP========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
    logger().info(result.decode())
    time.sleep(2)
    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    result =  wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    if result is False:
        logger().info('Unable to find DNS packet')
        assert True
    elif result is True:
        logger().info('Found DNS packet')
        assert True

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,

    }
)
def test_dns_server_when_dns_feature_not_enabled_c19299(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"****Query DNS Server IP address when DNS feature is not enabled in oper_mode****")

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    logger().info(f"***** Enabling Power save mode ******")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, 5)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info("=======DNS SERVER WITHOUT ENABLING DNS FEATURE========")
    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xFF74