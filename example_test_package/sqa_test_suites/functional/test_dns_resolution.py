from utf.interfaces.wifi import WlanError

from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping


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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19300_301_311(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19300_301_311')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter4 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    packet_filter3 = f'dhcp.hw.mac_addr == {mac_address}'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======Initiating DNS Get command========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******#### Sniffer validation for DHCP packets *******####")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    logger().info(f"*******#### Sniffer validation for DNS packets *******#####")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19302(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19302')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======DNS get command with primary & Secondary Static IPs for DNS server========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******#### Sniffer Validation for DNS packets *******####")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19303(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19303')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======DNS get command with Primary DNS server IP only========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "NULL")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******##### Sniffer Validation for DNS packets *******#####")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19304(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19304')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======DNS get command with Secondary DNS server IP ========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "10.8.4.10")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******  Sniffer Validation for DNS packets *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19305(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19305')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======DNS get command with Primary & Secondary DNS server IP's are 0's ========")
    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "0.0.0.0", "0.0.0.0")
        logger().info(result.decode())
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)
    assert exc_info.value.error_code == 0xbba1
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19306(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19310')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    with pytest.raises(WlanError) as exc_info:
        logger().info("=======DNS get command with Primary & Secondary DNS server IP's which are wrong ========")
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.210.91", "10.81.44.13")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xbba3

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    logger().info(f"*******#### Sniffer Validation for DNS packets *******####")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19307(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19310')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"***** Assigning static IP for DUT with wrong gateway ******")
    wifi_dut.interfaces.wifi.start_ip(mode='static', ip_address='192.168.50.123', subnet='255.255.255.0',
                                      gateway='192.168.50.55')

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("#### Get DNS response when DUT get static IP and with wrong gateway ####")
    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xbba3

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"*******  Sniffer Validation for DNS packets *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19308(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19310')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.207.110.11")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xaf

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19309(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19310')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.207.110.11")
        logger().info(result.decode())
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.207.110.11")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xaf

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
def test_dns_resolution_c19310(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    logger().info(f"***** Sniffer going to start ******")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_resolution_c19310')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    logger().info(f"***** preparing wifi_dut to join third party AP ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter3 = f'wlan.addr == {mac_address} && dns.id == dns.id'

    logger().info(f"*****Initiated Power_save Mode 2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)

    logger().info("=======DNS get command with Primary & Secondary DNS server IP's twice ========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
    logger().info(result.decode())
    time.sleep(5)
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"*******  Sniffer Validation for channel = {wifi_access_point.interfaces.wifi.channel} *******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger().info(f"####*******  Sniffer Validation for DNS packets *******####")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)

