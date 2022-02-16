from interfaces.wifi import WlanError

from devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap
import time
import pytest
from utils.logger import get_logger
from utils.iperf.iperf_utils import ping


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
@pytest.mark.end_state("wifi_access_point", wifi="ap_enabled")
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
def test_dns_server_c19297(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"********this test_case to validate DNS_SERVER WITH DHCP********")
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dns_server_c19297')
    time.sleep(2)

    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    packet_filter2 = f'wlan.sa == {mac_address} and dns'

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)
    logger().info(f"*****Enable Max PSP in DUT******")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    status = ping(device_ip, 4)
    time.sleep(2)
    logger().info("=======DNS SERVER WITH DHCP========")
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
    logger().info(result.decode())
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)


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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,

    }
)
def test_dns_server_c19299(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"***********this test_case to validate DNS_SERVER without enabling DNS feature*******")

    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)
    logger().info(f"*****Enable Max PSP in DUT******")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")
    time.sleep(2)

    status = ping(device_ip, 4)

    time.sleep(2)
    logger().info("=======DNS SERVER WITHOUT ENABLING DNS FEATURE========")
    with pytest.raises(WlanError) as exc_info:
        result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
        logger().info(result.decode())
    assert exc_info.value.error_code == 0xFF74