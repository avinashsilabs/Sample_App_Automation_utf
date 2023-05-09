import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect.devices.rs911x import RS9116ExtCustomFeatureBitMap,RS9116JoinFeatureBitMap,\
    RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes,\
    RS9116CustomFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_device_output_parser import Result
from retry import retry
from test_wlan_sta_enterprise import SnifferValidationProcess



def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Aravind
"""
class FilterPacket:
    def find_time_stamp(self):
        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            for x in line:
                count = count + 1
                if packet_filter1 in x:
                    result = re.search(r'\d+:\d+:\d+.\d+', x)
                    logger().info(f" RESULT {result}")
                    time_stamp = result.group()
                    logger().info(f'time_stamp={time_stamp}')
                    time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list

# configure ping_count to ping dut
ping_count = 1
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode |
                               RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        }
)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"passphrase": "12345678", "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])

def test_wpa2_personal_wrong_password_c113884(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True
    '''test case executes to validate wpa2 personal security when wr0ng password is issued '''
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wpa2_personal_wrong_password_c113884')
    for i in range(1, utf_constants.get('iter_count')):
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point, passphrase="123456789")
            assert exc_info.value.error_code == 0x8, "Connection should fail with error code 0x8"
        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiate ip command")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
            assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
    packet_filter1 = f'(wlan.sa=={ap_mac}) && (wlan.rsn.akms.count == 1) && (wlan.fc.type_subtype==8)'
    packet_filter2 = f'(wlan.sa=={ap_mac}) && (wlan.da=={dut_mac_address}) && (wlan.fixed.reason_code==0x0002)'

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find akm suite in beacon'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find deauth packet from ap with reason code 0x0002'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "passphrase":'wpa3personal'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode |
                               RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_wpa3_personal_wrong_password_C113885(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    '''test case executes to validate wpa3 personal security when wrong password is issued '''
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wpa3_personal_wrong_password_C113885')
    time.sleep(2)
    for i in range(1, utf_constants.get('iter_count')):
        with pytest.raises(WlanError) as exc_info:
            passphrase= "thisisatest"
            logger().info(f"***** preparing wifi_dut ******")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                             | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired, passphrase=passphrase)
            assert exc_info.value.error_code == 0x20, "Connection should fail with error code 0x20"
        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiate ip command")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
            assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
    packet_filter1 = f'(wlan.sa=={ap_mac}) && (wlan.rsn.akms.count == 1) && (wlan.fc.type_subtype==8)'
    time.sleep(5)
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find akm suite in beacon'
