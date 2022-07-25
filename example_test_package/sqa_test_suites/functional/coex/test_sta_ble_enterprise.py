import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap, RS9116CertificateType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import threading
from threading import *
import time

import rs_coex_common_apis as SC

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify more data bit to be enable in QOS data frames and power management bit in ps polls
        6. Initiate BLE advertise/scan
        7. Run Iperf data transfer/Download http data

    Author: swathi.pathuri
"""

def logger():
    return get_logger(__name__)


ping_count = 50

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TLS_BLE_adv_C20215(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TLS_BLE_adv_C20215"
    logger().info("testcase : test_sta_ble_TLS_BLE_adv_C20215")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = SC.BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = SC.WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                             eap_type="TLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TTLS_BLE_adv_C20216(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TTLS_BLE_adv_C20216"
    logger().info("testcase : test_sta_ble_TTLS_BLE_adv_C20216")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = SC.BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = SC.WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                             eap_type="TTLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_PEAP_BLE_adv_C20217(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_PEAP_BLE_adv_C20217"
    logger().info("testcase : test_sta_ble_PEAP_BLE_adv_C20217")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = SC.BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = SC.WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                             eap_type="PEAP", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_disconnect", "clear_certs"])
def test_sta_ble_TCP_UDP_TLS_C20205(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, ble_client, net_perf_client):
    testcase = "test_sta_ble_TCP_UDP_TLS_C20205"
    logger().info("testcase : test_sta_ble_TCP_UDP_TLS_C20205")
    validation = True
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    traffic_types = ["RX", "TX"]
    logger().info(f"configuring the Sniffer with the channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = SC.BleThread_Connection(wifi_dut, ble_client, mode="ble_master")
    wifi_obj = SC.WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                             eap_type="TLS", testcase=testcase,
                             wifi_client=wifi_client, net_perf_client=net_perf_client, protocols=protocols,
                             traffic_types=traffic_types)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info(f"Initiating disconnect...")
    # Disconnect
    ble_obj.disconnect()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_disconnect", "clear_certs"])
def test_sta_ble_TCP_UDP_TTLS_C20206(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, ble_client,
                                     net_perf_client):
    testcase = "test_sta_ble_TCP_UDP_TTLS_C20206"
    logger().info("testcase : test_sta_ble_TCP_UDP_TTLS_C20206")
    validation = True
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    traffic_types = ["RX", "TX"]
    logger().info(f"configuring the Sniffer with the channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = SC.BleThread_Connection(wifi_dut, ble_client, mode="ble_master")
    wifi_obj = SC.WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                             eap_type="TTLS", testcase=testcase,
                             wifi_client=wifi_client, net_perf_client=net_perf_client, protocols=protocols,
                             traffic_types=traffic_types)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info(f"Initiating disconnect...")
    # Disconnect
    ble_obj.disconnect()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
