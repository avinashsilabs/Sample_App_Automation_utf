import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xCertificateType
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.time_measurer import TimeMeasurer
from datetime import datetime, date
from test_sta_ble_sdk import BleThreadFunctionality, SnifferValidationProcess, ScanTime_JoinTime, WifiJoinThread
import re




def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp in EAP mode
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. data transfer

    Author: Swathi.Chinthala

"""


class SnifferValidationEAP(ThreadBase):

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, sniffer_filter=None, sl_collections=None, tcp_ip_bypass=False):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.tcp_ip_bypass = tcp_ip_bypass
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def verify_sniffer_validation_eap(self):
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=self.power_save)

        if not self.tcp_ip_bypass:
            sniff_obj = SnifferValidationProcess(wifi_sniffer=self.wifi_sniffer, wifi_access_point=self.wifi_access_point,
                                                 dut_mac_address=self.dut_mac_address,
                                                 ap_mac_address=self.ap_mac_address, sniffer_filter=self.sniffer_filter,
                                                 sl_collections=self.sl_collections)
            sniff_obj.sniffer_validation_powersave()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
            get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='eap_failure')
        logger().info(f"Validating eap_failure frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                       packet_filter1)['packet_count'], \
            'Sniffer: Unable to find eap_failure packets in sniffer'



class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None,
                 sl_collections=None, test_name=None, eap_type="tls", net_perf_client=None, protocol=None,
                 test_type=None, tcp_ip_bypass=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.eap_type = eap_type
        self.dut_addr = None
        self.device_ip = None
        self.dut_mac_address = None
        self.test_type = test_type
        self.tcp_ip_bypass = tcp_ip_bypass
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def join_to_ap_eap(self):

        logger().info(f"associated state : {self.wifi_dut.interfaces.wifi.associated}")

        if not self.wifi_dut.interfaces.wifi.associated:
            self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            if self.tcp_ip_bypass:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        tcp_ip_bypass=True,
                                                                        retry_count=1)

                self.dut_mac_address = self.dut_addr['dut_mac_address']
                logger().info(
                    f"device_mac : {self.dut_mac_address}")
            else:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        ping_after_power_save=True)

                self.device_ip = self.dut_addr['device_ip']
                self.dut_mac_address = self.dut_addr['dut_mac_address']
                logger().info(
                    f"device_ip, device_mac : {self.device_ip}, {self.dut_mac_address}")

    def run_traffic(self, protocol="TCP", traffic_type="TX"):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=protocol, device_ip=self.device_ip,
                                        host_ip=host_ip, timeout=60, traffic_type=traffic_type)

    def run(self):
        if self.test_type == "ping":
            self.join_to_ap_eap()
            if not self.tcp_ip_bypass:
                status = ping(self.device_ip, 30, size=300)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "throughput":
            self.join_to_ap_eap()
            self.run_traffic(protocol="TCP", traffic_type="TX")
            self.run_traffic(protocol="UDP", traffic_type="TX")
            self.run_traffic(protocol="TCP", traffic_type="RX")
            self.run_traffic(protocol="UDP", traffic_type="RX")




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "eap_cert": ["start_field.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_tls_BLE_adv_C133461(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping")
        wifi_thread.join_to_ap_eap()
        wifi_thread.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_thread.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           )

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable","ble_stop_adv",
                                         "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_ttls_BLE_adv_C133462(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping")
        wifi_thread.join_to_ap_eap()
        wifi_thread.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_thread.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter, sl_collections=sl_collections,)

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable","ble_stop_adv",
                                         "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_peap_BLE_adv_C133463(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap peap method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping")
        wifi_thread.join_to_ap_eap()
        wifi_thread.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_thread.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter, sl_collections=sl_collections,)

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "eap_cert": ["start_field.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_throughput_EAP_TLS_BLE_Central_C133451(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                              request, utf_constants, sl_collections, wifi_client,
                                                              sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on open security
               3. Advertise remote device
               4. Scan from DUT device and connect to Remote device
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="throughput")
        wifi_thread.join_to_ap_eap()
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter, sl_collections=sl_collections)

        sniffer_obj.verify_sniffer_validation_eap()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "eap_cert": ["start_field.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.skip("TCP-RX issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_throughput_EAP_TTLS_BLE_Central_C133452(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                              request, utf_constants, sl_collections, wifi_client,
                                                              sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Configure AP on open security
               3. Advertise remote device
               4. Scan from DUT device and connect to Remote device
               5. Join the access point and enable the dhcp
               6. Enable wlan and bt power save mode in dut after the connection
               7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="throughput")
        wifi_thread.join_to_ap_eap()
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_dut.interfaces.wifi.leave()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter, sl_collections=sl_collections)

        sniffer_obj.verify_sniffer_validation_eap()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "eap_cert": ["start_field.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.skip("TCP bypass unable to get response for commands after connection")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_tls_BLE_adv_tcp_bypass_C133497(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping", tcp_ip_bypass=True)
        wifi_thread.join_to_ap_eap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.skip("TCP bypass unable to get response for commands after connection")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_ttls_BLE_adv_tcp_bypass_C133498(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping", tcp_ip_bypass=True)
        wifi_thread.join_to_ap_eap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.skip("TCP bypass unable to get response for commands after connection")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_coex_WLAN_conn_eap_peap_BLE_adv_tcp_bypass_C133499(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")

        ble_obj.advertise_dut()
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections,
                                     test_name=test_name, test_type="ping", tcp_ip_bypass=True)
        wifi_thread.join_to_ap_eap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv"])
def test_Coex_sdk_all_channels_scan_time_BLE_adv_bypass_C133489(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz in bypass mode
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Wlan Scan in all channels from DUT and calculate time taken to scan in all channels
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan_time"
        all_channel_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     all_channel_2_4=all_channel_2_4)

        ble_obj.advertise_dut()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan", "ble_stop_adv"])
def test_Coex_sdk_sel_chan_scan_time_BLE_slave_bypass_C133490(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz in bypass mode
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Wlan Scan in all channels from DUT and calculate time taken to scan in all channels
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan_time"
        select_channel_2_4 = [1, 6, 11]

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter,
                                     select_channel_2_4=select_channel_2_4)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_scan", "ble_stop_adv"])
def test_Coex_sdk_join_time_WPA2_AES_BLE_ADV_bypass_C133494(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz in bypass mode
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. WLAN scan and connect to AP with PMK and enable power save
               4. Caluculate the time taken to connect to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "join_time"

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                     wifi_access_point=wifi_access_point, testcase=test_name,
                                     wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                     ping_count=ping_count, sniffer_filter=sniffer_filter)
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap(tcp_ip_bypass=True)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,

    }
)
@pytest.mark.skip("PMK connection issue")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable",  "disassociated", "ble_stop_adv", "ble_stop_scan"])
def test_Coex_sdk_join_time_WPA2_PMK_BLE_Adv_bypass_C133496(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                     request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz in bypass mode
               2. Advertise BLE DUT
               3. WLAN scan and connect to AP with PMK and enable power save
               4. Scan from remote BLE device and connect to DUT
               5. Caluculate the time taken to connect to AP
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "join_time"

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan_from_remote_device")
        ble_obj.advertise_dut()

        for i in range(0, iter_count):

            wifi_obj = ScanTime_JoinTime(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                         wifi_access_point=wifi_access_point, testcase=test_name,
                                         wifi_client=wifi_client, test_type=test_type, sl_collections=sl_collections,
                                         ping_count=ping_count, sniffer_filter=sniffer_filter)
            wifi_obj.start()
            ble_obj.start()
            wifi_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            logger().info("Initiating stop scan from Remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            wifi_obj.disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

