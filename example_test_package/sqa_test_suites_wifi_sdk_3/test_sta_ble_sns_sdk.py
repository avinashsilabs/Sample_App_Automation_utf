import pytest
import time
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer


def logger():
    return get_logger(__name__)


"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set advertise, scan & connect

    Author: Saurabh Sharma
"""


class WifiJoinThread(ThreadBase):

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None,
                 sl_collections=None, sniffer_filter=None):

        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_addr = None
        self.ap_mac_address = None

    def run(self):
        try:
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     ping_after_power_save=True, retry_count=3)
            logger().info(f"******** AP MAC ADD *******")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP MAC ADDRESS : {self.ap_mac_address}')

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name="probe_request")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=self.ap_mac_address, sa_addr=self.dut_addr['dut_mac_address'], filter_name="association_request")

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address, da_addr=self.dut_addr['dut_mac_address'], filter_name="association_response")

        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=self.ap_mac_address, sa_addr=self.dut_addr['dut_mac_address'], filter_name="qos_data_more_data")

        packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name="ps_poll")

        logger().info(f"***** Validating packets for probe request  ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe request"

        logger().info(f"***** Validating packets for association request  ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association request"

        logger().info(f"***** Validating packets for association response  ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association response"

        logger().info(f"***** Validating packets for Qos data packet with more data bit  ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Qos data packet with more data bit"

        logger().info(f"***** Validating packets for PS Poll  ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS Poll"


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, ble_scan_type=1,
                 ble_pairing=0, ble_scan_filter_type=0, ble_scan_interval=256, ble_scan_window=80, ble_public_address=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.ble_scan_filter_type = ble_scan_filter_type
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.ble_public_address = ble_public_address

        """ *************************** Set up DUT for BLE advertising ***************************** """

        logger().info("Initialising BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert self.ble_dut_address, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

    def run(self):
        if self.ble_test_type == "slave":
            self.sl_collections.ble_connection(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                               ble_dut_address=self.ble_dut_address, timeout=20)

        if self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.advertise_remote_device(wifi_dut=self.wifi_dut,
                                                                                  ble_client=self.ble_client,
                                                                                  ble_dut_address=self.ble_dut_address)
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_address=self.ble_client_address,
                                                             ble_scan_type=self.ble_scan_type,
                                                             ble_scan_filter_type=self.ble_scan_filter_type,
                                                             ble_scan_interval=self.ble_scan_interval,
                                                             ble_scan_window=self.ble_scan_window,
                                                             ble_public_address=self.ble_public_address,
                                                             ble_client_address=self.ble_client_address,
                                                             timeout=30)
            logger().info("*************** BLE scanning is successful****************")

        if self.ble_test_type == "advertise":
            logger().info("Initiating scan from Remote device")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut_address)
            assert ble_client_address, "Unable to fetch bluetooth address from Remote device"
            logger().info(f"Started scan from remote BLE device")
            logger().info("\n***********{}**********\n".format(ble_client_address))
            found_devices = []
            for i in range(0, 3):
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                logger().info("\n***scan results:{}**********\n".format(found_devices))
                time.sleep(5)
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
            logger().info(f"DUT BLE address:'{self.ble_dut_address}' found in raspi scan results")
            self.ble_client.interfaces.bluetooth.close()
            return ble_client_address

    def advertise_dut(self):
        logger().info(f"****** Advertising the DUT *******")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_from_remote_device(self):
        bt_client_address = self.sl_collections.scan_from_remote_device(wifi_dut=self.wifi_dut,
                                                                        ble_client=self.ble_client,
                                                                        ble_dut_address=self.ble_dut_address)
        logger().info(f'bt_client_address is : {bt_client_address}')

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           disconnect_from=disconnect_from,
                                           ble_client_address=self.ble_client_address)

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,

        },
    )
]


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "unassociated", "ble_stop_adv", "ble_stop_scan"])
def test_wifi_sdk_wlan_connect_disconnect_reconnect_and_Ble_adv_C148543(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, wifi_client, sniffer_filter):

    """Run wlan connect ,disconnect ,reconnect and Ble advertising test for 5 minutes"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise")
        ble_obj.advertise_dut()

        with TimeMeasurer() as T:
            t_end = time.time() + 10 * 30
            while time.time() < t_end:
                wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                          wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)
                wifi_obj.start()
                wifi_obj.wait_for_exit()
                wifi_obj.disconnect()
                ble_obj.scan_from_remote_device()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        logger().info(
            f'**** Total execution time for wlan connect_disconnect_reconnect and ble_adv = {T.duration} ****')

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "unassociated", "ble_stop_adv", "ble_stop_scan"])
def test_wifi_sdk_wlan_connect_disconnect_reconnect_and_Ble_conn_C148544(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, wifi_client, sniffer_filter):

    """Run wlan connect ,disconnect ,reconnect and Ble connection test for 30 minutes"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="slave")
        ble_obj.start()
        ble_obj.wait_for_exit()

        with TimeMeasurer() as T:
            t_end = time.time() + 60 * 30
            while time.time() < t_end:
                wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                          wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)
                wifi_obj.start()
                wifi_obj.wait_for_exit()
                wifi_obj.disconnect()

        wifi_dut.interfaces.wifi.ble_get_device_state()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        logger().info(
            f'**** Total execution time for wlan connect_disconnect_reconnect and ble_adv = {T.duration} ****')

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "unassociated", "ble_stop_adv", "ble_stop_scan"])
def test_wifi_sdk_wlan_connect_disconnect_reconnect_and_ble_scanning_C148547(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, wifi_client, sniffer_filter):

    """Run wlan connect ,disconnect ,reconnect and Ble scanning test for 5 minutes"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="master")
        ble_obj.start()

        time.sleep(5)
        with TimeMeasurer() as T:
            t_end = time.time() + 10 * 30
            while time.time() < t_end:
                wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                          wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)
                wifi_obj.start()
                wifi_obj.wait_for_exit()
                wifi_obj.disconnect()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        logger().info(
            f'**** Total execution time for wlan connect_disconnect_reconnect and ble_adv = {T.duration} ****')

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_wifi_sdk_ble_adv_20ms_and_wlan_scanning_C148545(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client):
    """Run ble advertising with 20ms and wlan scanning test for 30 minutes"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {ap_mac_address}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise")

        logger().info(f"Advertising the DUT")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=int(20 / 0.625), ble_adv_int_max=int(20 / 0.625),
                                                       timeout=20)

        with TimeMeasurer() as T:
            t_end = time.time() + 60 * 30
            while time.time() < t_end:
                logger().info(f"Initiating Scan")
                scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0, sleep_time=0.01)
                logger().info(scan_results)
                assert len(scan_results) > 0, "scan failed"
                if ap_mac_address.lower() in str(scan_results):
                    logger().info(f"found ap bssid in scan_results {ap_mac_address}")
                else:
                    assert False, "Unable to find ap in scan results"
                ble_obj.start()
                ble_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        logger().info(
            f'**** Total execution time for wlan connect_disconnect_reconnect and ble_adv = {T.duration} ****')
        ble_obj.stop_adv_scan()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        filter_name="probe_request")
        logger().info(f"***** Validating packets for probe request  ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe request"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
