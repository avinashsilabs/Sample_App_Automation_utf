import re
import time
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
from test_wlan_data_rates_sdk import SocketDataTransfer
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
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
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Enable Background scan
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Expectation of this test case is to verify different parameters of Background scan functionalities. 
        8. Validate Probe response & HT information, BG scan on primary, non US & DFS channel etc. via sniffer with
           different mode/channels 

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vivek Verma
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None, 
                 ping_count=None, data_transfer=True, test_name=None, sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.dut_addr = None
        self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                             time_period=self.time_period, data=self.data)

    def run(self):
        try:
            if self.test_case_no == 19035:
                """ Enabling BG scan """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)
            if self.test_case_no == 19037:
                """ Need to add instant BGscan """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20,
                                                                              adv_enable_instant_scan=1)

            if self.test_case_no == 19038:
                """ Rejoin infinite retry """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)

                # Rejoin
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)

            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     ping_after_power_save=False)
            logger().info("DUT successfully connected with AP")
            time.sleep(2)

            logger().info("\n *** Enable BGscan *** \n")
            self.wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

            if self.data_transfer:
                self.socket_obj.socket_data_transfer()

            time.sleep(2)
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_bgscan_c19035(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sniffer_filter,
                                sl_collections):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    '''Verify RSI_STA connectivity by enabling BG scan in 2.4Ghz band'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19035,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'

        '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
        wlan_obj_retry = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    time_period=time_period, sl_collections=sl_collections)
        wlan_obj_retry.start()
        wlan_obj_retry.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_instant_bgscan_c19037(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                        sl_collections, sniffer_filter):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    '''Verify RSI_STA connectivity by enabling instant BG scan'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19037, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'

        '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
        wlan_obj_retry = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    time_period=time_period, sl_collections=sl_collections)
        wlan_obj_retry.start()
        wlan_obj_retry.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_bgscan_rejoin_infinite_retry_c19038(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                      sl_collections, sniffer_filter):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    '''Re-join with infinite retry when bgscan enable. Module should rejoin. If not module should attempt infinitely.
       If it successfully rejoin to AP bgscan should happen. '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19038,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
          "oper_mode": Si91xOperatingMode.WiFiClient,
          "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
          "features": Si91xFeatureBitMap.Default,
          "custom_features": Si91xCustomFeatureBitMap.Default,
          "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
          "bt_features": 0,
          "ble_features": 0,
          "ble_custom_ext_features": 0,
          },
)
def test_wifi_sdk_bgscan_primary_channel_2g_c19039(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                   sl_collections, sniffer_filter, request):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    channel_bitmap_2_4 = 0
    data_transfer = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period)

    '''configure the channels 1,6,11 in channel_bitmap field and verify whether the BG scan is happening in those 
       particular channels only or not'''
    channel_list = [1, 6, 11]
    try:
        for channel in channel_list:
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(20)
            logger().info(f"Channel = {channel}")
            channel_bitmap_2_4 += 1 << (channel - 1)
            logger().info(f"channel bitmap = {channel_bitmap_2_4}")

            wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                     adv_passive_channel_time=20)

            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           ping_after_power_save=False)
            logger().info("DUT successfully connected with AP")

            wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10, scan_bitmap_2_4=channel_bitmap_2_4)
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_addr['dut_mac_address'],
                filter_name="probe_request")

            logger().info(f"\n\nCreate socket and start data transfer *****\n\n")
            data_transfer.socket_obj.socket_data_transfer()

            time.sleep(1)
            wifi_dut.interfaces.wifi.leave()

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find probe request broadcast packet'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
