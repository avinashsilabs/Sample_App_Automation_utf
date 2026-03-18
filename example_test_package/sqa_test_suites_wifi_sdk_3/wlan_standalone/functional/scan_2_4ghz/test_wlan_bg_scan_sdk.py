import re
import time
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf import UtfDatabaseProperties
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.tcp_udp.test_wlan_data_rates_sdk \
    import SocketDataTransfer
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
from utf.interfaces.iperf.iperf_constants import IperfConstants


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
                 ping_count=None, data_transfer=True, test_name=None, sl_collections=None, switch=None, wifi_client=None, net_perf_client=None,
                 protocol=None, sniffer_filter=None, rejoin_time=None):
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
        self.switch = switch
        self.socket_id = None
        self.dut_addr = None
        self.rejoin_time = rejoin_time
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
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
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     ping_after_power_save=False, retry_count=3)
            logger().info("DUT successfully connected with AP")
            time.sleep(2)

            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            logger().info("\n *** Enable BGscan *** \n")
            self.wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

            if self.data_transfer:
                self.socket_obj.socket_data_transfer()

            if not self.test_case_no ==19038:
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def infinite_data_recovery_in_rejoin(self, option_name=None, option_val=None, bsdSetSocketOpt=True,
                                         data_transfer=False):

        """ This method is responsible to validate socket data transfer recovery after Max TCP retransmission option """
        if data_transfer:
            end_time = 300
            if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
                try:
                    self.socket_id = self.wifi_dut.interfaces.wifi.socket(timeout=15)
                    if isinstance(self.socket_id, int):
                        logger().info(f"Socket open successfully : {self.socket_id}")
                    else:
                        logger().error(f"Unable to open socket id: {self.socket_id}")
                        raise RuntimeError(self.socket_id)

                    if bsdSetSocketOpt:
                        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=self.socket_id, option_name=option_name,
                                                                      option_val=option_val)

                    logger().info(f"\nSocket bind in DUT for socket-id: {self.socket_id}")
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=self.socket_id, device_ip=self.dut_addr['device_ip'],
                                                       timeout=15)
                    logger().info(f"\nTrying to connect with server ")
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id, timeout=60)

                    logger().info(f"\n **** Start validation of socket data transfer in rejoin scenario with AP turn "
                                  f"off &"
                                  f"Turn on again ****\n")

                    sw = Stopwatch()
                    check_flag = False
                    while sw.elapsed_sec < end_time:
                        send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id,
                                                                                 data=self.data,
                                                                                 timeout=120)
                        logger().info(f'SEND-Bytes = {send_bytes}')
                        time.sleep(1)
                        while sw.elapsed_sec < 20:
                            send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id,
                                                                                     data=self.data,
                                                                                     timeout=120)
                            logger().info(f'SEND-Bytes = {send_bytes}')

                        if check_flag is not True:
                            logger().info('***** Turn off Access point *****')
                            self.switch.interfaces.pdu_switch.turn_off(delay=10)
                            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                                sa_addr=self.dut_addr['dut_mac_address'],
                                filter_name="probe_request")
                            logger().info("\n\n Adding sleep for 20 sec \n")
                            time.sleep(20)
                            self.wifi_sniffer.interfaces.capture.stop_capture()
                            assert \
                            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                                'packet_count'], \
                                'Unable to find Broadcast Probe request packet'

                            # start sniffer before turn on acess point
                            logger().info("\n\n *** Start sniffer configuration before turn on AP *** \n\n")
                            self.wifi_sniffer.interfaces.capture.configure_interface(
                                channel=self.wifi_access_point.interfaces.wifi.channel)
                            logger().info("Start sniffer capture")
                            self.wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_event_start")

                            logger().info(f'******* Turn on Access point with delay {self.rejoin_time} **********')
                            self.switch.interfaces.pdu_switch.turn_on(delay=self.rejoin_time)
                            check_flag = True
                            logger().info('******* Trying to reconnect DUT and resume data transfer **********')
                            # Initiate ping from third party wifi-client to DUT
                            logger().info(f"\n\n *** Initiating ping from third party wifi-client to DUT after turn "
                                          f"on the AP *** \n\n")
                            logger().info(f"DUT IP address: {self.dut_addr['device_ip']}")

                            status = ping(self.dut_addr['device_ip'], 20)
                            assert status, "Failed to ping to DUT"
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)
                except Exception as e:
                    logger().error(f"An error occurred: {str(e)}")
                    raise
            else:
                logger().error("Invalid WiFi DUT interface. Expected SLWifiCLI")
                raise RuntimeError("Invalid WiFi DUT interface")
        self.wifi_sniffer.interfaces.capture.stop_capture()


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.legacy_deployed
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.legacy_deployed
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


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "eth1"
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_bgscan_rejoin_infinite_retry_c19038(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                      sl_collections, sniffer_filter, switch, net_perf_client, protocol, wifi_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    rejoin_time = utf_constants.get("rejoin_time")

    '''Re-join with infinite retry when bgscan enable. Module should rejoin. If not module should attempt infinitely.
       If it successfully rejoin to AP bgscan should happen. '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19038, sl_collections=sl_collections, switch=switch, data_transfer=False,
                          protocol=protocol, net_perf_client=net_perf_client,wifi_client=wifi_client,
                          sniffer_filter=sniffer_filter, rejoin_time=rejoin_time)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_rejoin_us_region")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        wlan_obj.infinite_data_recovery_in_rejoin(option_name='SO_MAX_RETRANSMISSION_TIMEOUT_VALUE',
                                              option_val='128',
                                              data_transfer=True)
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


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
          "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
          "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
          "bt_features": 0,
          "ble_features": 0,
          "ble_custom_ext_features": 0,
          },
)
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
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

            dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           ping_after_power_save=False, retry_count=3)
            logger().info("DUT successfully connected with AP")

            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(1)
            wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10, scan_bitmap_2_4=channel_bitmap_2_4)
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_addr['dut_mac_address'],
                filter_name="probe_request")

            logger().info(f"\n\nCreate socket and start data transfer *****\n\n")
            data_transfer.socket_obj.socket_data_transfer()
            wifi_dut.interfaces.wifi.leave()

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find probe request broadcast packet'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
