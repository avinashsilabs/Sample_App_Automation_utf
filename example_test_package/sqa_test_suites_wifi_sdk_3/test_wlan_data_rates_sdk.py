import re
import time
from retry import retry
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
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
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Validate all management packets in 1 Mbps data rates.
        8. Configure data rates at on 11/12/54 Mbps and check the data rate in sniffer.
        9. Verification of EAPOL packets for 1 Mbps data rates
        10. Verification of Basic data rates for Association req & Probe response

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vivek Verma
"""


class SocketDataTransfer:
    def __init__(self, wifi_dut=None, dut_ip=None, time_period=None, data=None, data_transfer=True, switch=None,
                 wifi_access_point=None):
        self.wifi_dut = wifi_dut
        self.dut_ip = dut_ip
        self.time_period = time_period
        self.data = data
        self.data_transfer = data_transfer
        self.switch = switch
        self.socket_id = None
        self.wifi_access_point = wifi_access_point

    def socket_data_transfer(self):
        if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
            self.socket_id = self.wifi_dut.interfaces.wifi.socket(timeout=15)
            if isinstance(self.socket_id, int):
                logger().info(f"Socket open successfully : {self.socket_id}")
            else:
                logger().error(f"Unable to open socket id: {self.socket_id}")
                raise RuntimeError(self.socket_id)

            logger().error(f"\n\n Socket bind in DUT for socket-id: {self.socket_id}")
            self.wifi_dut.interfaces.wifi.bind(socket_fd=self.socket_id, device_ip=self.dut_ip, timeout=15)
            logger().error(f"\n\n Trying to connect with server ")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id, timeout=30)

            if self.data_transfer:
                sw = Stopwatch()
                while sw.elapsed_sec < self.time_period:
                    send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=self.data, timeout=120)
                    if isinstance(send_bytes, str):
                        logger().info(f"Send {send_bytes} bytes successfully")
                    else:
                        logger().info(f"Data transfer failed")

            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)

    def verify_data_rates(self):
        packet_filter = '    Data rate:'
        data_rates_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for find_filter in line:
            if packet_filter in find_filter:
                data_rates = find_filter.split(':')[1].strip().split(' ')[0].split('.')[0]
                data_rates_list.append(data_rates)

        filter_file.close()
        return max(set(data_rates_list), key=data_rates_list.count)

    @retry(Exception, delay=15, tries=5)
    def ping_to_dut(self, ping_count=10):
        status = ping(self.dut_ip, ping_count)
        assert status, "Failed to ping to DUT"
        return status


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None
                 , ping_count=None, data_transfer=True, test_name=None, sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                             time_period=self.time_period, data=self.data)

    def run(self):
        try:
            if self.test_case_no == 19625:
                """ set data rate in b(11Mbps) mode and Verify """
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11b", data_rate="11Mbps",
                                                                expected_status=SLStatus.SL_STATUS_OK)
            if self.test_case_no == 19626:
                """ set data rate in g mode(54 Mbps) and Verify """
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11g", data_rate="12Mbps",
                                                                expected_status=SLStatus.SL_STATUS_OK)

            if self.test_case_no == 19627:
                """ set data rate in n mode """
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="14.4Mbps",
                                                                expected_status=SLStatus.SL_STATUS_OK)

            if self.test_case_no == 19628:
                """ set data rate in 12 Mbps """
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11g", data_rate="12Mbps",
                                                                expected_status=SLStatus.SL_STATUS_OK)

            if self.test_case_no == 19631:
                """ set data rate in Auto mode """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=150,
                                                                              scan_interval=4,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="auto", data_rate="auto")

            if self.test_case_no == 19634:
                """ set data rate in Auto mode """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                              scan_interval=4,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="auto", data_rate="auto")

            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     , ping_after_power_save=False)
            logger().info("DUT successfully connected with AP")
            time.sleep(10)
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
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mgmt_data_rates_c19622(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for Management packets, Verify for following management packets,Assoc req,Assoc resp.Reassoc 
    req,Re assoc resp,Probe req,Prob res'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(f"\n\n\n DUT MAC Address = {wlan_obj.dut_addr['dut_mac_address']}\n\n")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='mgmt_data_rates_1_mbps')

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth mgmt packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mgmt_data_rates_rts_cts_c19623(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for Control packets, Verify for following Control packets,Block ACK Req,(Qos)Block Ack(Qos)
       Ps-PollRTSCTSACK'''
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_mac_address}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        """Verification of Block ack req/res, RTS/CTS mgmt packets data rates"""
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_block_ack_req_rts_1mbps')
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                                        filter_name='mgmt_data_rates_block_ack_res_cts_1mbps')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(1)
        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)
        if result1 is False or result2 is False:
            logger().info(
                f"Expected packet validation failed, Block Ack req/RTS = {result1}, Block Ack res/CTS = {result2}")
            assert False
        else:
            logger().info(
                f"Block Ack req/RTS = {result1}, Block Ack res/CTS = {result2}")
            logger().info("Sniffer validation Passed")
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_data_packet_c19624(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                    sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for Data packets, Verify for following Data packets,Data.Null Data and Qos Null data.Qos Data'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        """Verification of Data/Null/Qos packets data rates"""
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_data_null_Qos_1mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Data/Null/Qos packets data rates'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_b_mode_c19625(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Set data rate to 11b rates, and verify all following packets with all data rates Assoc Req,Assoc Resp.ReAssoc
    Req,Re Assoc Resp.Probe Req,Probe RespBeacon.DisAssoc.'''
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_mac_address}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19625, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_data_null_Qos_11mbps')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        radio_ch=wifi_access_point.
                                                                                        interfaces.wifi.channel,
                                                                                        filter_name='mgmt_data_rates_assoc_reassoc_probe_req_res_1mbps')
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packets for Data/Qos/Null packet for 11 Mbps dat rates'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find packets for Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 ' \
            'Mbps ' \
            'data rates'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_g_mode_c19626(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Set data rate to 11g rates, and verify all following packets with all data ratesAssoc Req,Assoc Resp.ReAssoc
       Req,Re Assoc RespProbe Req,Probe Resp'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19626, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_data_null_Qos_12mbps')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_assoc_reassoc_probe_req_res_1mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packets for Data/Qos/Null packet for 54 Mbps dat rates'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find packets for Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 ' \
            'Mbps data rates'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_n_mode_c19627(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Set data rate to 11n rates,and verify all following packets with all data ratesAssoc Req,Assoc RespReAssoc
       Req,Re Assoc RespProbe Req,Probe RespBeaconDisAssoc'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19627, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_probe_auth_Assoc_req_eapol_deauth_1mbps')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='radio_mcs_index_1')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth frame'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find the MCS rate 4 in data packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_data_packets_12mbps_c19628(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                            request, sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Set Fixed data rate to 12Mbps and verify which data rate is using for 4GHz .DataNull Data and Qos Null dataQos
       Data'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19628, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_data_null_Qos_12mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packet for Data/Null/Qos packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_for_rts_cts_12mbps_c19629(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request, sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Set Fixed data rate to 12Mbps and verify which data rate is using for 2.4GHz .Block ACK Req,(Qos)Block Ack(Qos)
       Ps-Poll, RTS, CTS, ACK'''
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19628, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_data_rates_block_ack_req_rts_12mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets for Block ACK Req, RTS for data rates 12 Mbps'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_eapol_c19631(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                          sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for EAPOL key exchanges and GTK key renewal exchanges with auto rate'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19628, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        """Verification of EAPOL packets for 1 Mbps data rates"""
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='mgmt_data_rates_eapol_1mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets for EAPOL packets for 1 Mbps data rates'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | 
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_basic_data_rates_c19634(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                          sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Verify data rates in Assoc Req, is same as data rates present in probe Resp of connected AP or not'''
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections, test_case_no=19634)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        """Verification of Basic data rates for Association req & Probe response"""
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_basic_data_rates_assoc_req')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_basic_data_rates_probe_res')

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='mgmt_basic_data_rates_probe_req')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n\n *** Stop Sniffer finally ***\n\n")
        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)
        result3 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)

        if result1['packet_count'] is False or result2['packet_count'] is False or result3['packet_count'] is False:
            logger().info(
                f"Expected packet validation failed, Assoc req = {result1}, Probe req = {result3}, Probe res = {result2}")
            assert False
        else:
            logger().info(
                f"Assoc req = {result1['packet_count']}, Probe res = {result2['packet_count']}, Probe req = {result3['packet_count']}")
            logger().info("Sniffer validation Passed")
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_data_rates_with_diff_rssi_values_c19630(wifi_sniffer, wifi_access_point, wifi_dut, rf_attenuator,
                                                          utf_constants, request, sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    set_rssi = 0
    packet_filter6 = '    Data Rate:'

    '''Verify data rate functionality of STA DUT using AUTO RATE as data rate with AP OPEN mode'''
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)
    logger().info(f'\n\n{scan_results[0]}\n')
    my_str = str(scan_results[0])
    current_rssi = abs(int(my_str.strip('()').split(' ')[5]))
    logger().info(f'Current RSSI = {current_rssi}')
    logger().info(f'Make RSSI -35 for ideal condition')
    if current_rssi < 35:
        set_rssi = 35 - current_rssi
    elif current_rssi > 35:
        set_rssi = current_rssi - 35
    elif current_rssi == 35:
        set_rssi = 35

    logger().info(f'SET RSSI value = {set_rssi}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                          ping_count=ping_count, test_name=test_name, test_case_no=19622)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='probe_request')
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid,
            filter_name='association_request')
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid,
                                                                                        da_addr=wlan_obj.dut_addr[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='association_response')
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid,
            filter_name='power_mgmt_bit')
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'],
            ra_addr=ap_bssid,
            filter_name='data_packets')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast probe request packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find Association req packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find Association response packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find Power save mode with pmt bit 1'

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            db_value = 10
            att_channel = 1
            attenuation_data_rates_dict = dict()

            file_name = 'attenuation_' + str(db_value)
            logger().info('***** Set the attenuator *****')
            # ideal_rssi = set_rssi + current_rssi
            # set_db_value = int(ideal_rssi) + db_value
            ideal_rssi = 10
            set_db_value = int(ideal_rssi) + db_value
            logger().info(f'\n\n Set the ideal RSSI = {ideal_rssi}\n')
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, ideal_rssi)

            while sw.elapsed_sec < time_period:

                time.sleep(10)

                wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
                logger().info(f'current time = {sw.elapsed_sec}, end time = {time_period}')
                send_response = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=data)
                logger().info(f'SEND-RESPONSE = {send_response}')

                logger().info(f'\n\n set_db_value = {set_db_value}\n')
                wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, set_db_value)
                time.sleep(10)
                sw1 = Stopwatch()
                while sw1.elapsed_sec < 30:
                    logger().info(f'\n\n current time = {sw.elapsed_sec}\n')
                    send_response = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=data)
                    logger().info(f'\n\n SEND-RESPONSE = {send_response}\n')
                wifi_sniffer.interfaces.capture.stop_capture()

                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5,
                                                                          packet_filter2=packet_filter6)['packet_count'], \
                    'Unable to find data packets'

                attenuation_data_rates_dict[eval('set_db_value')] = tcp_socket_obj.verify_data_rates()
                logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
                set_db_value = set_db_value + 10

            logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
