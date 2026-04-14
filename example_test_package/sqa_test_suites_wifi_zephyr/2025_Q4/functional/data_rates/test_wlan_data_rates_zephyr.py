import time
from retry import retry
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger

from utf.utils.stopwatch import Stopwatch
from utf_wifi_zephyr.interfaces.zephyr_wifi_test_agent_cli import SLWifiCLI
from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : bgnax
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Ping from remote peer
        5. Validate all management packets in 1 Mbps data rates.
        6. Verification of EAPOL packets for 1 Mbps data rates
        7. Verification of Basic data rates for Association req & Probe response

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vinod.G
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
            time.sleep(5)
            logger().error(f"\n\n Trying to connect with server ")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id, timeout=30)

            if self.data_transfer:
                sw = Stopwatch()
                while sw.elapsed_sec < self.time_period:
                    send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=self.data,
                                                                             timeout=120)
                    if isinstance(send_bytes, str):
                        logger().info(f"Send {send_bytes} bytes successfully")
                    else:
                        logger().info(f"Data transfer failed")

            time.sleep(5)
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id, timeout=30)

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
                 , ping_count=None, data_transfer=True, test_name=None, zephyr_wifi_collections=None, data_rates=None,
                 power_save=None):
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
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.data_rates = data_rates
        self.power_save = power_save
        self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                             time_period=self.time_period, data=self.data)

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              retry_count=3, power_save=self.power_save,
                                                                              ping_after_power_save=True
                                                                              )
            logger().info("DUT successfully connected with AP")
            time.sleep(10)
            if self.data_transfer:
                self.socket_obj.socket_data_transfer()

            time.sleep(2)
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C19622')
def test_wifi_zephyr_mgmt_data_rates_c19622(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                            sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for Management packets, Verify for following management packets,Assoc req,Assoc resp.Reassoc 
    req,Re assoc resp,Probe req,Prob res'''
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          zephyr_wifi_collections=zephyr_wifi_collections, data_transfer=False, power_save=power_save)
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
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
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C19623')
def test_wifi_zephyr_mgmt_data_rates_rts_cts_c19623(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                    sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    '''Data rates used for Control packets, Verify for following Control packets,Block ACK Req,(Qos)Block Ack(Qos)
       Ps-PollRTSCTSACK'''
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_mac_address}')
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          zephyr_wifi_collections=zephyr_wifi_collections, data_transfer=False, power_save=power_save)
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
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
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C19624')
def test_wifi_zephyr_data_rates_for_data_packet_c19624(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request,
                                                       sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    '''Data rates used for Data packets, Verify for following Data packets,Data.Null Data and Qos Null data.Qos Data'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          zephyr_wifi_collections=zephyr_wifi_collections, data_transfer=False, power_save=power_save)
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
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
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C19631')
def test_wifi_zephyr_data_rates_eapol_c19631(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    '''Data rates used for EAPOL key exchanges and GTK key renewal exchanges with auto rate'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          test_case_no=19628, zephyr_wifi_collections=zephyr_wifi_collections, data_transfer=False,
                          power_save=power_save)
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
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
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C19634')
def test_wifi_zephyr_basic_data_rates_c19634(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    '''Verify data rates in Assoc Req, is same as data rates present in probe Resp of connected AP or not'''
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, ping_count=ping_count, test_name=test_name,
                          zephyr_wifi_collections=zephyr_wifi_collections, test_case_no=19634, data_transfer=False,
                          power_save=power_save)
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
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
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
