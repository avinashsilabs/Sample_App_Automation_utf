import time
import pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf_wifi_zephyr.devices.si91x import (
    ZephyrWifiMfpOptions
)
from threading import Thread
from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


def ap_switch(switch, ap_turn_off_time, start_delay):
    time.sleep(start_delay)
    logger().info(f"Turn off AP for {ap_turn_off_time} seconds")
    switch.interfaces.pdu_switch.turn_off(delay=1)
    time.sleep(ap_turn_off_time)
    switch.interfaces.pdu_switch.turn_on()
    logger().info("AP is turn on")


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Stop the sniffer  
        6. Analyizing all sniffer capture packets for wpa3 functionality
    setup requirement:
        1. DUT(RS9117)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)

    Author: Vinod G
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None, sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, zephyr_wifi_collections=None,
                 wifi_client=None,
                 traffic_type=None, dut_leave=True, protocol=None, net_perf_client=None, test_case_no=None,
                 power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.device_ip = None
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dut_leave = dut_leave
        self.test_name = test_name
        self.power_save = power_save
        self.ap_mac_address = None

    def run(self):
        try:
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 34503:
                logger().info(f"\n\nscanning for wpa3 Access Point with different combinations of scan\n\n\n")
                scan_dict = [{"ssid": None, "channel": 0},
                             {"ssid": None, "channel": self.wifi_access_point.interfaces.wifi.channel},
                             {"ssid": self.wifi_access_point.interfaces.wifi.ssid,
                              "channel": self.wifi_access_point.interfaces.wifi.channel}]

                for i in range(len(scan_dict)):
                    assert self.wifi_dut.interfaces.wifi.scan(ssid=scan_dict[i]['ssid'],
                                                              channel=scan_dict[i]['channel'])
                    time.sleep(3)

            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              power_save=self.power_save,
                                                                              ping_after_power_save=True,
                                                                              mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED)
            logger().info("DUT successfully connected with AP")
            self.device_ip = self.dut_addr['device_ip']

            if self.test_case_no == 113907:
                return

            if self.test_case_no == 113911 or self.test_case_no == 996239:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                device_ip = self.dut_addr['device_ip']
                logger().info(f"Remote device ip :{host_ip}")
                protocols = ["TCP", "UDP"]
                traffic_types = ["TX", "RX"]
                for protocol in protocols:
                    for traffic_type in traffic_types:
                        self.zephyr_wifi_collections.run_traffic(
                            wifi_dut=self.wifi_dut,
                            net_perf_client=self.net_perf_client,
                            protocol=protocol,
                            device_ip=device_ip,
                            host_ip=host_ip,
                            timeout=35,
                            traffic_type=traffic_type,
                        )

            if self.test_case_no == 113911 or self.test_case_no == 113907 or self.test_case_no == 113912 or self.test_case_no == 996239 or self.test_case_no == 537920 or self.test_case_no == 537921:
                return

            time.sleep(2)
            if self.test_case_no == 996238:
                logger().info("This is rejoin")
            else:
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")

                if self.test_case_no != 113912 or self.test_case_no != 113911 or self.test_case_no != 996239 or self.test_case_no != 537920 or self.test_case_no != 537921:
                    time.sleep(2)
                    packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        wlan_addr=self.dut_addr['dut_mac_address'],
                        filter_name="wpa3_confirm_commit_message")
                    logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

                    packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        wlan_addr=self.dut_addr['dut_mac_address'],
                        filter_name="wpa3_4_way_handshake_message")
                    logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")

                    snif_pkt_count = \
                        self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                            'packet_count']
                    assert snif_pkt_count, "Unable to find the commit & confirm packets."

                    snif_pkt_count = \
                        self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                            'packet_count']
                    assert snif_pkt_count, "Unable to find association & ea pols packets."

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4, async_socket=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip
        self.async_socket = async_socket

    def run_traffic(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=self.async_socket
        )

    def run(self):
        self.run_traffic()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC34503')
def test_wifi_zephyr_scan_wpa3_c34503_04_05_07(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying scan for wpa3 configured access point'''
    logger().info(f"This test case will cover four test cases c34503, c34504, c34505, c34507")
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    wlan_obj = WifiConnectionThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    ping_count=ping_count, test_name=test_name,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    sniffer_filter=sniffer_filter, test_case_no=34503, data_transfer=False,
                                    power_save=power_save)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C34508')
def test_wifi_zephyr_conn_deconn_reconn_wpa3_C34508(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                    sniffer_filter, zephyr_wifi_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection, disconnection and reconnection with WPA3 configured Access Point'''
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    wlan_obj = WifiConnectionThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    ping_count=ping_count, test_name=test_name, sniffer_filter=sniffer_filter,
                                    zephyr_wifi_collections=zephyr_wifi_collections, data_transfer=False,
                                    power_save=power_save)
    try:
        for i in range(0, iter_count):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                            wlan_obj.dut_addr['dut_mac_address'],
                                                            wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C113907')
def test_wifi_zephyr_conn_STA_AP_in_H2E_mode_C113907(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                     sniffer_filter, zephyr_wifi_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        data_transfer=False, test_case_no=113907, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(3)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="wpa3_h2e_mode")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Assoc req with H2E."
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.skip()
@pytest.mark.test_src_map_id('C113909')
def test_wifi_zephyr_DUT_behaviour_rejoin_H2E_C113909(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                      sniffer_filter, switch, zephyr_wifi_collections):
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        ''' Verify Rejoin Functionality in WPA3 Security'''
        state = switch.interfaces.pdu_switch.get_state()
        logger().info("pdu switch state : " + str(state))
        if state == 'true':
            logger().info('PDU is ready for use')
        else:
            logger().info(f'\n\n Please check the AP & PDU current state')
            assert False
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60,
                                      mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")

        wifi_dut.interfaces.wifi.wifi_ps(enabled=1)

        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="wpa3_h2e_mode")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Assoc req with H2E."
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        dut_mac_addr, ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
        if state == 'true':
            logger().info('#### Turn off the Access Point')
            switch.interfaces.pdu_switch.turn_off()
        time.sleep(30)
        logger().info('##### Turn on Access point #####')
        state = switch.interfaces.pdu_switch.get_state()
        logger().info(f"checking status: {state}")
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds to check DUT is rejoined to that AP or not ........")
            time.sleep(60)
        if wifi_dut.interfaces.wifi.associated is True:
            logger().info(f"Initiating ping to DUT ip {device_ip} after successful rejoin")
        status = ping(device_ip, ping_count)
        assert status, "DUT not responding for ping request......"
        if status == 1:
            logger().info('#### Ping successful ####')
        else:
            logger().info('#### Ping unsuccessful ####')
        time.sleep(2)
        logger().info(f"DUT is leaving the Third party AP")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"
    finally:
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"Checking PDU status in finally state, trying to turn on using PDU, Please wait for 60 seconds......")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C113911')
def test_wifi_zephyr_data_transfer_STA_AP_in_H2E_mode_C113911(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              net_perf_client, protocol, request, sniffer_filter,
                                                              wifi_client,
                                                              zephyr_wifi_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                                        net_perf_client=net_perf_client,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        protocol=protocol,
                                        data_transfer=True, traffic_type="TX", test_case_no=113911,
                                        power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(3)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="wpa3_h2e_mode")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Assoc req with H2E."
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2WPA3MixedMode', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C113912')
def test_wifi_zephyr_conn_STA_AP_in_Transition_mode_C113912(wifi_sniffer, wifi_access_point, wifi_dut,
                                                            utf_constants,
                                                            request, sniffer_filter, zephyr_wifi_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        data_transfer=False, test_case_no=113912, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
        time.sleep(3)
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
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2WPA3MixedMode', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C996239')
def test_wifi_zephyr_data_transfer_STA_in_Transition_mode_C996239(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                  utf_constants,
                                                                  wifi_client, net_perf_client, protocol, request,
                                                                  sniffer_filter, zephyr_wifi_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                                        net_perf_client=net_perf_client,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        protocol=protocol,
                                        data_transfer=True, traffic_type="RX", test_case_no=996239,
                                        power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
        time.sleep(3)

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
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C537920')
def test_wifi_zephyr_conn_with_11ax_enabled_C537920(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                    sniffer_filter, zephyr_wifi_collections):
    ''' Verify WPA3 with 11 AX enabled parameter in the AP'''
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"MAC of AP2 is: {ap_bssid}")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        data_transfer=False, test_case_no=537920, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(1)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_bssid,
            filter_name="third_party_ap_ax")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find H2E Packets."
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="adv_he_info")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find advertising H2E Packets."
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="adv_he_in_data_pkt")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter4}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find advertising H2E Packets."
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2WPA3MixedMode', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C537921')
def test_wifi_zephyr_conn_when_ap_in_wpa3_transition_mode_and_11w_capable_only_C537921(wifi_sniffer, wifi_access_point,
                                                                                       wifi_dut, utf_constants,
                                                                                       request, sniffer_filter,
                                                                                       zephyr_wifi_collections):
    ''' Verify WPA3 functionality when third party AP is configured in WPA3 transition mode and
        11W as capable only see the behavior '''
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        data_transfer=False, test_case_no=537921, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(1)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="pmf_bit_enable")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PMF bit enabled packets."
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC966619')
def test_wifi_zephyr_ap_wpa3_security_dut_wpa2_sec_neg_c966619(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                               request,
                                                               sniffer_filter, zephyr_wifi_collections):
    """ This neg test case verifies DUT behavior when trying to connect to WPA3 enabled AP when WPA2 security is selected in DUT"""
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60,
                                      mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED,
                                      custom_security=1,
                                      expected_status=0x0001)
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.skip()
@pytest.mark.test_src_map_id('C996238')
def test_wifi_zephyr_wpa3_security_udp_tx_after_rejoin_successful_c996238(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                         utf_constants, request,
                                                                         sniffer_filter, switch,
                                                                         zephyr_wifi_collections, wifi_client,
                                                                         net_perf_clients):
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        ''' Verify Rejoin Functionality in WPA3 Security'''
        state = switch.interfaces.pdu_switch.get_state()
        logger().info("pdu switch state : " + str(state))
        if state == 'true':
            logger().info('PDU is ready for use')
        else:
            logger().info(f'\n\n Please check the AP & PDU current state')
            assert False
        '''Verifying the scan results with-in the configure time interval of 500 Milli-Seconds '''
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name,
                                        zephyr_wifi_collections=zephyr_wifi_collections,
                                        data_transfer=False, test_case_no=996238, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        device_ip = wlan_obj.device_ip

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=test_name, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4
                                     )

        socket1_thread.start()
        time.sleep(3)

        socket1_thread.wait_for_exit()
        time.sleep(1)

        ap_turn_off_time = 10
        start_delay = 2
        thread = Thread(target=ap_switch, args=(switch, ap_turn_off_time, start_delay), )
        thread.start()

        logger().info("Stop sending data on DUT as rejoin is going, wait for 90 seconds")
        time.sleep(90)
        socket1_thread.start()
        time.sleep(3)

        socket1_thread.wait_for_exit()
        time.sleep(1)

        logger().info(f"DUT is going to leave the Thirdy Party")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'], wlan_obj.ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"
    finally:
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"Checking PDU status in finally state, trying to turn on using PDU, Please wait for 60 seconds ......")
            time.sleep(60)
