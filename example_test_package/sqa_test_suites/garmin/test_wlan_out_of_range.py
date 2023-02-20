import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, SocketOptions, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap
import time
from typing import Dict
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from datetime import datetime
import uuid

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN by enabling HTTP server feature in the DUT
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Turn off the Third party AP
        5. Turn on the Third party AP
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def shut_down_method(wifi_dut, switch):
    logger().info("\n\n ----------------------------Cleaning UP the DUT ----------------------------")
    try:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        logger().info("Closing all opened sockets")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
    except:
        logger().info("******* Recovering the DUT  **********")
        wifi_dut.interfaces.wifi.reset()
    logger().info("\n ----------------------------Cleaning UP of DUT is Completed ----------------------------")


class adaptive_ping(ThreadBase):
    def __init__(self, device_ip):
        super().__init__()
        self.device_ip = device_ip

    def run(self):
        logger().info(f'\n\n Ping traffic is going on for 90 sec ........Please wait\n')
        ping(self.device_ip, 90)


class AccessPointApOnOff(ThreadBase):
    def __init__(self, switch):
        super().__init__()
        self.switch = switch

    def run(self):
        time.sleep(15)
        logger().info('\n\n******* Turn off Access point **********\n')
        self.switch.interfaces.pdu_switch.turn_off(5)
        logger().info('\n\n******* Wait for 90 second after turn on the AP radio **********\n')
        time.sleep(2)
        logger().info('\n\n ******* Turn off the AP radio **********\n')
        self.switch.interfaces.pdu_switch.turn_on(delay=70)


class Wlan_data_transfer_rx(ThreadBase):
    def __init__(self, host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout, net_perf_client=None,
                 protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.host_ip = host_ip
        self.device_ip = device_ip
        self.rs_helper = rs_helper
        self.timeout = timeout
        # self.traffic_type = traffic_type

    def run(self):
        self.rs_helper.run_traffic(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip,
                                   self.timeout, traffic_type="RX")


class Wlan_data_transfer_tx(ThreadBase):
    def __init__(self, host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout, net_perf_client=None,
                 protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.host_ip = host_ip
        self.device_ip = device_ip
        self.rs_helper = rs_helper
        self.timeout = timeout

    def run(self):
        self.rs_helper.run_traffic(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip,
                                   self.timeout, traffic_type="TX")


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    }
)
def test_join_ap_on_off_C21278(switch, rs_helper, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):

    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_ap_on_off_C21276')
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info('\n####====>>>>> Turn off Access point ####====>>>>>')
        switch.interfaces.pdu_switch.turn_off(delay=5)
        time.sleep(2)
        logger().info('\n####====>>>>> Turn on Access point ####====>>>>>')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('####====>>>>> Initiating DUT Recovery using Reset ####====>>>>>')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        shut_down_method(wifi_dut, switch)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    }
)
def test_join_ap_on_off_adaptive_ping_C21282(switch, rs_helper, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):

    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_ap_on_off_adaptive_ping_C21282')
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)

        adp_ping = adaptive_ping(device_ip)
        ap_onoff = AccessPointApOnOff(switch)
        adp_ping.start()
        ap_onoff.start()
        adp_ping.wait_for_exit()
        ap_onoff.wait_for_exit()

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('####====>>>>> Initiating DUT Recovery using Reset ####====>>>>>')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        shut_down_method( wifi_dut, switch )


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_TCP_TX_data_transfer_while_ap_on_off_C21279(switch, net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                                        wifi_client, rs_helper, utf_constants):
    try:
        capture_filename = "test_TCP_TX_data_transfer_while_ap_on_off_C21279"
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.set_tx_wait_time(tx_wait_time=120000)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        timeout = 120
        protocol = IperfConstants.TCP
        wlan_traffic_tx = Wlan_data_transfer_tx(host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout,
                                                net_perf_client, protocol)
        ap_onoff = AccessPointApOnOff(switch)
        wlan_traffic_tx.start()
        ap_onoff.start()
        wlan_traffic_tx.wait_for_exit()
        ap_onoff.wait_for_exit()
        time.sleep(5)
        # Disconnect the AP
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('####====>>>>> Initiating DUT Recovery using Reset ####====>>>>>')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        shut_down_method(wifi_dut, switch)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_UDP_TX_data_transfer_while_ap_on_off_C21280(switch, net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                                        wifi_client, rs_helper, utf_constants):
    try:
        capture_filename = "test_UDP_TX_data_transfer_while_ap_on_off_C21280"
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        wifi_dut.interfaces.wifi.set_tx_wait_time(tx_wait_time=120000)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        timeout = 120
        protocol = IperfConstants.UDP
        wlan_traffic_tx = Wlan_data_transfer_tx(host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout,
                                                net_perf_client, protocol)
        ap_onoff = AccessPointApOnOff(switch)
        wlan_traffic_tx.start()
        ap_onoff.start()
        wlan_traffic_tx.wait_for_exit()
        ap_onoff.wait_for_exit()
        time.sleep(5)
        # Disconnect the AP
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('####====>>>>> Initiating DUT Recovery using Reset ####====>>>>>')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        shut_down_method(wifi_dut, switch)








