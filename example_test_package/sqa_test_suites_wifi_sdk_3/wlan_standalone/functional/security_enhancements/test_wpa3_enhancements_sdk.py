import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 enhancements
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None, sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, wifi_client=None,
                 traffic_type=None, dut_leave=True, protocol=None, net_perf_client=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name
        self.dut_mac_addr = None


    def run(self):
        try:
            if self.test_case_no == 113909 or self.test_case_no == 113916:
                logger().info(f"Rejoin Test_case")
            else:
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 113911 or self.test_case_no == 113913:
                transfer_type = 2
                protocol = 17
                throughput_type = 2
                size = 1470

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
            self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
            self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                          security="wpa3_transition",
                                          passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                          channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            time.sleep(5)
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
            time.sleep(2)
            device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")
            time.sleep(2)
            mode = 'power_save_low_latency'
            dtim_aligned_type = 0
            num_of_dtim_skip = 0
            listen_interval = 0
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip,
                                                             listen_interval)
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            time.sleep(2)
            status = ping(device_ip, self.ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")
            time.sleep(2)
            if self.test_case_no == 113911 or self.test_case_no == 113913:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                protocols = ["TCP", "UDP"]
                traffic_types = ["TX", "RX"]
                for protocol in protocols:
                    for traffic_type in traffic_types:
                        self.sl_collections.run_traffic(
                            wifi_dut=self.wifi_dut,
                            net_perf_client=self.net_perf_client,
                            protocol=protocol,
                            device_ip=device_ip,
                            host_ip=host_ip,
                            timeout=35,
                            traffic_type=traffic_type,
                        )

            if self.test_case_no == 113909 or self.test_case_no == 113916:
                logger().info(f"Rejoin Test_case")
            else:
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")
                time.sleep(2)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

class Wlan_Conn_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None, sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, wifi_client=None,
                 dut_leave=True, protocol=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name
        self.dut_mac_addr = None

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
            self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
            self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                          security="wpa3_transition",
                                          passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                          channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            time.sleep(5)
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
            time.sleep(2)
            device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")
            time.sleep(2)
            status = ping(device_ip, self.ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            time.sleep(2)
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_STA_AP_in_H2E_mode_C113907(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
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
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_STA_AP_in_Transition_mode_C113912(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                         request, sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(3)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_DUT_behaviour_rejoin_H2E_C113909(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                   sniffer_filter, switch, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
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
        time.sleep(2)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security="wpa3_transition",
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        mode = 'power_save_low_latency'
        dtim_aligned_type = 0
        num_of_dtim_skip = 0
        listen_interval = 0
        wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip,
                                                         listen_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"
    finally:
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"Checking PDU status in finally state, trying to turn on using PDU, Please wait for 60 seconds......")
            time.sleep(60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_thpt_STA_AP_in_H2E_mode_C113911(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                  net_perf_client, protocol, request, sniffer_filter, wifi_client,
                                                  sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections, protocol=protocol,
                                        data_transfer=True, traffic_type="TX", test_case_no=113911)
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
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_data_transfer_STA_in_Transition_mode_C113913(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                               wifi_client, net_perf_client, protocol, request,
                                                               sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections, protocol=protocol,
                                        data_transfer=True, traffic_type="RX", test_case_no=113913)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(3)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_with_ax_enabled_C537920(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections):
    ''' Verify WPA3 with 11 AX enabled parameter in the AP'''
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"MAC of AP2 is: {ap_bssid}")
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
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
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2WPA3MixedMode', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_when_ap_in_wpa3_mixed_mode_C537921(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                          request, sniffer_filter, sl_collections):
    ''' Verify WPA3 functionality when third party AP is configured in WPA3 mixed mode and
        11W as capable only see the behavior '''
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
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
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA3',
                                               "protected_management_frame": "Capable", 'channel': 11})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features":  Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_with_conc_mode_with_bec_C463705(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections, wifi_client):
    ''' Verify WLAN Connectivity to STAUT with WPA3 Security in Concurrent Mode when APUT is Beaconing'''
    try:
        ssid = "Concurent_ap"
        security = "wpa3_transition"
        password = "Automation@Silabs"
        channel = "11"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval,
                                          ht_caps=ht_caps)
        time.sleep(2)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        time.sleep(2)
        wlan_obj = Wlan_Conn_Thread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="concurrent_wpa3")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA3',
                                               "protected_management_frame": "Capable", 'channel': 11})
@pytest.mark.config(
    "wifi_client",
    wifi={
                "security": "OPEN",
                "ssid": "Concurent_ap",
                "channel": 11,
                "interface": "wlan0",
         }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features":  Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_with_conc_mode_with_open_mode_C463712(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections, wifi_client):
    ''' Verify connectivity of STAUT with WPA3 security to 3rd party AP and 3rd party STA connectivity
    with OPEN Security to APUT'''
    try:
        ssid = "Concurent_ap"
        security = "Open"
        channel = "11"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval,
                                          ht_caps=ht_caps)
        time.sleep(2)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_mac_address}**********")
        wifi_client.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.Open)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(10)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        wlan_obj = Wlan_Conn_Thread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA3',
                                               "protected_management_frame": "Capable", 'channel': 11})
@pytest.mark.config(
    "wifi_client",
    wifi={
                "security": "WPA2",
                "ssid": "Concurent_ap",
                "passphrase": "Automation@Silabs",
                "channel": 11,
                "interface": "wlan0",
         }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features":  Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_with_conc_mode_with_wpa2_mode_C463709(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections, wifi_client):
    ''' Verify connectivity of STAUT with WPA3 security to 3rd party AP and 3rd party STA connectivity
    with WPA2 Security to APUT'''
    try:
        ssid = "Concurent_ap"
        security = "WPA2"
        password = "Automation@Silabs"
        channel = "11"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval,
                                          ht_caps=ht_caps)
        time.sleep(2)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_mac_address}**********")
        wifi_client.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(10)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        wlan_obj = Wlan_Conn_Thread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()