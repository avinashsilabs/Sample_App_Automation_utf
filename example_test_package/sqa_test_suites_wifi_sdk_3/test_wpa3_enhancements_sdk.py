import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
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
            if self.data_transfer:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                if self.traffic_type == "TX":
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                    protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=device_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(3)
                if self.traffic_type == "RX":
                    # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        device_ip, protocol=self.protocol, bandwidth=bandwidth)
                    else:
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)

                    self.net_perf_client.interfaces.net_perf.start()

                    logger().info("receiving data from Host")
                    # open socket and listen for data
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        local_ip=self.device_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2)
                    logger().info("data received is successful")
                    time.sleep(3)
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
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
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
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
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


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        1: {
             'ssid': 'OPEN',
             'security': 'Open',
             'channel': 1,
        },
        0: {
             'ssid': 'WPA3-SSID',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
def test_wifi_sdk_behaviour_of_DUT_when_AP_without_H2E_C113910(wifi_sniffer, wifi_access_points, wifi_dut,
                                                               utf_constants, request, sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_points[0].interfaces.wifi.ssid,
        security="wpa3_transition",
        passphrase=wifi_access_points[0].interfaces.wifi.passphrase, channel=wifi_access_points[0].interfaces.wifi.channel, timeout=60)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        mode = 'power_save_low_latency'
        dtim_aligned_type = 0
        num_of_dtim_skip = 0
        listen_interval = 0
        wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip, listen_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"DUT is going to leave the 3rd party Access Point")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (wlan_addr=dut_mac_addr, filter_name="wpa3_confirm_commit_message")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (wlan_addr=dut_mac_addr, filter_name="wpa3_4_way_handshake_message")
        assert snif_pkt_count, "Unable to find commit & confirm packets."
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association & ea pols packets."

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        1: {
             'ssid': 'OPEN',
             'security': 'Open',
             'channel': 11,
        },
        0: {
             'ssid': 'WPA3-SSID',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 11,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
def test_wifi_sdk_DUT_reconnection_hunting_pecking_C113908(wifi_sniffer, wifi_access_points, wifi_dut,
                                                               utf_constants, request, sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        for count in range(0, utf_constants.get("iter_count")):
            wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)# | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)

            time.sleep(2)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_points[0].interfaces.wifi.ssid,
                                          security="wpa3_transition",
                                          passphrase=wifi_access_points[0].interfaces.wifi.passphrase,
                                          channel=wifi_access_points[0].interfaces.wifi.channel, timeout=60)
            time.sleep(2)
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
            time.sleep(2)
            device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")
            time.sleep(2)
            mode = 'power_save_low_latency'
            dtim_aligned_type = 0
            num_of_dtim_skip = 0
            listen_interval = 0
            wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip, listen_interval)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            time.sleep(2)
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            time.sleep(1)
            wifi_access_points[0].interfaces.wifi.stop_ap()
            time.sleep(10)
            wifi_access_points[0].interfaces.wifi.start_ap()
            logger().info("Dut going to leave the AP")
            time.sleep(60)
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info("Dut going to leave the AP")
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (wlan_addr=dut_mac_addr, filter_name="wpa3_confirm_commit_message")
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (wlan_addr=dut_mac_addr, filter_name="wpa3_4_way_handshake_message")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find commit & confirm packets."
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association & ea pols packets."

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        1: {
             'ssid': 'WPA3-TR',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        },
        0: {
             'ssid': 'WPA3-TR',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
def test_wifi_sdk_DUT_rejoin_AP1_H2E_AP2_hunting_pecking_C113916(wifi_sniffer, wifi_access_points, wifi_dut,
                                                               utf_constants, request, sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        logger().info("Turning OFF AP[1]")
        wifi_access_points[1].interfaces.wifi.stop_ap()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)  # | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_points[0].interfaces.wifi.ssid,
                                      security="wpa3_transition",
                                      passphrase=wifi_access_points[0].interfaces.wifi.passphrase,
                                      channel=0, timeout=60)
        time.sleep(2)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        mode = 'power_save_low_latency'
        dtim_aligned_type = 0
        num_of_dtim_skip = 0
        listen_interval = 0
        wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip, listen_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        time.sleep(2)
        logger().info("Turning OFF AP")
        wifi_access_points[0].interfaces.wifi.stop_ap()
        time.sleep(30)
        logger().info("Turning ON AP")
        wifi_access_points[0].interfaces.wifi.start_ap()
        time.sleep(2)
        wifi_access_points[1].interfaces.wifi.start_ap()
        time.sleep(30)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_addr,
            filter_name="wpa3_h2e_mode")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Assoc req with H2E."
        time.sleep(3)
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info("Dut going to leave the AP")

        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        ap_bssid = wifi_access_points[0].interfaces.wifi.bssid
        logger().info(f"MAC of AP2 is: {ap_bssid}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=ap_bssid, filter_name="wpa3_enh_mode")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find commit & confirm packets."

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
