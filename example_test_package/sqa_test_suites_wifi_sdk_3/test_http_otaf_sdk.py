from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode
import time
import pytest
import datetime
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer
        8. Validating Add-ba request from AP/DUT
        9. Validating Add-ba response from AP/DUT 

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vishakha
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, sl_collections=None, http_server=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case_no = test_case_no

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.host_reset()
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        self.wifi_dut.interfaces.wifi.associated = False
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.inited = False
        return fw_after_upgrade

    def run(self):
        try:
            """ ******* SERVER CHECKS ******* """
            logger().info("checking server stats....")
            server_stat = self.http_server.interfaces.http.started
            assert server_stat == True, "server is inactive"
            logger().info(f'http server state is {server_stat}')
            logger().info("fetching server ip....")
            host_ip = self.http_server.interfaces.http.hostname_or_ip_address
            logger().info(f"server ip is {host_ip}")

            logger().info("pinging to server ip....")
            status = ping(host_ip, 10)
            assert status == 1, "failed to ping to server"
            if self.test_case_no == 19779:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Performing firmware upgrade....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x10021, "observed wrong error code expected is 0x10021"
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            logger().info("dut fw version before upgrade...")
            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")
            logger().info("join WIFI network...")
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=False)
            time.sleep(2)
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")

            if self.test_case_no == 19796:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6.bin",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x10021, "observed wrong error code expected is 0x10021"
                self.get_firmware_status()

            if self.test_case_no == 19795:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut non rps ...")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/cgi-bin/cgi_example.py", host_ip)
                    time.sleep(100)
                assert exc_info.value.error_code == 0x1FFFD, "observed wrong error code expected is 0x1FFFD"
                self.get_firmware_status()

            if self.test_case_no == 19800:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut with empty rps file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_empty.rps",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x1FFF9, "observed wrong error code expected is 0xFFF9"
                self.get_firmware_status()

            if self.test_case_no == 19794:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut with empty rps file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.0.0.6_corrupted_remove.rps",
                                                                   host_ip)
                    time.sleep(100)
                assert exc_info.value.error_code == 0x1FFFD, "observed wrong error code expected is 0x1FFFD"

                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by adding some content to  rps....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_corrupted_add.rps",
                                                                   host_ip)
                    time.sleep(100)
                assert exc_info.value.error_code == 0xBB41, "observed wrong error code expected is 0xBB41"
                self.get_firmware_status()

            if self.test_case_no == 19798:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by removing data in .xls file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_empty.xls",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x1FFFD, "observed wrong error code expected is 0x1FFFD"

                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by removing data in .xls file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_empty.txt",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x1FFFD, "observed wrong error code expected is 0x1FFFD"

                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by removing data in .xls file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_empty.docx",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x1FFFD, "observed wrong error code expected is 0x1FFFD"

            if self.test_case_no == 19797:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by adding data in .xls file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6_add.xls",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0xBB41, "observed wrong error code expected is 0xBB41"
                self.get_firmware_status()

            if self.test_case_no == 19799:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut by using .bin file....")
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6.bin",
                                                                   host_ip)
                    time.sleep(120)
                assert exc_info.value.error_code == 0x1FF74, "observed wrong error code expected is 0x1FF74"
                time.sleep(3)
                self.get_firmware_status()

            else:
                logger().info("performing firmware upgrade....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6.rps", host_ip)
                time.sleep(120)
                finish_time = time.time()
                logger().info(f"firmware upgraded : {finish_time}")
                time_duration = (finish_time - start_time)
                logger().info(f"Time taken to upgrade firmware is: {time_duration}")

                if time_duration > 40:
                    logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
                else:
                    logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
                fw_after_upgrade = self.get_firmware_status()
                time.sleep(2)
                logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                              f" firmware version after loading through otaf :{fw_after_upgrade}")
                assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                              f" firmware through otaf"
                logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(10)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_sdk_http_fw_upgrade_in_STA_alone_mode_and_measure_time_C19780(http_server, wifi_sniffer, wifi_access_point,
                                                                       wifi_dut, request, wifi_client, sl_collections,
                                                                       sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename,
                            sl_collections=sl_collections, http_server=http_server)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_sdk_http_fw_upgrade_in_STA_BLE_mode_and_measure_time_C19782(http_server, wifi_sniffer, wifi_access_point,
                                                                     wifi_dut, request, wifi_client, sl_collections,
                                                                     sniffer_filter):
    capture_filename = request.node.name
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"host ip is {host_ip}")
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
def test_sdk_http_fw_upgrade_failure_with_empty_rps_C19800(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                           request, wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19800)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
def test_sdk_http_fw_upgrade_failure_without_enabling_http_C19799(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                                  request, wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19799)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
def test_sdk_fw_upgrade_failure_when_STA_is_not_connected_C19779(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                                 request, wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19779)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_http_fw_upgrade_failure_with_non_rps_C19798(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19798)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_http_fw_upgrade_failure_with_junk_rps_C19797(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19797)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
def test_sdk_http_fw_upgrade_failure_when_enabled_only_ble_C19796(http_server, wifi_sniffer, wifi_access_point,
                                                                  wifi_dut,
                                                                  request, wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19796)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_http_fw_upgrade_over_night_C19793(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter,utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19793)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_http_fw_upgrade_over_night_corrupted_file_C19794(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter, utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19794)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_http_fw_upgrade_over_night_corrupted_file_C19795(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter, utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19795)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "channel": 11}
)
@pytest.mark.config(
    "wifi_client",
    wifi={"interface": "wlan0", "security": "WPA2", "ssid": "TEST_C19784", "passphrase": "Automation@123",
          "channel": 11}
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_http_fw_upgrade_in_conc_mode_and_measure_time_C19784(http_server, wifi_sniffer, wifi_dut, wifi_access_point,
                                                              request, sl_collections, wifi_client, utf_constants,
                                                              sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        logger().info("dut fw version before upgrade...")
        fw_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

        logger().info("join WIFI network...")
        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, retry_count=3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C19784", security="WPA2", psk="Automation@123",
                                          channel=11, dtim_beacon_count="1", beacon_interval="100")
        logger().info("joining 3rd party client to DUT ap")
        wifi_client.interfaces.wifi.config['interface'] = "wlan0"
        wifi_client.interfaces.wifi.join()

        logger().info("fetching gateway ip of ap")
        device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
        ping_iterations = 10
        logger().info("fetching ip address of 3rd party sta")
        wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
        status = ping(wifi_client_ip, ping_iterations)
        assert status == 1
        logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
        logger().info("wifi client ip: " + str(wifi_client_ip))
        time.sleep(2)

        """ ******* SERVER CHECKS ******* """
        logger().info("checking server stats....")
        server_stat = http_server.interfaces.http.started
        if not server_stat:
            http_server.interfaces.http.start_server()
        logger().info(f'http server state is {server_stat}')
        logger().info("fetching server ip....")
        host_ip = http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"server ip is {host_ip}")

        start_time = time.time()
        logger().info(f" start firmware upgrade: {start_time}")
        logger().info("performing firmware upgrade....")
        wifi_dut.interfaces.wifi.firmware_upgrade(0, host_ip, 80, "/SiWG917-B.2.10.1.0.0.6.rps", host_ip)
        time.sleep(100)
        finish_time = time.time()
        logger().info(f"firmware upgraded : {finish_time}")
        time_duration = (finish_time - start_time)
        logger().info(f"Time taken to upgrade firmware is: {time_duration}")

        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")

        wifi_dut.interfaces.wifi.host_reset()
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init()
        time.sleep(5)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        wifi_dut.interfaces.wifi.associated = False
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_after_upgrade}")
        assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                      f" firmware through otaf"
        logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
        wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)