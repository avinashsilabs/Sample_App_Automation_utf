from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""This Test plan is validating Firmware version updation through OTAF

        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Stop the sniffer
        6. Compare firmware version

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Ayush Agarwal

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, sl_collections=None, http_server=None, test_case=None, switch=None, wifi_clients=None):
        super().__init__()
        self.host_ip = None
        self.wifi_dut = wifi_dut
        self.time_duration = None
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.switch = switch
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case = test_case
        self.twelve_hour = 43200
        self.clients_connected = True
        self.fw_version_before_upgrade = None
        self.fw_version_after_upgrade = None

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        if self.clients_connected:
            logger().info(f"Disconnecting clients from DUT-AP before associating to DUT-AP")
            for client in wifi_clients:
                client.interfaces.wifi.leave()
            self.clients_connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        self.clients_connected = True
        return ip_dict

    def run(self):
        try:
            with TimeMeasurer() as T:
                status_http = self.http_server.interfaces.http.started
                assert status_http, 'Server is inactive'
                logger().info(f'http server state is {status_http}')

                logger().info(" **** configuring the sniffer with access point channel **** ")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

                if self.test_case != '19762':
                    self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

                if self.test_case != '19762':
                    logger().info("pinging to server ip....")
                    status = ping(self.host_ip, 10)
                    logger().info(f'Ping status = {status}')

                logger().info("dut fw version before upgrade...")
                self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")

                if self.test_case == '19774':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return

                if self.test_case == '19766':
                    self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                                  beacon_missed_count=40,
                                                                                  first_time_retry_enable=0)

                if self.test_case == '19773':
                    with TimeMeasurer() as T:
                        t_end = time.time() + self.twelve_hour
                        while time.time() < t_end:
                            self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
                            logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")
                            logger().info("scanning for ap...")
                            self.wifi_dut.interfaces.wifi.scan()
                            self.wifi_dut.interfaces.wifi.join_ap(access_point=self.wifi_access_point)
                            self.wifi_dut.interfaces.wifi.start_ip()
                            with TimeMeasurer() as t:
                                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                               host_name=self.host_ip)

                            if t.duration > 40:
                                logger().info('*** Firmware upgrade time is more ***')
                            else:
                                logger().info(f'*** Firmware upgrade time = {t.duration}')

                            logger().info(f'*** Firmware upgrade time: {t.duration} ***')
                            self.wifi_dut.interfaces.wifi.reset()
                            time.sleep(15)
                            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                            self.wifi_dut.interfaces.wifi.init(load_certificate=False)
                            self.wifi_dut.interfaces.wifi.initialize_thread()
                            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                            self.fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                            logger().info(f"*** dut fw version after upgrade = {self.fw_version_after_upgrade} ***")
                            assert self.fw_version_before_upgrade != self.fw_version_after_upgrade, \
                                "Firmware after matched with the previous firmware"
                            self.wifi_dut.interfaces.wifi.default_fw = True
                            self.wifi_dut.interfaces.wifi.close()
                            self.wifi_dut.interfaces.wifi.reset()
                            time.sleep(15)
                            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                            self.wifi_dut.interfaces.wifi.init(load_certificate=False)
                            self.wifi_dut.interfaces.wifi.initialize_thread()
                            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                    return

                logger().info("scanning for ap...")
                self.wifi_dut.interfaces.wifi.scan()
                if self.test_case == '19757':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return
                self.wifi_dut.interfaces.wifi.join_ap(access_point=self.wifi_access_point)
                self.dut_addr = self.wifi_dut.interfaces.wifi.start_ip()
                time.sleep(10)

                logger().info("Performing firmware upgrade....")

                if self.test_case == '19772':
                    with TimeMeasurer() as T:
                        t_end = time.time() + self.twelve_hour
                        while time.time() < t_end:
                            with TimeMeasurer() as t:
                                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                               host_name=self.host_ip,
                                                                               http_url='/SiWG917-B.2.10.1.0.0.6_corrupted_add.rps')
                                # expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
                    return

                if self.test_case == '19775':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   http_url='/SiWG917-B.2.9.0.0.20.bin')
                    # expected_status=SLStatus.SL_STATUS_SI91X_WRONG_PACKET_INFO)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return

                if self.test_case == '19776':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   http_url='/RS9116.2.5.0.4_remove.xls',
                                                                   expected_status=SLStatus.SL_STATUS_SI91X_HTTP_OTAF_INVALID_PACKET)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return

                if self.test_case == '19778':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   http_url='/RS9116.2.5.0.4_empty.rps',
                                                                   expected_status=SLStatus.SL_STATUS_SI91X_WRONG_PACKET_INFO)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return

                if self.test_case == '19777':
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip,
                                                                   expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
                    logger().info("stop Sniffer capture...")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return

                if self.test_case == '19762':
                    self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                                   static_subnet="255.255.255.0",
                                                                   static_gateway="192.168.100.76")
                    logger().info(" ********** Starting DUT as an AP ********* ")
                    self.wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148564", security="WPA2", psk="Automation@123",
                                                           channel=11, dtim_beacon_count="1", beacon_interval="100")
                    self.connect_clients_to_dut_as_ap(wifi_clients=self.wifi_clients, wifi_dut=self.wifi_dut)

                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

                if self.test_case == '19766':
                    return

                with TimeMeasurer() as t:
                    self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                                   host_name=self.host_ip, timeout=150)

                if t.duration > 40:
                    logger().info(f'*** Firmware upgrade time is more that is {t.duration} ***')
                else:
                    logger().info(f'*** Firmware upgrade time = {t.duration}')

                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                self.wifi_dut.interfaces.wifi.reset()
                time.sleep(15)
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init(load_certificate=False)
                self.wifi_dut.interfaces.wifi.initialize_thread()
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                self.fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** dut fw version after upgrade = {self.fw_version_after_upgrade} ***")
                assert self.fw_version_before_upgrade != self.fw_version_after_upgrade, \
                    "Firmware after matched with the previous firmware"
            logger().info(f'*** Time required is {T.duration} ***')

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_fw_upgrade_failure_when_sta_is_not_connected_c19757(http_server, wifi_client, wifi_sniffer,
                                                                      wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation when STA is not connected with client"""
    try:
        test_case = '19757'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_in_sta_alone_mode_and_measure_time_c19758(http_server, wifi_client, wifi_sniffer,
                                                                             wifi_access_point, wifi_dut,
                                                                             sl_collections):
    """This Test case is validating Firmware updation in STA Alone mode"""
    try:
        test_case = '19758'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_in_sta_ble_mode_and_measure_time_c19760(http_server, wifi_client, wifi_sniffer,
                                                                           wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation in STA+BLE mode"""
    try:
        test_case = '19760'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_after_rejoin_failure_and_measure_time_c19766(http_server, wifi_client, wifi_sniffer,
                                                                                wifi_access_point, wifi_dut, switch,
                                                                                sl_collections):
    """This Test case is validating Firmware updation after rejoin failure"""
    try:
        test_case = '19766'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer, switch=switch,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case, sl_collections=sl_collections)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_https_fw_upgrade_failure_when_enabled_ble_only_c19774(http_server, wifi_client, wifi_sniffer,
                                                                        wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure with ble only mode"""
    try:
        test_case = '19774'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_https_fw_upgrade_failure_with_junk_rps_c19775(http_server, wifi_client, wifi_sniffer,
                                                                wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure with junk rps"""
    try:
        test_case = '19775'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_https_fw_upgrade_failure_with_non_rps_c19776(http_server, wifi_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure with non rps"""
    try:
        test_case = '19776'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_https_fw_upgrade_failure_without_enabling_http_c19777(http_server, wifi_client, wifi_sniffer,
                                                                        wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure without enabling http-otaf"""
    try:
        test_case = '19777'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
def test_wifi_sdk_https_fw_upgrade_failure_with_empty_rps_c19778(http_server, wifi_client, wifi_sniffer,
                                                                 wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure with empty rps"""
    try:
        test_case = '19778'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_downgrade_success_with_text_format_overnight_c19773(http_server, wifi_client,
                                                                                       wifi_sniffer, wifi_access_point,
                                                                                       wifi_dut, sl_collections):
    """This Test case is validating Firmware updation with non-rps file, i.e., text file"""
    try:
        test_case = '19773'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_downgrade_overnight_c19771(http_server, wifi_client, wifi_sniffer,
                                                              wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation overnight"""
    try:
        test_case = '19773'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_failure_with_junk_rps_overnight_c19772(http_server, wifi_client, wifi_sniffer,
                                                                          wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware updation failure with junk rps overnight"""
    try:
        test_case = '19772'
        wlan_obj = WifiJoin(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148564",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0"
        }
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.wifi_clients(["raspi_wifi"])
def test_wifi_sdk_https_fw_upgrade_in_concurrent_mode_and_measure_time_c19762(http_server, wifi_client, wifi_sniffer,
                                                                              wifi_access_point, wifi_dut, wifi_clients,
                                                                              sl_collections):
    """This Test case is validating Firmware updation in Concurrent mode"""
    try:
        test_case = '19762'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            wifi_clients=wifi_clients, wifi_client=wifi_client)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
