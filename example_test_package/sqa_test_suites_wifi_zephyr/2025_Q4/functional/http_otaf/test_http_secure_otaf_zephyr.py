from utf.utils import print_dict
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf_wifi_zephyr.utils.sl_status import SLStatus
from threading import Thread
from utf_wifi_zephyr.devices.si91x import Si91xBSDSocketParams

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

    Author: Vinod
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def close_socket(wifi_dut, wait_time, socket_id):
    logger().info(f"wait for {wait_time} before closing the socket")
    time.sleep(wait_time)
    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, zephyr_wifi_collections=None, http_server=None,
                 test_case_no=None,
                 rps_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case_no = test_case_no
        self.rps_path = rps_path

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init()
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
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
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            logger().info("dut fw version before upgrade...")
            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

            logger().info("join WIFI network...")
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                              retry_count=3,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              power_save=False)
            if self.test_case_no == 12348:
                return
            time.sleep(2)
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")

            if self.test_case_no == 19800:
                logger().info("performing fw upgrade on dut with empty rps file....")

                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                     http_url="/SiWG917-B.2.10.1.0.0.6_empty.rps",
                                                                     expected_status=SLStatus.SL_STATUS_TIMEOUT)

                return

            if self.test_case_no == 19797:
                logger().info("performing fw upgrade on dut by using corrupted rps file add lines at end ....")
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                     http_url='/SiWG917-B.2.13.3.0.0.5_corrupt_add.rps',
                                                                     expected_status=SLStatus.SL_STATUS_TIMEOUT)

                # time.sleep(5)
                # self.get_firmware_status()
                # logger().info("join WIFI network...")
                # self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                #                                                                   retry_count=3,
                #                                                                   associated=self.wifi_dut.interfaces.wifi.associated,
                #                                                                   power_save=False)
                # logger().info("performing fw upgrade on dut by using corrupted rps file  remove lines at end ....")
                # self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip, port=80,
                #                                                http_url='/SiWG917-B.2.13.3.0.0.5_corrupt_remove.rps',
                #                                                expected_status=SLStatus.SL_STATUS_SI91X_HTTP_OTAF_INVALID_PACKET)

                # logger().info("stop Sniffer capture...")
                # self.wifi_sniffer.interfaces.capture.stop_capture()
                # self.get_firmware_status()
                return

            if self.test_case_no == 19798:
                logger().info("performing fw upgrade on dut by using excel xls file....")
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                     http_url='/excel_file.xlsx',
                                                                     expected_status=SLStatus.SL_STATUS_TIMEOUT)
                # time.sleep(5)
                # self.get_firmware_status()
                #
                # logger().info("stop Sniffer capture...")
                # self.wifi_sniffer.interfaces.capture.stop_capture()
                # self.get_firmware_status()
                return
            if self.test_case_no == 12345:
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                     http_url='/invalid_firmware_zephyr.rps',
                                                                     expected_status=SLStatus.SL_STATUS_FAIL)
                # time.sleep(5)
                # self.get_firmware_status()
                #
                # logger().info("stop Sniffer capture...")
                # self.wifi_sniffer.interfaces.capture.stop_capture()
                # self.get_firmware_status()
                return
            if self.test_case_no == 12347:
                logger().info("performing firmware upgrade....")
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, http_url=self.rps_path,
                                                                     expected_status=SLStatus.SL_STATUS_TIMEOUT)
                # logger().info("Stop Sniffer finally")
                # self.wifi_sniffer.interfaces.capture.stop_capture()
                # self.wifi_dut.interfaces.wifi.reset()
                return

            if self.test_case_no == 498660:
                logger().info("performing firmware upgrade....")
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, http_url=self.rps_path)
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                self.wifi_dut.interfaces.wifi.reset()
                time.sleep(30)
                logger().info("Initialising DUT after the reset....")
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init()
                self.wifi_dut.interfaces.wifi.initialize_thread()
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                test_message = self.wifi_dut.interfaces.wifi.wifi_test_application()
                assert test_message == "test application working", "The new application upgraded using OTAF is not working"
                self.wifi_dut.interfaces.wifi.inited = False
                return

            else:
                if self.test_case_no == 29780:
                    logger().info(f"Put device to idle state for 10 minutes")
                    time.sleep(60 * 10)
                logger().info("performing firmware upgrade....")
                if self.rps_path:
                    if self.test_case_no == 12346:
                        wait_time = 20
                        socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                                         stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                                         protocol=Si91xBSDSocketParams.IPPROTO_TCP)
                        thread = Thread(target=close_socket, args=(self.wifi_dut, wait_time, socket_id + 1), )
                        thread.start()
                        self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                             expected_status=SLStatus.SL_STATUS_TIMEOUT)
                        return
                    self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80,
                                                                         http_url=self.rps_path)
                else:
                    self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80)
                finish_time = time.time()
                logger().info(f"firmware upgraded : {finish_time}")
                time_duration = (finish_time - start_time)
                logger().info(f"Time taken to upgrade firmware is: {time_duration}")

                if time_duration > 40:
                    logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
                else:
                    logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
                logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                fw_after_upgrade = self.get_firmware_status()
                time.sleep(2)
                logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                              f" firmware version after loading through otaf :{fw_after_upgrade}")
                assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                              f" firmware through otaf"
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.test_src_map_id('C19780')
def test_zephyr_http_fw_upgrade_in_STA_alone_mode_secure_image_and_measure_time_c19780(firmware_loader, http_server,
                                                                                       wifi_sniffer,
                                                                                       wifi_access_point,
                                                                                       wifi_dut, request, wifi_client,
                                                                                       zephyr_wifi_collections,
                                                                                       sniffer_filter,
                                                                                       utf_constants):
    capture_filename = request.node.name
    try:
        rps_path = utf_constants.get("rps_filename")
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename,
                            zephyr_wifi_collections=zephyr_wifi_collections, http_server=http_server, rps_path=rps_path)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.test_src_map_id('C498660')
def test_zephyr_http_m4_full_security_fw_upgrade_using_c498660(http_server, wifi_sniffer, wifi_access_point,
                                                               wifi_dut, request, wifi_client, zephyr_wifi_collections,
                                                               utf_constants):
    ''' Verify M4 firmware update functionality using HTTP otaf (port 80)with local apache server  '''
    capture_filename = request.node.name
    try:
        rps_path = utf_constants.get("m4_full_secure_rps_filename")
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, rps_path=rps_path,
                            zephyr_wifi_collections=zephyr_wifi_collections, http_server=http_server,
                            test_case_no=498660)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.test_src_map_id('C19780')
def test_zephyr_http_otaf_neg_load_mic_only_image_when_full_sec_enabled_c19780(firmware_loader, http_server,
                                                                               wifi_sniffer,
                                                                               wifi_access_point,
                                                                               wifi_dut, request, wifi_client,
                                                                               zephyr_wifi_collections,
                                                                               sniffer_filter,
                                                                               utf_constants):
    capture_filename = request.node.name
    try:
        rps_mic_only_filename = utf_constants.get("rps_mic_only_filename")
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename,
                            zephyr_wifi_collections=zephyr_wifi_collections,
                            http_server=http_server, test_case_no=12347, rps_path=rps_mic_only_filename)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.reset()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.reset()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.test_src_map_id('C19780')
def test_zephyr_non_secure_http_fw_upgrade_stress_c19780(firmware_loader, http_server,
                                                         wifi_sniffer,
                                                         wifi_access_point,
                                                         wifi_dut, request, wifi_client,
                                                         zephyr_wifi_collections,
                                                         sniffer_filter,
                                                         utf_constants):
    capture_filename = request.node.name
    try:
        rps_path = utf_constants.get("rps_filename")
        rps_path_secondary = utf_constants.get("rps_filename_alternative")
        http_iter_count = utf_constants.get("http_otaf_long_run_duration")
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        for count in range(0, http_iter_count):
            logger().info(f"Running the test case for {count} time")
            for test_count in range(0, 2):
                wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    wifi_client=wifi_client, capture_filename=capture_filename,
                                    zephyr_wifi_collections=zephyr_wifi_collections, http_server=http_server,
                                    test_case_no=12348)
                wifi_obj.start()
                wifi_obj.wait_for_exit()
                wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.start_capture(
                    capture_file=f"{capture_filename + str(http_iter_count)}.pcap")
                logger().info("dut fw version before upgrade...")
                start_time = time.time()
                fw_before_upgrade = wifi_dut.interfaces.wifi.version()
                logger().info(f" start firmware upgrade: {start_time}")
                if test_count == 0:
                    firmware_rps_file = rps_path
                else:
                    firmware_rps_file = rps_path_secondary
                wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=80, http_url=firmware_rps_file)
                finish_time = time.time()
                logger().info(f"firmware upgraded : {finish_time}")
                time_duration = (finish_time - start_time)
                logger().info(f"Time taken to upgrade firmware is: {time_duration}")

                if time_duration > 40:
                    logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
                else:
                    logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
                logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
                logger().info("Stop Sniffer finally")
                wifi_sniffer.interfaces.capture.stop_capture()
                fw_after_upgrade = wifi_obj.get_firmware_status()
                time.sleep(2)
                logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                              f" firmware version after loading through otaf :{fw_after_upgrade}")
                assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                              f" firmware through otaf"


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
