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

            time.sleep(2)
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")

            if self.test_case_no == 510702:
                logger().info("performing firmware upgrade....")
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, http_url=self.rps_path, port=443)
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
                self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=host_ip, port=443)
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
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_zephyr_http_fw_upgrade_in_STA_alone_mode_secure_image_and_measure_time_c510697(firmware_loader, http_server,
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.firmware_app("firmware_security_encrypted_1")
def test_zephyr_http_m4_full_security_fw_upgrade_using_c510702(firmware_loader, http_server, wifi_sniffer, wifi_access_point,
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
                            test_case_no=510702)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
