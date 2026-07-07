import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase

"""This Test plan is validating Firmware version upgrade through AWS/Azure HTTP OTAF

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
        5. AWS server
        6. Azure server

    Author: SHOBHA RANI JOGU

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, zephyr_wifi_collections=None,
                 test_case=None, url=None, url1=None, aws_s3=None, azure_blob=None, rps_path=None, url_len=None):
        super().__init__()
        self.host_ip = None
        self.wifi_dut = wifi_dut
        self.time_duration = None
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_case = test_case
        self.fw_version_before_upgrade = None
        self.fw_version_after_upgrade = None
        self.url = url
        self.url1 = url1
        self.aws_s3 = aws_s3
        self.azure_blob = azure_blob
        self.presigned_aws_host_name = "httpotaf.s3.amazonaws.com"
        self.aws_host_name = "httpotaf.s3.us-east-2.amazonaws.com"
        self.transfer_accelerate_aws_host_name = "httpotaf.s3-accelerate.amazonaws.com"
        self.azure_host_name = "httpotaf.blob.core.windows.net"
        self.rps_path = rps_path
        self.long_url = None
        self.url_len = url_len
        self.new_url = None
        self.dut_addr = None
        self.dut_mac_address = None

    def fw_download_from_aws_server(self, aws_s3, rps_path):

        rps_path = rps_path.replace('/', '')
        logger().info(f"******firmware file name uploading to aws server {rps_path}*********")

        rps_path_final = "/app/manifest/" + rps_path
        status = aws_s3.interfaces.s3.upload_file(rps_path_final, "httpotaf", "rps_path")
        assert status is True, f"unable to upload"
        logger().info(f"upload successful")
        url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", "rps_path")
        logger().info(f"aws url is :{url}")
        return url

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(45)
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
            logger().info(" **** Configuring the sniffer with access point channel **** ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ====== Start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)
            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")
            logger().info("Downloading firmware from AWS server...")
            self.url = self.fw_download_from_aws_server(aws_s3=self.aws_s3, rps_path=self.rps_path)
            logger().info(f"Firmware URL obtained: {self.url}")
            logger().info("join WIFI network...")
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                              retry_count=3,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              power_save=False)

            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")
            self.wifi_dut.interfaces.wifi.wifi_http_otaf_upgrade(ip_address=self.aws_host_name, port=443,
                                                                 http_url="/rps_path", timeout=900)
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
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
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
def test_wifi_sdk_https_fw_upgrade_using_aws_server_c510698(firmware_loader, aws_s3, wifi_sniffer, wifi_access_point,
                                                            wifi_dut, zephyr_wifi_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server.
    Uses combined_cert.pem so the DUT trusts the current AWS S3 TLS chain (avoids SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED).
    """
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '510698'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, zephyr_wifi_collections=zephyr_wifi_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
