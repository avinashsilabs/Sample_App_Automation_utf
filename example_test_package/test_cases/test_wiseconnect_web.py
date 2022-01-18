from utils.iperf.iperf_utils import ping
import time
import pytest
from devices.rs911x import RS9116TCPIPFeatureBitMap


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer
        }
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "disable_store_config"])
def test_wiseconnect_web(wifi_access_point, wifi_dut, wiseconnect_web, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    # configures the values from harness on given ip address of web page
    wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(web_address=device_ip)

    wifi_dut.interfaces.wifi.reset_soft()
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(10)

    # # Ping to dut from third party device
    status = ping(device_ip, 10)
    logger.info(f"ping status after reset is :: {status}")
    assert status is True, "DUT is not responding to ping request from third party device after store configuration"
    time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "disable_store_config"])
def test_wiseconnect_web_firmware_upgrade(wifi_access_point, wifi_dut, wiseconnect_web, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    # configures the values from harness on given ip address of web page
    wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(web_address=device_ip, firmware_file_path="")

