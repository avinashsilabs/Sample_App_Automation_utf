from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.iperf.iperf_utils import ping
import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116TCPIPFeatureBitMap

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
def test_wiseconnect_web_firmware_upgrade(wifi_dut, wifi_access_point, wiseconnect_web, logger):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path='/app/test_package/RS9116W.2.4.1.17.rps', upgrade_wait_time=300)
    logger.info(f"upgraded message: {alert_msg}")
    wifi_dut.reset()
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Upgraded version: {upgraded_version}")
