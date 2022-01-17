from utils.iperf.iperf_utils import ping
import time
import pytest
from devices.rs911x import RS9116OperatingMode, RS9116TCPIPFeatureBitMap
from pathlib import Path

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "disable_store_config"])
def test_store_config(wifi_access_point, wifi_dut, wiseconnect_web):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(web_address=device_ip)

    wifi_dut.interfaces.wifi.reset_soft()
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(10)

    # # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device after store configuration"
    time.sleep(5)

