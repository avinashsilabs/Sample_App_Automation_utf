from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band, RS9116FeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap
import time
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping ,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1}
)
@pytest.mark.firmware_app("test_concurrent_mode")
def test_concurrent_mode(firmware_loader, wifi_access_point, wifi_dut, wifi_client, protocol, logger):
    #preparing wifi_dut as STA - STA Mode
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)

    logger.info("DUT Station Mode")
    logger.info("dut station mode ip: " + device_ip_dut_as_client)
    logger.info("access point ip: " + str(acces_point_ip))

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip_dut_as_client) < 0.1

    #preparing wifi_dut as access point - AP Mode
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip_dut_as_ap) < 0.1
    logger.info("DUT AP Mode")
    logger.info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger.info("wifi client ip: " + str(wifi_client_ip))