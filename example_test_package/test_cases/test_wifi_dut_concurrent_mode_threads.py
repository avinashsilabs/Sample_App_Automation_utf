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

# preparing wifi_client for tcp server using iperf for DUT as STA
class DUTSTAThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_client, net_perf_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client

    def run(self):
        # preparing wifi_dut
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(vap_id=1)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        acces_point_ip = self.wifi_dut.interfaces.wifi.ip.gateway
        self.wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)

        logger().info("Running DUT in Station Mode")
        logger().info("dut station mode ip: " + device_ip)
        logger().info("access point ip: " + str(acces_point_ip))

        #@Todo need to fix some thing in testagent to work for Iperf and Sockets. 
        #@Todo as of now test agent changes support for ping. Comment below lines to pass this test

        # preparing wifi_client for iperf server
        if self.wifi_access_point != self.wifi_client:
            self.wifi_client.interfaces.wifi.join_ap(self.wifi_access_point)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip)
        self.net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic from dut
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info("Iperf Output:")
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None

# preparing wifi_client for pinging DUT as AP
class DUTAPThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
    
    def run(self):
        time.sleep(20)
        #preparing wifi_dut as access point
        self.wifi_dut.interfaces.wifi.start_ap()
        self.wifi_client.interfaces.wifi.join()
        device_ip_dut_as_ap = self.wifi_client.interfaces.wifi.client_gateway_ip
        wifi_client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip_dut_as_ap) < 0.1
        logger().info("Running DUT in AP Mode")
        logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
        logger().info("wifi client ip: " + str(wifi_client_ip))
     
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server  | RS9116TCPIPFeatureBitMap.Ping ,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.config(
    "net_perf_client", 
    net_perf={"host_role": IperfConstants.SERVER_MODE, IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
)
@pytest.mark.firmware_app("test_concurrent_mode")
def test_device_as_sta_and_ap(firmware_loader, net_perf_client, wifi_access_point, wifi_dut, wifi_client, logger):
    with DUTSTAThread(wifi_dut, wifi_access_point, wifi_client, net_perf_client), DUTAPThread(wifi_dut, wifi_client):
         time.sleep(15)