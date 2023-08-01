from utf.utils.iperf.ping_utils import ping
from utf.utils.logger import get_logger
import time

def logger():
    return get_logger(__name__)


def test_round_trip_time(wifi_dut, wifi_client, wifi_access_point):
    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    ap_ip = wifi_dut.interfaces.wifi.ip.gateway
    ping(ap_ip, 10)
    wifi_client.interfaces.tc.add_delay(40)
    ping(ap_ip, 10)
    wifi_client.interfaces.tc.delete_delay()
    ping(ap_ip, 10)

