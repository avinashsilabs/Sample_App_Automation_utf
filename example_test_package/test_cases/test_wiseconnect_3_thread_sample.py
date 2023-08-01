import time
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


class ThreadA(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        
    def run(self):
        self.wifi_dut.interfaces.wifi.scan(thread=True)
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
        self.wifi_dut.interfaces.wifi.start_ip(thread=True)


class ThreadB(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut
        
    def run(self):
        for _ in range(1, 5):
            self.wifi_dut.interfaces.wifi.version(thread=True)
            time.sleep(5)
    

def test_wiseconnect_3_without_using_threads(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.scan(ssid=None, thread=True)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, thread=True)
    wifi_dut.interfaces.wifi.start_ip(thread=True)


def test_wiseconnect_3_with_using_threads(wifi_dut, wifi_access_point):
    with ThreadA(wifi_dut, wifi_access_point), ThreadB(wifi_dut):
        time.sleep(30)


def test_wiseconnect_3_with_or_without_threads(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.init(thread=True)
    time.sleep(2)
    with ThreadA(wifi_dut, wifi_access_point), ThreadB(wifi_dut):
        time.sleep(5)
    time.sleep(2)
