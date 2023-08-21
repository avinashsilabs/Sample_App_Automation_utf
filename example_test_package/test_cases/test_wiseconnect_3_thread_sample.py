import time
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import pytest

def logger():
    return get_logger(__name__)


class ThreadA(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        
    def run(self):
        self.wifi_dut.interfaces.wifi.scan()
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.wifi_dut.interfaces.wifi.start_ip()


class ThreadB(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut
        
    def run(self):
        for _ in range(1, 5):
            self.wifi_dut.interfaces.wifi.version()
            time.sleep(5)
            
class ThreadC(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut
        
    def run(self):
        with TimeMeasurer() as t:
            logger().info("Waiting up to 180 seconds for async events")
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                if len(events) >0:
                    for event in events:
                        logger().info(f"Event Data {event.event_data} Event Type {event.event_type}")
                time.sleep(0.5)
    
def test_wiseconnect_3_without_using_threads(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

@pytest.mark.config(
    "wifi_dut",
     wifi={ "thread_config": { "wifi":{ "count": 3, "stack_len": 2048 }, "ble":{ "count": 3, "stack_len": 2048 }  } }
)
def test_wiseconnect_3_with_using_threads(wifi_dut, wifi_access_point):
    with ThreadA(wifi_dut, wifi_access_point), ThreadB(wifi_dut):
        time.sleep(30)


def test_wiseconnect_3_with_or_without_threads(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.init()
    time.sleep(2)
    with ThreadA(wifi_dut, wifi_access_point), ThreadB(wifi_dut):
        time.sleep(5)
    time.sleep(2)

#@pytest.mark.wifi_access_point("dlink810_ap")
def test_async_rejoin_errors(wifi_dut, wifi_access_point, logger):
    # verify ping
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    # stop ap
    logger.info("Disabling access point")
    wifi_access_point.interfaces.wifi.stop_ap()
    with TimeMeasurer() as t:
        logger.info("Waiting up to 180 seconds for rejoin error event...")
        sw = Stopwatch()
        while sw.elapsed_sec < 180:
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
            ]
            if len(rejoin_error_events):
                break
            time.sleep(0.1)
        else:
            assert False, "Did not receive an expected rejoin error event"
    logger.info(f"Received rejoin error event after {t.duration:.2f}s")
    
def test_wiseconnect_3_get_async_messages_with_threads(wifi_dut, wifi_access_point):
    time.sleep(2)
    with ThreadA(wifi_dut, wifi_access_point), ThreadC(wifi_dut):
            time.sleep(5)
    time.sleep(2)