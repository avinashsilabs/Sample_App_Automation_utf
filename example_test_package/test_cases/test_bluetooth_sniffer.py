import pytest
from utf.utils.logger import get_logger
import os
from utf.utils.iperf.iperf_utils import print_dict
import time

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


def test_ble_sniffer_using_nrf(ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    for _ in range(1000):
        logger().info("Do Some Thing")
    time.sleep(15)
    ble_sniffer.interfaces.sniffer.stop_capture()
    file_size = os.path.getsize(ble_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
def test_bt_sniffer_using_ellisys(bt_sniffer):
    bt_sniffer.interfaces.sniffer.init_sniffer()
    bt_sniffer.interfaces.sniffer.start_capture()
    for _ in range(1000):
        logger().info("Do Some Thing")
    time.sleep(15)
    bt_sniffer.interfaces.sniffer.stop_capture()
    assert bt_sniffer.interfaces.sniffer.result is not None
    __print_throughput(bt_sniffer.interfaces.sniffer.result)
    assert bt_sniffer.interfaces.sniffer.capture_file is not None
    file_size = os.path.getsize(bt_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
    