import pytest
from utf.utils.logger import get_logger
import os
import json
from utf.utils.iperf.iperf_utils import print_dict

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)

def test_ble_sniffer_using_nrf_sniffer(ble_sniffer):
    ble_sniffer.interfaces.sniffer.configure_interface()
    ble_sniffer.interfaces.sniffer.start_capture()
    for _ in range(1000):
        logger().info("Do Some Thing")
    ble_sniffer.interfaces.sniffer.stop_capture()
    file_size = os.path.getsize(ble_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
def test_ble_sniffer_using_ellisys(ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    assert ble_sniffer.interfaces.sniffer.result is not None
    result_json  = json.loads(ble_sniffer.interfaces.sniffer.result)
    __print_throughput(result_json)
    file_size = os.path.getsize(ble_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
    