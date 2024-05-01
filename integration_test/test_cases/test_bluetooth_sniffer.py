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
    for _ in range(30):
        logger().info("Do Some Thing")
        time.sleep(1)
    ble_sniffer.interfaces.sniffer.stop_capture()
    file_size = os.path.getsize(ble_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
def test_bt_sniffer_using_ellisys(bt_sniffer):
    bt_sniffer.interfaces.sniffer.init_sniffer()
    bt_sniffer.interfaces.sniffer.start_capture()
    for _ in range(30):
        logger().info("Do Some Thing")
        time.sleep(1)
    bt_sniffer.interfaces.sniffer.stop_capture()
    assert bt_sniffer.interfaces.sniffer.result is not None
    __print_throughput(bt_sniffer.interfaces.sniffer.result)
    assert bt_sniffer.interfaces.sniffer.capture_file is not None
    file_size = os.path.getsize(bt_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_sniffer_using_frontline(ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    #working bt addresses of NB0016136 NB0016205 NB16209 are '0x3C58C2EA91FA','0x08D23E8B0F46','0xF4A475DEB24A'
    ble_sniffer.interfaces.sniffer.select_bt_devices(['0xFFA198459EAC','0xC6B6F5B18D8D','0xD639EA187595'])
    # ToDo commented below line as this is depended on UTF-4985.
    #ble_sniffer.interfaces.sniffer.add_link_key("XYZ")
    for _ in range(60):
        logger().info("Do Some Thing")
        time.sleep(1)
    ble_sniffer.interfaces.sniffer.stop_capture()
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

    time.sleep(30)
    for captured_file in captured_files:
        # /tmp/reports is mounted to /app/reports in docker
        captured_file = captured_file.replace("/tmp/reports","/app/reports")
        file_size = os.path.getsize(captured_file)
        assert file_size > 0
