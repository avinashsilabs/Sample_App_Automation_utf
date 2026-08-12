import time
from utf.utils.logger import get_logger

"""
Test LE Audio
==========================================================================

Objective:
    Test LE Audio on device with the nRF5340 audio-dk kits / earbuds
    using RT595 GAF / UMS CLI wrappers.

Author: Ravi Nemali (nRF5340 audio-dk kit -- PoC)
"""


def logger():
    return get_logger(__name__)


# Peer bud addresses from LE Audio setup notes (override as needed for your kit).
PEER_BUD_ADDR_1 = "24:24:B7:1D:0B:F3"
PEER_BUD_ADDR_2 = "B0:54:76:EF:B3:09"

# Stream duration between start and pause (15 minutes per CLI procedure).
LE_AUDIO_STREAM_DURATION_SEC = 15 * 60

# How long to keep CSIP set-member scan running.
GAF_SETMEMBER_SCAN_SEC = 5


def test_le_connect(wifi_dut):
    logger().info("Start Buds in adv mode")
    time.sleep(30)
    logger().info("waiting for the device to initialise and connect")
    # wifi_dut.interfaces.wifi.get_local_address()
    # wifi_dut.interfaces.wifi.()
    wifi_dut.interfaces.wifi.req_conn(PEER_BUD_ADDR_1, address_type=0, conn_type=1)
    time.sleep(30)
    wifi_dut.interfaces.wifi.req_conn(PEER_BUD_ADDR_2, address_type=0, conn_type=1)
    time.sleep(30)
    logger().info("connected")
    logger().info("===== LE Audio: gaf_remote_setup for both buds =====")
    wifi_dut.interfaces.wifi.gaf_remote_setup(PEER_BUD_ADDR_1, 0, 0)
    time.sleep(10)
    wifi_dut.interfaces.wifi.gaf_remote_setup(PEER_BUD_ADDR_2, 0, 0)
    time.sleep(10)
    logger().info("===== LE Audio: stop advertisements before streaming =====")
    wifi_dut.interfaces.wifi.req_adv_stop(3)
    time.sleep(2)
    wifi_dut.interfaces.wifi.btc_disconnect(PEER_BUD_ADDR_1)
    time.sleep(5)
    wifi_dut.interfaces.wifi.btc_disconnect(PEER_BUD_ADDR_2)
    time.sleep(5)
    logger().info("le audio stream completed")  


def test_le_audio_gaf_ums_stream_two_cycles(wifi_dut):
   logger().info("Start Buds in adv mode")
    time.sleep(30)
    logger().info("waiting for the device to initialise and connect")
    wifi_dut.interfaces.wifi.req_conn(PEER_BUD_ADDR_1, address_type=0, conn_type=1)
    time.sleep(15)
    wifi_dut.interfaces.wifi.req_conn(PEER_BUD_ADDR_2, address_type=0, conn_type=1)
    time.sleep(15)
    logger().info("connected")
    logger().info("===== LE Audio: gaf_remote_setup for both buds =====")
    wifi_dut.interfaces.wifi.gaf_remote_setup(PEER_BUD_ADDR_1, 0, 0)
    time.sleep(10)
    wifi_dut.interfaces.wifi.gaf_remote_setup(PEER_BUD_ADDR_2, 0, 0)
    time.sleep(10)
    logger().info("===== LE Audio: stop advertisements before streaming =====")
    wifi_dut.interfaces.wifi.req_adv_stop(3)
    time.sleep(2)
    wifi_dut.interfaces.wifi.stop_scan()
    time.sleep(2)
    logger().info("Gaf remote setup completed")
    logger().info("le audio start streamin")
    wifi_dut.interfaces.wifi.gaf_ums_stream_start(0, 1, 4, 1, 1, 2, 1, 1, 0, 0, 0)
    time.sleep(20)
    wifi_dut.interfaces.wifi.gaf_ums_stream_pause(0, 1, 1)
    time.sleep(10)
    wifi_dut.interfaces.wifi.gaf_ums_stream_start(0, 1, 4, 1, 1, 2, 1, 1, 0, 0, 0)
    time.sleep(20)
    wifi_dut.interfaces.wifi.gaf_ums_stream_pause(0, 1, 1)
    time.sleep(10)
    wifi_dut.interfaces.wifi.btc_disconnect(PEER_BUD_ADDR_1)
    time.sleep(5)
    wifi_dut.interfaces.wifi.btc_disconnect(PEER_BUD_ADDR_2)
    time.sleep(5)
    logger().info("le audio stream completed")  