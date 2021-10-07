import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116TCPIPFeatureBitMap
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116BTFeatureBitMap
import time
import os

def logger():
    return get_logger(__name__)

def test_http(wifi_client, wifi_access_point, http_server):
    # if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
    #     raise NotImplementedError(
    #         "This test case is only currently implemented for SAPI"
    #     )
    if wifi_client != wifi_access_point:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        wifi_client.interfaces.wifi.start_ip()

    with TimeMeasurer() as t:
        assert http_server.interfaces.http.started
        time.sleep(60)
    logger().info(f"Scan in {t.duration} seconds")