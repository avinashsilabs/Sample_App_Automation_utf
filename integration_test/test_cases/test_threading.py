import pytest
from utf.utils.thread_base import ThreadBase
import time


class PingThread(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        while not self.stop_requested:
            self.wifi_dut.interfaces.wifi.ping(self.wifi_dut.interfaces.wifi.ip.gateway)
            time.sleep(0.1)


class HttpRequestThread(ThreadBase):
    def __init__(self, wifi_dut, http_server):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.http_server = http_server

    def run(self):
        while not self.stop_requested:
            status, content = self.wifi_dut.interfaces.http.http_get(
                self.http_server.interfaces.http, ""
            )
            self.logger.info(status)
            self.logger.info(content)
            time.sleep(0.1)


@pytest.mark.dut("rs9116_at")
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.test_src_map_id('SM11986')
def test_threading(http_server, wifi_networked_dut, http_dut, wifi_access_point):
    # explicit thread start/stop/wait for exit
    ping_thread = PingThread(wifi_networked_dut)
    http_thread = HttpRequestThread(http_dut, http_server)
    ping_thread.start()
    http_thread.start()
    try:
        time.sleep(15)
    finally:
        http_thread.stop()
        ping_thread.stop()
        http_thread.wait_for_exit()
        ping_thread.wait_for_exit()


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.test_src_map_id('SM11990')
def test_threading_contextmgr(
    http_server, wifi_networked_dut, http_dut, wifi_access_point
):
    # start/stop/wait for exit through context manager
    with PingThread(wifi_networked_dut), HttpRequestThread(http_dut, http_server):
        time.sleep(15)
