import pytest
from utils.thread_base import ThreadBase
import time
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BTSocketRole
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes


# This Thread is used to wifiJoinThread
class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.logger.info(status)
        time.sleep(15)


# This Thread is used to run the dut on slave mode
class BtSppMaster_SlaveThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

        if self.mode == "bt_slave":
            send_text = "yAbdcUK0tAOSMhCT4d6U"
            rec_text = "H2D7yZKRhKULU9Xil5Yv"

            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                time.sleep(20)

                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(rec_text)  # SQA Agent is programmed to send back data
                    assert sent
                    data = bt_server_socket.recv()
                    assert data is not None
                    assert data.decode() == rec_text

                # Send data from dut to bt_client
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == send_text

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_server_socket.close()

        if self.mode == "bt_master":
            # while not self.stop_requested:
            send_text = "sA0L9b1xEgGuUqN5YOlx"
            rec_text = "H2D7yZKRhKULU9Xil5Yv"

            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None

            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None

            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=120)
                    assert addr == bt_dut_address

                    # Send data from bt_client to dut
                    time.sleep(20)
                    with self.wifi_dut.interfaces.wifi.run_bt_task():
                        sent = bt_client_socket.send(
                            rec_text
                        )  # Dut is programmed to send back data
                        assert sent
                        data = bt_client_socket.recv()
                        assert data is not None
                        assert data.decode() == rec_text

                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                    data = bt_client_socket.recv()
                    assert data is not None
                    assert data.decode() == send_text

                    # Ping dut
                    assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_client_socket.close()

# This Thread is used to sent different data
class BtSppMasterThread_diff_data(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        if self.mode == "single":
            send_text = "B"
            self.bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert self.bt_dut_address is not None
            self.bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(self.bt_dut_address, pin_code)
            assert self.bt_client_address is not None
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as self.bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    self.bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(self.bt_client_address)
                    addr = self.bt_client_socket.accept(timeout=120)
                    assert addr == self.bt_dut_address
                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, self.bt_client_address)
                    content = self.bt_client_socket.recv()
                    assert content is not None

        if self.mode == "numbers":
            send_text = "436353837"
            self.bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert self.bt_dut_address is not None
            self.bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(self.bt_dut_address, pin_code)
            assert self.bt_client_address is not None
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as self.bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    self.bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(self.bt_client_address)
                    addr = self.bt_client_socket.accept(timeout=120)
                    assert addr == self.bt_dut_address
                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, self.bt_client_address)
                    content = self.bt_client_socket.recv()
                    assert content is not None

        if self.mode == "paragraph":
            send_text = "RandomtextRandomtextRandomtextRandomtextRandomtextRandomtextRandomtextRandomtexRandomtext"
            self.bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert self.bt_dut_address is not None
            self.bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(self.bt_dut_address, pin_code)
            assert self.bt_client_address is not None
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as self.bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    self.bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(self.bt_client_address)
                    addr = self.bt_client_socket.accept(timeout=120)
                    assert addr == self.bt_dut_address
                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, self.bt_client_address)
                    content = self.bt_client_socket.recv()
                    assert content is not None

        if self.mode == "special_characters":
            send_text = "@#$%^&*()_!_)(*&^%$#@!"
            self.bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert self.bt_dut_address is not None
            self.bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(self.bt_dut_address, pin_code)
            assert self.bt_client_address is not None
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as self.bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    self.bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(self.bt_client_address)
                    addr = self.bt_client_socket.accept(timeout=120)
                    assert addr == self.bt_dut_address
                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, self.bt_client_address)
                    content = self.bt_client_socket.recv()
                    assert content is not None

        if self.mode == "different_language":
            send_text = "支那支那支那支那支那支那支那支那支那"
            self.bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert self.bt_dut_address is not None
            self.bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(self.bt_dut_address, pin_code)
            assert self.bt_client_address is not None
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as self.bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    self.bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(self.bt_client_address)
                    addr = self.bt_client_socket.accept(timeout=120)
                    assert addr == self.bt_dut_address
                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, self.bt_client_address)
                    content = self.bt_client_socket.recv()
                    assert content is not None


# Testcase1 # Testcase7 # Testcase8 # Testcase 10 # Testcase 12
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase1(wifi_dut, bt_client, wifi_access_point):
    mode = "bt_master"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMaster_SlaveThread(wifi_dut, bt_client, mode):
        time.sleep(20)


# Testcase2 # Testcase5 # Testcase6 # Testcase 10 # Testcase 11
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase2(wifi_dut, bt_client, wifi_access_point):
    mode = "bt_slave"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMaster_SlaveThread(wifi_dut, bt_client, mode):
        time.sleep(20)

# Testcase 24 to 28
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase3(wifi_dut, bt_client, wifi_access_point):
    mode = "single"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread_diff_data(wifi_dut, bt_client, mode):
        time.sleep(20)

# Testcase 25
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase4(wifi_dut, bt_client, wifi_access_point):
    mode = "numbers"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread_diff_data(wifi_dut, bt_client, mode):
        time.sleep(20)

# Testcase 26
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase5(wifi_dut, bt_client, wifi_access_point):
    mode = "paragraph"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread_diff_data(wifi_dut, bt_client, mode):
        time.sleep(20)

# Testcase 27
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase6(wifi_dut, bt_client, wifi_access_point):
    mode = "special_characters"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread_diff_data(wifi_dut, bt_client, mode):
        time.sleep(20)

# Testcase 29
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
def test_sta_bt_functional_testcase7(wifi_dut, bt_client, wifi_access_point):
    mode = "different_language"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread_diff_data(wifi_dut, bt_client, mode):
        time.sleep(20)
