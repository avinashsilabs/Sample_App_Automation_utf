import pytest
from utils.thread_base import ThreadBase
import time
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BTSocketRole
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes


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
class BtSppSlaveThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        # while not self.stop_requested:
        send_text = "yAbdcUK0tAOSMhCT4d6U"
        recv_text = "H2D7yZKRhKULU9Xil5Yv"

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
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == recv_text

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

# This thread runs the dut on bt master mode
class BtSppMasterThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        # while not self.stop_requested:
        send_text = "sA0L9b1xEgGuUqN5YOlx"
        recv_text = "H2D7yZKRhKULU9Xil5Yv"

        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None

        with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address

                # Send data from bt_client to dut
                time.sleep(20)
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    assert sent
                    data = bt_client_socket.recv()
                    assert data is not None
                    assert data.decode() == recv_text

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


# Testcase1 # Testcase7 # Testcase8
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
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppMasterThread(wifi_dut, bt_client):
        time.sleep(15)


# Testcase2 # Testcase5 # Testcase6
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
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSppSlaveThread(wifi_dut, bt_client):
        time.sleep(15)
