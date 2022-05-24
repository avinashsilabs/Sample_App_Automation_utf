import time
import pytest
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes

def logger():
    return get_logger(__name__)

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

class BtSppMaster_SlaveThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
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
                time.sleep(5)

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
                time.sleep(5)


# This Thread is used to sent different data
class BtSpp_role_switch(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

        if self.mode == "bt_slave":
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

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {final_role}")

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_server_socket.close()

        if self.mode == "bt_master":
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None

            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=20)
                    assert addr == bt_dut_address

                    result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                    logger().info(f"Device role:{result}")
                    wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                    time.sleep(10)
                    final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                    logger().info(f"Role Switch: {final_role}")

                    # Ping dut
                    assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_client_socket.close()


# This Thread is used to run and inquiry the BT
class BtThread_inquiry(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.wifi_dut.interfaces.wifi.bt_inquiry()
        time.sleep(20)


# This Thread is used to run and inquiry the BT
class BtThread_cancel_inquiry(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.wifi_dut.interfaces.wifi.bt_inquiry()
        time.sleep(20)

    def set_noscan(self):
        self.shell.execute(f"sudo hciconfig {self.adapter} noscan")
        # Disable scan
        self.bt_client.interfaces.bluetooth.bt_adapter.set_noscan()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_bt_coex_mode_as_slave_C20089(wifi_dut,wifi_access_point,bt_client):
     # mode = "bt_slave"
     # #with wifiJoinThread(wifi_dut, wifi_access_point),BtSppMaster_SlaveThread(wifi_dut, bt_client, mode):
     # with wifiJoinThread(wifi_dut, wifi_access_point):
     #     time.sleep(3)
     # t2 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
     # for i in range(1,5):
     #    t2.start()
     #    time.sleep(2)
     #    t2.wait_for_exit(True)
     #    logger().info(f"iteration completed: {i}")

    mode = "bt_master"
    with wifiJoinThread(wifi_dut, wifi_access_point):
        time.sleep(2)
    t3 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
    for i in range(1,5):
        t3.start()
        time.sleep(2)
        t3.wait_for_exit(True)
        logger().info(f"iteration completed: {i}")

def test_bt_coex_mode_C20091(wifi_dut, bt_client, wifi_access_point):
    mode = "bt_slave"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSpp_role_switch(wifi_dut, bt_client, mode):
        time.sleep(20)

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_bt_coex_inquiry_C20101(wifi_dut, bt_client, wifi_access_point):
    with wifiJoinThread(wifi_dut, wifi_access_point), BtThread_inquiry(wifi_dut, bt_client):
        time.sleep(20)

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_bt_coex_cancel_inquiry_C20103(wifi_dut, bt_client, wifi_access_point):
    with wifiJoinThread(wifi_dut, wifi_access_point), BtThread_cancel_inquiry(wifi_dut, bt_client):
        time.sleep(20)