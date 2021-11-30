import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
import time

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            }
    )
]

def logger():
    return get_logger(__name__)

def test_bt_spp_dut_as_slave(wifi_dut, wifi_access_point, bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected

            # Initiating power save
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                wifi_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                wifi_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
                )

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(
                    recv_text
                )  # SQA Agent is programmed to send back data
                assert sent
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None
            assert data.decode() == send_text

            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            # Close connection
            bt_server_socket.close()
    logger().info(f"Scan in {t.duration} seconds")


def test_bt_spp_dut_as_master(wifi_dut, wifi_access_point, bt_client):
    send_text = "sA0L9b1xEgGuUqN5YOlx"
    recv_text = "H2D7yZKRhKULU9Xil5Yv"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None
        time.sleep(0.5)

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=12)
                assert addr == bt_dut_address

            # Initiating power save
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                wifi_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                wifi_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
                )

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_client_socket.send(
                    recv_text
                )  # Dut is programmed to send back data
                assert sent
                data = bt_client_socket.recv()
                assert data is not None
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data is not None
            assert data.decode() == send_text

            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")
