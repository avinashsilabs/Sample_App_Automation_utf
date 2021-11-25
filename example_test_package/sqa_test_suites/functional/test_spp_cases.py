import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116CertificateType
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
import time
import filecmp
import os
import random
import string
from utils.stopwatch import Stopwatch
from interfaces.bluetooth.bluez.ble_device import DeviceManager



def test_bt_dut_as_slave_800bytes_data(wifi_dut, bt_client):
    send_text = "XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241"
    with TimeMeasurer() as t:

        # DUT API
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        # RD API
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

def test_bt_dut_Tx_Rx_powersave_mode(wifi_dut, wifi_access_point,bt_client):
    send_text = "utf_wifi/example_test_package/test_cases/test_powersave.py"
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
                #  If we want to enable BT_powersave
                #wifi_dut.interfaces.wifi.bt_power_save(
                    #power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                #)
                # Send data from dut to bt_client
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == send_text

                # Send data from bt_client to dut
                with wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    assert sent
                    data = bt_client_socket.recv()
                    assert data is not None
                    assert data.decode() == recv_text


def test_SPP_reconnection_of_DUT_after_longer_hours_of_SPP_data_transfer(wifi_dut,  bt_client):
    send_text = "TestinginprogressTestinginprogressTestinginprogress"
    recv_text = "gajgajhcajkcblkv"

    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        bt_server_socket: object
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            recv_text = "9cDKpYOnOJeqYPsL987v"
        with TimeMeasurer() as t:
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected

                # Send data from bt_client to dut
                with wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(
                        recv_text
                    )  # SQA Agent is programmed to send back data
                    assert sent
                    # data = bt_server_socket.recv()
                    # assert data is not None
                    # assert data.decode() == recv_text

                # Send data from dut to bt_client
                #for i in range(0,100):
                sw = Stopwatch()
                while sw.elapsed_sec < (30 * 60):
                    print(sw.elapsed_sec)
                    time.sleep(0.3)
                    wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)

                # Ping dut
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                # Close connection
                bt_server_socket.close()

                time.sleep(20)
                # #Reinitiate connection
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected

        logger().info(f"Scan in {t.duration} seconds")