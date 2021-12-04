import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from interfaces.bluetooth import BTSocketRole
from utils.time_measurer import TimeMeasurer
import time



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            }
        )
    ]

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""
"""This test case is used to switch the dut as slave mode to duat as master mode"""
def test_bt_spp_dut_as_slave(wifi_dut, bt_client):
    send_text = "AMFJTEJRTOLGWSGJWTJWGTL"
    with TimeMeasurer() as t:
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
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )

                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                status = wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                events = wifi_dut.interfaces.wifi.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == 'rsi_bt_on_role_change_event success':
                            role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                final_role= wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {final_role}")
                # Send data from dut to bt_client
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == send_text
            bt_server_socket.close()
    logger().info(f"Scan in {t.duration} seconds")

"""This test cases is used to switch the dut as master mode to dut as slave mode"""
def test_bt_spp_dut_as_master(wifi_dut,bt_client):
    send_text = "ABCDEFRGHJ12345UIOPLKJ"
    role =" "
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Client
        ) as bt_client_socket:
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                wifi_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                wifi_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
            result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Device role:{result}")
            status = wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="1")
            time.sleep(10)
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if 'rsi_bt_on_role_change_event success' in event.event_type:
                          role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Role Switch: {final_role}")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data is not None
            assert data.decode() == send_text
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")







