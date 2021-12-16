import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
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


"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's
        
    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capabilty enables
        4. Opnes Bt socket and connects to the remote client.
        5. Verifies ping after the connection.
    
    Author: Ravi Nemali
"""

'''=============================== DUT AS MASTER TEST CASES ================================='''

# This test case verifies the bt basic spp connection
def test_bt_physical_level_conn(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            #SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
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


# This test case verifies the spp connection in display only mode
def test_bt_master_ssp_displayonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="0")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayOnly")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
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


# This test case verifies the spp connection in display YesNo mode
def test_bt_master_ssp_DisplayYesNo(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="0")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayYesNo")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
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


# This test case verifies the spp connection in keyboardonly mode
def test_bt_master_ssp_keyboardonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="2")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="KeyboardOnly")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
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

