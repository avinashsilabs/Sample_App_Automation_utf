import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
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

  Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capabilty enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.
  
  Author: Ravi Nemali
    
"""

'''=============================== DUT AS SLAVE TEST CASES ================================='''

# This test case verifies the spp connection in slave mode
def test_bt_physical_level_conn_slave(wifi_dut, bt_client):
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

                # Ping dut
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                # Close connection
                bt_server_socket.close()
    logger().info(f"Scan in {t.duration} seconds")

# This test case verifies the spp connection in slave displayonly mode
def test_bt_slave_ssp_displayonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_slave_ssp_display(pair_mode="1", capability="0")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code, capability="DisplayOnly")
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                    # Close connection
                    bt_server_socket.close()
                    time.sleep(
                0.2
            )
    logger().info(f"Scan in {t.duration} seconds")


# This test case verifies the spp connection in slave keyboarddisplay mode
def test_bt_slave_ssp_keyboarddisplay(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_slave_ssp_display(pair_mode="1", capability="2")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code, capability="KeyboardDisplay")
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                    # Close connection
                    bt_server_socket.close()
                    time.sleep(
                0.2
            )
    logger().info(f"Scan in {t.duration} seconds")