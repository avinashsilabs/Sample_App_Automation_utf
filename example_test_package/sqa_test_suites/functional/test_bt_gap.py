import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
import time

def logger():
    return get_logger(__name__)

"""
    setup requirement:
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

    Author: RaviNemali
"""

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
def test_bt_connectable_C19974(bt_dut, bt_client):

    logger().info("configurung dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("set dut in discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="rs9916bt")

    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    bt_dut.interfaces.bluetooth.bt_spp_init()
    logger().info("initiating dut in slave spp role....")


    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
        mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected

        # Initiating power save
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
            )

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Close connection
        bt_server_socket.close()

def test_bt_non_connectable_C19975(bt_dut, bt_client):

    logger().info("configurung dut in non-connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_non_connectable()

    logger().info("set dut in discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("initiating dut in slave spp role....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address, "unable to fetch dut bd address...."

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address..."

    with bt_client.interfaces.bluetooth.bt_socket(
        mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected

        # Initiating power save
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
            )
        logger().info("ping to dut....")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Close connection
        logger().info("closing bt connection.....")
        bt_server_socket.close()

def test_bt_connectable_non_connectable_C19976(bt_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    logger().info("configurung dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("set dut in discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="rs9916bt")

    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    bt_dut.interfaces.bluetooth.bt_spp_init()
    logger().info("initiating dut in slave spp role....")


    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
        mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected

        # Initiating power save
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
            )
        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Close connection
        bt_server_socket.close()

        time.sleep(20)
        logger().info("configurung dut in non-connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_non_connectable()

        time.sleep(10)
        bt_dut.interfaces.bluetooth.bt_inquiry(inq_type, duration, max_no_dev)

def test_bt_non_connec_connectable_non_connece_C19977(bt_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    logger().info("configurung dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("set dut in discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="rs9916bt")

    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    bt_dut.interfaces.bluetooth.bt_spp_init()
    logger().info("initiating dut in slave spp role....")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected

        # Initiating power save
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
            )
        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Close connection
        bt_server_socket.close()

        time.sleep(20)
        logger().info("configurung dut in non-connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_non_connectable()

        logger().info("set dut in discoverable mode....")
        bt_dut.interfaces.bluetooth.bt_start_discoverable()

        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="rs9916bt")

        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

        bt_dut.interfaces.bluetooth.bt_spp_init()
        logger().info("initiating dut in slave spp role....")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        time.sleep(10)
        bt_dut.interfaces.bluetooth.bt_inquiry(inq_type, duration, max_no_dev)