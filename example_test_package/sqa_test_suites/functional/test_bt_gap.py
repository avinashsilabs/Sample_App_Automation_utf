import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ExtCustomFeatureBitMap,RS9116ConfigFeatureBitMap
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

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in slave Spp mode with capability and connect modes
        3. Opens Bt socket and connects to the remote client.
        4. Verifies ping after the connection.
        5. Disconnects from the DUT and close the bt socket.

    Author: RaviNemali
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
]
def test_bt_connectable_C19974(bt_dut, bt_client):
    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("configuring dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Errno 112] Host is down issue
    bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")
    time.sleep(2)

    ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
    logger().info(f"l2ping response {ping_response}")
    assert ping_response, "dut is in inactive state..."

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "failed to connect to bt dut"

        logger().info("enabling power save after bt connection...")
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )

        time.sleep(30)
        logger().info("pinging dut...")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )

        status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
        logger().info(f"connectable state is:{status}")
        assert status is not None,"failed to fetch connectable status"

        logger().info("disconnecting bt host....")
        bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

        logger().info("closing bt socket...")
        bt_server_socket.close()

def test_bt_non_connectable_C19975(bt_dut, bt_client):
    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("configuring dut in non-connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_non_connectable()
    time.sleep(2)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()
    time.sleep(2)

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Errno 112] Host is down issue
    bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")
    time.sleep(2)

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert not connected,"expected connection failure in non connectable mode but dut is able to connect"
                logger().info("Expected connection failure in non connectable mode")
                logger().info("closing bt socket...")

                status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
                logger().info(f"connectable state is:{status}")
                assert status is not None, "failed to fetch connectable status"

                bt_server_socket.close()

def test_bt_connectable_non_connectable_C19976(bt_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10

    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("configuring dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()
    time.sleep(2)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()
    time.sleep(2)

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Errno 112] Host is down issue
    bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

    ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
    logger().info(f"l2ping response {ping_response}")
    assert ping_response, "dut is in inactive state..."

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "failed to connect to bt dut"
            logger().info("dut connected to host in connectable mode")

        logger().info("enabling power save after bt connection...")
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )

        time.sleep(30)
        logger().info("pinging dut...")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        logger().info("disconnecting bt host....")
        bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

        logger().info("closing bt socket...")
        bt_server_socket.close()
        time.sleep(10)

        logger().info("==== configuring dut in non-connectable mode ====")

        logger().info("configuring dut in non-connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_non_connectable()

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "failed to fetch client bt address"

        # Added set class to 400100 to avoid [Errno 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

        time.sleep(10)
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert not connected, "expected connection failure in non connectable mode but dut is able to connect"
                logger().info("Expected connection failure in non connectable mode")
                logger().info("closing bt socket...")
                bt_server_socket.close()

        time.sleep(10)
        bt_dut.interfaces.bluetooth.bt_inquiry(inq_type, duration, max_no_dev)

def test_bt_connec_and_non_connectable_C19977(bt_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("configuring dut in connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_connectable()
    time.sleep(2)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()
    time.sleep(2)

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Errno 112] Host is down issue
    bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")
    time.sleep(2)

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "failed to connect to bt dut"
            time.sleep(60)
            logger().info("pinging dut...")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            logger().info("disconnecting bt host....")
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

            logger().info("closing bt socket...")
            bt_server_socket.close()

    logger().info("configuring dut in non-connectable mode...")
    bt_dut.interfaces.bluetooth.bt_set_non_connectable()
    time.sleep(2)

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Errno 112] Host is down issue
    bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

    time.sleep(10)
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert not connected, "expected connection failure in non connectable mode but dut is able to connect"
            logger().info("Expected connection failure in non connectable mode")
            logger().info("closing bt socket...")
            bt_server_socket.close()

        logger().info("enabling power save after bt connection...")
        if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
            bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
            bt_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            bt_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )

        time.sleep(10)
        bt_dut.interfaces.bluetooth.bt_inquiry(inq_type, duration, max_no_dev)

        status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
        logger().info(f"connectable state is:{status}")
        assert status is not None

        logger().info("closing bt socket...")
        bt_server_socket.close()