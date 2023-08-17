import pytest

from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, RS9116BTFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116CustomFeatureBitMap
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
import time
from utf.utils.time_measurer import TimeMeasurer


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

    Author: RaviNemali & Vishakha
"""


def clean_up_method(dut, dut_type="bt_dut"):
    time.sleep(2)
    try:
        if dut_type == "bt_dut":
            logger().info("Disabling WLAN Power Save in DUT...")
            dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            logger().info("Disabling BT Power Save in DUT...")
            dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)
        else:
            logger().info("Disabling WLAN Power Save in DUT...")
            dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            logger().info("Disabling BT Power Save in DUT...")
            dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)
    except Exception as e:
        logger().error(f"Exception: {e}")


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
            | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "bt_features": RS9116BTFeatureBitMap.Default,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        }
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_connectable_c19974(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()

        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

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

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, bt_pin_code)
        assert bt_client_address, "failed to fetch client bt address"

        # Added set class to 400100 to avoid [Error no 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")
        time.sleep(2)

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
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                "Dut is in inactive state!"

            time.sleep(3)
            status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
            logger().info(f"connectable state is:{status}")
            assert status is not None, "failed to fetch connectable status"

            logger().info("disconnecting bt host....")
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address, timeout=100)

            logger().info("closing bt socket...")
            bt_server_socket.close()
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_non_connectable_c19975(bt_dut, bt_client):
    duration = 10000
    retry_count = 2

    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

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
    bt_dut.interfaces.bluetooth.bt_set_non_connectable(timeout=120)
    time.sleep(2)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()
    time.sleep(2)

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=duration,
                                                                      retry_counts=retry_count)
    assert found != bt_dut_address, "DUT address not found in Inquiry"
    logger().info(f"found:{found}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "failed to fetch client bt address"

    # Added set class to 400100 to avoid [Error no 112] Host is down issue
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

            status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
            logger().info(f"connectable state is:{status}")
            assert status is not None, "failed to fetch connectable status"

        logger().info("closing bt socket...")
        bt_server_socket.close()


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_connectable_non_connectable_c19976(bt_dut, bt_client):
    try:
        duration = 10000
        retry_count = 2

        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"
        pin_code = bt_pin_code

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()

        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

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

        # Added set class to 400100 to avoid [Error no 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

        time.sleep(2)
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
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address, timeout=100)

            logger().info("closing bt socket...")
            bt_server_socket.close()
            time.sleep(10)

            logger().info("==== configuring dut in non-connectable mode ====")

            logger().info("configuring dut in non-connectable mode...")
            bt_dut.interfaces.bluetooth.bt_set_non_connectable(timeout=120)

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address, "failed to fetch client bt address"

            # Added set class to 400100 to avoid [Error no 112] Host is down issue
            bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

            time.sleep(3)
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=duration,
                                                                              retry_counts=retry_count)
            assert found != bt_dut_address, "DUT address not found in Inquiry"
            logger().info(f"found:{found}")

            with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert not connected, "expected connection failure in non connectable mode but dut is able to connect"
                logger().info("Expected connection failure in non connectable mode")
                logger().info("closing bt socket...")
                bt_server_socket.close()
            time.sleep(10)
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_connec_and_non_connectable_c19977(bt_dut, bt_client):
    try:
        duration = 10000
        retry_count = 2
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"
        pin_code = bt_pin_code

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()

        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

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

        # Added set class to 400100 to avoid [Error no 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

        time.sleep(3)
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=duration,
                                                                          retry_counts=retry_count)
        assert found != bt_dut_address, "DUT address not found in Inquiry"
        logger().info(f"found:{found}")

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

                logger().info("enabling power save after bt connection...")
                if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
                    bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
                    bt_dut.interfaces.bluetooth.power_save(
                        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                    )
                    bt_dut.interfaces.bluetooth.bt_power_save(
                        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                    )

                logger().info("disconnecting bt host....")
                bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address, timeout=100)

            logger().info("closing bt socket...")
            bt_server_socket.close()

        time.sleep(5)
        logger().info("configuring dut in non-connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_non_connectable(timeout=120)
        time.sleep(2)

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "failed to fetch client bt address"

        # Added set class to 400100 to avoid [Error no 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")

        time.sleep(10)
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=duration,
                                                                          retry_counts=retry_count)
        assert found != bt_dut_address, "DUT address not found in Inquiry"
        logger().info(f"found:{found}")

        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert not connected, "expected connection failure in non connectable mode but dut is able to connect"
                logger().info("Expected connection failure in non connectable mode")

            time.sleep(3)
            status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
            logger().info(f"connectable state is:{status}")
            assert status, "failed to fetch the status"

        logger().info("closing bt socket...")
        bt_server_socket.close()
    finally:
        clean_up_method(bt_dut)


# # Written By Himaja
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_pair_unpair_multiple_c19965(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"
        pin_code = bt_pin_code
        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()
        # status = rsi_bt_spp_init();
        logger().info("initialising dut in spp....")
        bt_dut.interfaces.bluetooth.bt_spp_init()

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "failed to fetch client bt address"

        # Added set class to 400100 to avoid [Error no 112] Host is down issue
        bt_client.interfaces.bluetooth.bt_adapter.set_class("400100")
        for i in range(5):
            time.sleep(2)
            logger().info(f"checking the connection stability in iteration: {i + 1}")
            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                with bt_dut.interfaces.bluetooth.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected, f"failed to connect to bt dut in iteration: {i + 1}"

                time.sleep(3)
                status = bt_dut.interfaces.bluetooth.bt_get_connectable_status()
                logger().info(f"connectable state is:{status}")
                assert status is not None, f"failed to fetch connectable status in iteration: {i + 1}"

                logger().info("enabling power save after bt connection...")
                if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
                    bt_dut.interfaces.bluetooth.set_sleep_gpio(True)
                    bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
                    bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
                time.sleep(30)
                logger().info("pinging dut...")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                logger().info("disconnecting bt host....")
                result = bt_client.interfaces.bluetooth.bt_device.remove_device(bt_dut_address)
                logger().info(f"successfully disconnected device, {result}")
                logger().info("closing bt socket...")
                bt_server_socket.close()
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_init_deinit_functionality_of_the_dut_c19966(bt_dut, bt_client):
    try:
        logger().info(f"running the test_Init_DeInit_functionality_of_the_DUT for 5 Iterations ")
        for i in range(5):
            bt_local_name = "rs911x_bt_spp"
            bt_pin_code = "4321"
            logger().info("starting bt module in dut.....")
            bt_dut.interfaces.bluetooth.bt_start()
            # status = rsi_bt_get_local_device_address(local_dev_addr);
            logger().info("fetching dut bd address....")
            bt_dut.interfaces.bluetooth.bt_get_local_address()
            # status = rsi_bt_get_local_name( & local_name);
            logger().info("configuring bt name....")
            bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
            logger().info("configuring eir data....")
            bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
            logger().info("configuring dut in slave role...")
            bt_dut.interfaces.bluetooth.bt_set_slave_role()
            # status = rsi_bt_spp_init();
            logger().info("setting ssp mode...")
            bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

            logger().info("configuring pin code..")
            bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
            # status = rsi_bt_set_connectable();
            logger().info("configuring dut in connectable mode...")
            bt_dut.interfaces.bluetooth.bt_set_connectable()

            logger().info(f"Enabling the Wi-Fi power save")
            bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            logger().info(f"Enabling the BT power save")
            bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

            time.sleep(10)
            logger().info(f"disabling power save")
            bt_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveDisabled, timeout=120)
            bt_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled, timeout=120)

            logger().info("De-initialising dut in spp....")
            bt_dut.interfaces.bluetooth.bt_deinit()
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_stop_discovery_functionality_c19967(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()
        time.sleep(2)
        logger().info("Stopping the dut in discoverable mode...")
        bt_stop_discoverable_status = bt_dut.interfaces.bluetooth.bt_stop_discoverable(timeout=120)
        assert bt_stop_discoverable_status is not "success", "bt_stop_discoverable is not issued successfully"

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("scanning for the DUT on the RD side")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20)
        assert found is not None, "the DUT is found on the Scan results even after stopping discoverable"
        if found is None:
            logger().error(f"Dut was not found during the scan by bt client. The test case will fail.")
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_discovery_functionality_c19968(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()

        logger().info("Stopping the dut in discoverable mode...")
        bt_start_discoverable_status = bt_dut.interfaces.bluetooth.bt_start_discoverable(timeout=120)
        assert bt_start_discoverable_status is not "success", "bt_start_discoverable is not issued success"

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("scanning for the DUT on the RD side")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=6)
        assert found is not None, "the DUT is Not found on the Scan results even after stopping discoverable"
        if found is None:
            logger().error(f"Dut was found during the scan by bt client. The test case will fail.")
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_stop_discovery_after_discovery_functionality_c19970(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)
        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        for i in range(5):
            logger().info(f"currently in the iteration: {i + 1}")
            logger().info("Starting the dut in discoverable mode...")
            bt_start_discoverable_status = bt_dut.interfaces.bluetooth.bt_start_discoverable(timeout=120)
            assert bt_start_discoverable_status is not "success", "issuing bt_start_discoverable has failed"
            logger().info("scanning for the DUT on the RD side")
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,
                                                                              retry_counts=6)
            assert found is not None, "the DUT is Not found on the Scan results even after stopping discoverable"
            if found is None:
                logger().error(f"Dut was found during the scan by bt client. The test case will fail.")
            logger().info("Stopping the dut in discoverable mode...")
            time.sleep(2)
            bt_stop_discoverable_status = bt_dut.interfaces.bluetooth.bt_stop_discoverable(timeout=120)
            assert bt_stop_discoverable_status is not "success", "issuing bt_stop_discoverable has failed"
            time.sleep(2)
            logger().info("scanning for the DUT on the RD side")
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20)
            assert found is not None, "the DUT is found on the Scan results even after stopping discoverable"
            if found is None:
                logger().error(f"Dut was not found during the scan by bt client. The test case will fail.")
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_spp_dut_as_slave_wrong_pin_c19963(wifi_dut, bt_client):
    try:
        with TimeMeasurer() as t:

            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp(bt_pin_code="1234")
            assert bt_dut_address is not None

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code="9876")
            assert bt_client_address is not None

            bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)

            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    time.sleep(1)
                    assert not connected
                bt_server_socket.close()

            logger().info(f"Enabling the Wi-Fi power save")
            wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            logger().info(f"Enabling the BT power save")
            wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

            received_authentication_failure = False
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                        received_authentication_failure = b"4E05" in event.event_data
                        break
            assert received_authentication_failure
        logger().info(f"Scan in {t.duration} seconds")
    finally:
        clean_up_method(wifi_dut, "wifi_dut")


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_limited_discovery_functionality_c19969(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)
        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        for i in range(5):
            time.sleep(2)
            logger().info(f"Iteration Count:{i + 1}")
            logger().info("Starting the dut in limited discoverable mode...")
            bt_start_limited_discoverable_status = bt_dut.interfaces.bluetooth.bt_start_limited_discoverable(
                time_out_ms=10000, timeout=120)
            assert bt_start_limited_discoverable_status is not "success", \
                "issuing bt_start_limited_discoverable has failed"
            logger().info("scanning for the DUT on the RD side")
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,
                                                                              retry_counts=3)
            assert found, f"Dut was not found during the scan by bt client"

            logger().info("waiting for 10sec for the limited discoverable to timeout")
            time.sleep(10)
            logger().info("scanning after the timeout")
            logger().info("scanning for the DUT on the RD side")
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20)
            assert not found, "Dut is found in Inquiry"
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_get_discoverable_status_after_limited_discovery_c19972(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        time.sleep(3)
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        # status = rsi_bt_get_local_name( & local_name);
        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Starting the dut in limited discoverable mode set to 10sec...")
        bt_start_limited_discoverable_status = bt_dut.interfaces.bluetooth.bt_start_limited_discoverable(
            time_out_ms=10000)
        assert bt_start_limited_discoverable_status is not "success", "bt_start_limited_discoverable " \
                                                                      "is not issued successfully"
        logger().info("issuing get discoverable status")
        get_discover_status = bt_dut.interfaces.bluetooth.bt_get_discoverable_status(timeout=120)
        assert get_discover_status is not "success", "issuing bt_get_discoverable_status has failed"

        logger().info("scanning for the DUT on the RD side")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, "DUT is Not found on the Scan results"

        time.sleep(10)
        logger().info("issuing get discoverable status after timeout")
        get_discover_status = bt_dut.interfaces.bluetooth.bt_get_discoverable_status(timeout=120)
        assert get_discover_status is not "success", "issuing bt_get_discoverable_status has failed"
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_get_discoverable_status_after_stop_discovery_functionality_c19973(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        # status = rsi_bt_get_local_device_address(local_dev_addr);
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)

        logger().info("configuring bt name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)
        logger().info("configuring eir data....")
        bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")
        logger().info("configuring dut in slave role...")
        bt_dut.interfaces.bluetooth.bt_set_slave_role()
        # status = rsi_bt_spp_init();
        logger().info("setting ssp mode...")
        bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

        logger().info("configuring pin code..")
        bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()
        time.sleep(2)
        logger().info("Stopping the dut in discoverable mode...")
        bt_dut.interfaces.bluetooth.bt_stop_discoverable(timeout=120)
        logger().info("scanning for the DUT on the RD side")
        logger().info("issuing get discoverable status")
        get_discover_status = bt_dut.interfaces.bluetooth.bt_get_discoverable_status(timeout=120)
        assert get_discover_status is not "success", "issuing bt_get_discoverable_status has failed"

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20)
        assert found is not None, "the DUT is found on the Scan results even after stopping discoverable"
        if found is None:
            logger().error(f"Dut was not found during the scan by bt client. The test case will fail.")
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_get_discoverable_status_after_discovery_c19971(bt_dut, bt_client):
    try:
        bt_local_name = "rs911x_bt_spp"
        bt_pin_code = "4321"

        logger().info("starting bt module in dut.....")
        bt_dut.interfaces.bluetooth.bt_start()
        logger().info("fetching dut bd address....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address(timeout=120)
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
        # status = rsi_bt_set_connectable();
        logger().info("configuring dut in connectable mode...")
        bt_dut.interfaces.bluetooth.bt_set_connectable()
        logger().info("Stopping the dut in discoverable mode...")
        bt_dut.interfaces.bluetooth.bt_start_discoverable(timeout=120)
        logger().info("issuing get discoverable status")
        get_discover_status = bt_dut.interfaces.bluetooth.bt_get_discoverable_status(timeout=120)
        assert get_discover_status is not "success", "issuing bt_get_discoverable_status has failed"

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("scanning for the DUT on the RD side")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=6)
        assert found is not None, "the DUT is Not found on the Scan results even after stopping discoverable"
        if found is None:
            logger().error(f"Dut was found during the scan by bt client. The test case will fail.")
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_connectivity_of_dut_scanned_remote_bt_with_correct_pin_c19961(wifi_dut, bt_client):
    try:
        with TimeMeasurer() as t:
            logger().info(f"Configuring DUT as SPP Master")
            wifi_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert wifi_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-Master with MAC address {wifi_dut_address} ")
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(wifi_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

            time.sleep(4)
            logger().info(f' initialize bt inquiry ')
            found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                   inquiry_type=1,
                                                                   inquiry_duration_ms=10000,
                                                                   timeout=22,
                                                                   retry_counts=3)
            if not found:
                assert found, "Dut unable to find the bt client device. The test case may fail"
            logger().info(f' bt inquiry successful')

            logger().info(f'Create SPP Connection')
            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
                # SPP Connection
                logger().info("******* SPP Connection *******")
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    time.sleep(3)
                    wifi_dut.interfaces.wifi.bt_link_policy_settings(bt_client_address, 4)
                    wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=12)
                    assert addr == wifi_dut_address, "SPP Connection Failed"
                logger().info(f'SPP Connection Completed')

                ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=wifi_dut_address)
                logger().info(f"l2ping response {ping_response}")
                assert ping_response, "dut is in inactive state..."

                logger().info(f"Enabling the Wi-Fi power save")
                wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
                logger().info(f"Enabling the BT power save")
                wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        bt_client_socket.close()
        logger().info(f"Scan in {t.duration} seconds")
    finally:
        clean_up_method(wifi_dut, "wifi_dut")


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_remote_name_request_functionality_of_dut_on_sd_when_bt_is_on_c19978(bt_dut, bt_client):
    try:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        time.sleep(4)
        logger().info(f' initialize bt inquiry ')
        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=10000,
                                                             timeout=22,
                                                             retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(3)
        received_name = False
        logger().info("initiating remote name request")
        for i in range(3):
            event_data = ""
            bt_dut.interfaces.bluetooth.bt_remote_name_request_async(bt_client_address, timeout=10)
            events = bt_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    event_data = event_data + str(event.event_data.decode())
                    if "0x4E04" in event_data:
                        continue
                    elif "RSI_APP_EVENT_REMOTE_NAME_RESP" in event_data and "resp_status: 0x0" in  event_data:
                        logger().info(f"event.event_data: {event_data}")
                        received_name = True
                        break
            if received_name:
                logger().info("Found remote device name")
                break
            else:
                logger().info("Wait for 5 sec")
                time.sleep(5)
        assert received_name, "Failed to get remote device name"
    finally:
        clean_up_method(bt_dut)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_get_services_functionality_of_dut_c19987(bt_dut, bt_client):
    try:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=10000,
                                                             timeout=22,
                                                             retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f'Create SPP Connection')
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            logger().info("******* SPP Connection *******")
            with bt_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                time.sleep(3)
                bt_dut.interfaces.wifi.bt_link_policy_settings(bt_client_address, 4)
                bt_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=12)
                assert addr == bt_dut_address, "SPP Connection Failed"
            logger().info(f'SPP Connection Completed')

            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, "dut is in inactive state..."

            logger().info(f"Enabling the Wi-Fi power save")
            bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            logger().info(f"Enabling the BT power save")
            bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

            status = bt_dut.interfaces.bluetooth.bt_get_services(bt_client_address)
            assert status is not "success", "bt_get_services is not successfully issued"
            logger().info(f"bt_get_services: {status}")

            time.sleep(60)
            logger().info("pinging dut...")
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, "dut is in inactive state..."

            logger().info("disconnecting bt host....")
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address, timeout=100)

            logger().info("closing bt socket...")
            bt_client_socket.close()
    finally:
        clean_up_method(bt_dut)


def test_bt_search_service_async_on_dut_c19988(bt_dut, bt_client):
    try:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=10000,
                                                             timeout=22,
                                                             retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device."
        logger().info(f' bt inquiry successful')

        logger().info(f'Create SPP Connection')
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            logger().info("******* SPP Connection *******")
            with bt_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                time.sleep(3)
                bt_dut.interfaces.wifi.bt_link_policy_settings(bt_client_address, 4)
                bt_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=12)
                assert addr == bt_dut_address, "SPP Connection Failed"
            logger().info(f'SPP Connection Completed')

            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, "dut is in inactive state..."

            logger().info(f"Enabling the Wi-Fi power save")
            bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            logger().info(f"Enabling the BT power save")
            bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

            result = bt_dut.interfaces.bluetooth.bt_get_services(bt_client_address)
            logger().info(f"The results are {result}")
            for i in range(len(result)):
                search_service_status = bt_dut.interfaces.bluetooth.bt_search_service_async(
                    device_Addr=bt_client_address, service_uuid=int(result[i], 16))
                logger().info(f"The status is {search_service_status}")
                assert search_service_status == 0, f"Service UUID {int(result[i], 16)} " \
                                                   f"is not supported on remote device"

            time.sleep(60)
            logger().info("pinging dut...")
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, "dut is in inactive state..."

            logger().info("disconnecting bt host....")
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address, timeout=100)

            logger().info("closing bt socket...")
            bt_client_socket.close()
    finally:
        clean_up_method(bt_dut)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "disassociated"])
def test_dut_not_respondingto_pincode_request_C19962(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave_without_agent(bt_dut_address)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=10000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"enabling power save")
        wifi_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        logger().info(f'Create SPP Connection')
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            time.sleep(3)
            wifi_dut.interfaces.wifi.bt_link_policy_settings(bt_client_address, 4)
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
            assert result[1] is None, "Unable to find BT client socket connection"
            logger().info(f'SPP Connection Completed')

        # Close connection
        logger().info(f"BT client socket connection closing")
        bt_client_socket.close()
        time.sleep(2)

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E18" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E18"
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.
        WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_bt_cancel_inquiry_C19986(bt_dut, bt_client):
    with TimeMeasurer() as t:
        logger().info(f"Configuring DUT as SPP Master")
        wifi_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert wifi_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {wifi_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(wifi_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info(f' initialize bt inquiry ')
        bt_dut.interfaces.wifi.bt_inquiry(inquiry_type=0, inquiry_duration_ms=10000, max_device_cnt=10)
        logger().info(f'bt inquiry successful')
        time.sleep(1)

        # Cancel BT inquiry
        bt_dut.interfaces.wifi.bt_cancel_inquiry()
        logger().info("Inquiry cancelled")
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.
        WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_cancel_pairing_request_C19964(bt_dut, bt_client):
    with TimeMeasurer() as t:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="-9")
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=20000,
                                                             timeout=22,
                                                             retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        for i in range(3):
            logger().info(
                "Send SPP Connection From DUT and reject pairing request from remote device")
            logger().info(f"Create SPP Connection attempt: {i + 1}")
            with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                with bt_dut.interfaces.bluetooth.run_bt_task():
                    bt_client_socket.create_client()
                    time.sleep(5)
                    bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)

        received_authentication_failure = False
        events = bt_dut.interfaces.bluetooth.get_async_events()
        if len(events):
            for event in events:
                for err_code in [b"4E18", b"4E16"]:
                    if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                        received_authentication_failure = err_code in event.event_data
                        break
        assert received_authentication_failure, f"Did not receive authentication failure message"
        logger().info("Received Authentication failure message")
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.
        WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_reinitiate_pairing_request_C19989(bt_dut, bt_client):
    with TimeMeasurer() as t:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="-9")
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=20000,
                                                             timeout=22,
                                                             retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        for i in range(3):
            logger().info(
                "Send SPP Connection From DUT and reject pairing request from remote device")
            logger().info(f"Create SPP Connection attempt: {i + 1}")
            with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                with bt_dut.interfaces.bluetooth.run_bt_task():
                    bt_client_socket.create_client()
                    time.sleep(5)
                    connected = bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
                    assert connected, "failed to connect to bt dut"

        received_authentication_failure = False
        events = bt_dut.interfaces.bluetooth.get_async_events()
        if len(events):
            for event in events:
                for err_code in [b"4E18", b"4E16"]:
                    if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                        received_authentication_failure = err_code in event.event_data
                    break
        assert received_authentication_failure, f"Did not receive authentication failure message"
        logger().info("Received Authentication failure message")

        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="-9")
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.
        WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "bt_disconnect"])
def test_max_length_remote_device_name_C19980(bt_dut, bt_client):
    try:
        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address=bt_dut_address,
                                                                           pin_code=pin_code,
                                                                           bt_name="max_remote_device_name")

        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        time.sleep(4)
        logger().info(f' initialize bt inquiry ')
        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                             inquiry_type=1,
                                                             inquiry_duration_ms=10000,
                                                             timeout=22,
                                                             retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"Enabling the Wi-Fi power save")
        bt_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enabling the BT power save")
        bt_dut.interfaces.bluetooth.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(3)
        received_name = False
        logger().info("initiating remote name request")
        for i in range(3):
            event_data = ""
            bt_dut.interfaces.bluetooth.bt_remote_name_request_async(bt_client_address, timeout=10)
            events = bt_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    event_data = event_data + str(event.event_data.decode())
                    if "0x4E04" in event_data:
                        continue
                    elif "RSI_APP_EVENT_REMOTE_NAME_RESP" in event_data and "resp_status: 0x0" in  event_data:
                        logger().info(f"event.event_data: {event_data}")
                        received_name = True
                        break
            if received_name:
                logger().info("Found remote device name")
                break
            else:
                logger().info("Wait for 5 sec")
                time.sleep(5)
        assert received_name, "Failed to get remote device name"
    finally:
        clean_up_method(bt_dut)
