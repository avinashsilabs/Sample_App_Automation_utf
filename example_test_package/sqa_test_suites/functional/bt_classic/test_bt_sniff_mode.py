import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116ExtCustomFeatureBitMap
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.stopwatch import Stopwatch
from datetime import datetime, timedelta
import random
import string
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap,
    RS9116ConfigFeatureBitMap
)

"""Test Author = M.Harshitha

Test Steps:
    1. Initiates the DUT Coex wlan and DualBluetoothBLEmode
    2. Initiates the DUT in master SPP mode (or)slave SPP mode for the capability
    3. Initiates the Client in slave SPP (or) master SPP with capability enables
    4. Opens Bt socket and connects to the remote client.
    5. Verifies ping after the connection.
    6. Initiates the DUT in Sniff Mode
    7. Verifies the powersave in wifi and BT
    7. Send Data transfer from Dut to BT client.

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

def logger():
    return get_logger(__name__)

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def sniff_mode_in_slave_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    send_text = text_generator()

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("Fetching the name of bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut in discoverable mode ")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("configuring dut in connectable mode")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()

    logger().info(f"BT dut address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected, "failed to connect to bt dut"

            time.sleep(60)
            logger().info("pinging dut...")
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            time.sleep(2)
            sniffmode = bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                                      sniff_max_interval=sniff_max_interval,
                                                                      sniff_min_interval=sniff_min_interval,
                                                                      sniff_attempt=sniff_attempt,
                                                                      sniff_tout=sniff_time_out)
            assert sniffmode, "Failed to initiate dut in sniff mode"

            # Initiating power save
            logger().info("======= Initiating the Power Save mode in Wifi and BT==========")
            if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifiPowersave , f"Failed to enable wifi in powersave"
                logger().info("==========Enables Power Save in BT Mode===========")
                enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_btPowersave, f"Failed to enable BT in Powersave"

            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                logger().info("==========Send the data from dut to bt client=========")
                bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data, "failed to recevie data from dut to bt client "
                assert data.decode() == send_text

    logger().info("Disconnecting bt client address")
    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    logger().info(f"Close Socket connection")
    bt_server_socket.close()

    if not found:
        assert found, f"device with address {bt_dut_address} not found"

def sniff_mode_in_master_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):
    send_text = text_generator()

    logger().info("configuring dut in spp master role")
    bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
    assert bt_dut_address, "failed to initialise bt in dut"

    logger().info(f"BT Dut address {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                         inquiry_duration_ms=20000, timeout=22, retry_counts=3)

    logger().info(f"BT found device is {found}, found bt client address {bt_client_address}")
    if not found:
        assert found, f"BT DUT is unable to inquiry, So Could not find bt client address {bt_client_address} during inquiry, test case may fail "

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        logger().info("========Spp Connection=======")
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_client_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=10)
            assert addr == bt_dut_address

            # Ping DUT
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, "fFailed to ping BT client to DUT"

            time.sleep(2)
            sniffmode = bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                          sniff_max_interval=sniff_max_interval,
                                                          sniff_min_interval=sniff_min_interval,
                                                          sniff_attempt=sniff_attempt,
                                                          sniff_tout=sniff_time_out)
            assert sniffmode, "Failed to initiate dut in sniff mode"

            # Initiating power save
            logger().info("======= Initiating the Power Save==========")
            if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifiPowersave, f"Failed to enable wifi in powersave"
                logger().info("==========Enables Power Save in BT Mode===========")
                enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_btPowersave, f"Failed to enable BT in Powersave"

            # Data will transfer 60 seconds
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                # Send the data from dut to bt client
                logger().info("=========Send the data from dut to bt client==========")
                bt_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data ,"failed to recevie data from dut to bt client "
                assert data.decode() == send_text

    logger().info("Disconnecting bt client address")
    bt_dut.interfaces.wifi.bt_disconnect(bt_client_address)

    logger().info(f"Close Socket connection")
    bt_client_socket.close()

def exit_sniff_mode_in_slave_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    bt_local_name = "rs911x_bt_spp"
    bt_pin_code = "4321"
    pin_code = bt_pin_code

    send_text = text_generator()

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("Fetching the name of bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    logger().info("configuring eir data....")
    bt_dut.interfaces.bluetooth.bt_set_eir_data(f"{bt_local_name}_eir")

    logger().info("configuring dut in slave role...")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut in discoverable mode ")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("configuring dut in connectable mode")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("setting ssp mode...")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(0, 3)

    logger().info("configuring pin code..")
    bt_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)

    logger().info("initialising dut in spp....")
    bt_dut.interfaces.bluetooth.bt_spp_init()

    logger().info(f"BT dut address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected, "failed to connect to bt dut"

            time.sleep(60)
            logger().info("pinging dut...")
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            time.sleep(2)
            sniffmode = bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                                      sniff_max_interval=sniff_max_interval,
                                                                      sniff_min_interval=sniff_min_interval,
                                                                      sniff_attempt=sniff_attempt,
                                                                      sniff_tout=sniff_time_out)
            assert sniffmode, "Failed to initiate dut in sniff mode"

            # Initiating power save
            logger().info("======= Initiating the Power Save mode in Wifi and BT==========")
            if isinstance(bt_dut.interfaces.bluetooth, RSSAPICommands):
                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifiPowersave, f"Failed to enable wifi in powersave"
                logger().info("==========Enables Power Save in BT Mode===========")
                enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_btPowersave, f"Failed to enable BT in Powersave"

            exit_mode = bt_dut.interfaces.bluetooth.set_bt_sniff_exit_mode(bt_client_address=bt_client_address)
            assert exit_mode,"Failed to exit the sniff mode from dut"

            time.sleep(5)
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                logger().info("==========Send the data from dut to bt client=========")
                bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data, "failed to recevie data from dut to bt client "
            assert data.decode() == send_text

        logger().info(f"Close Socket connection")
        bt_server_socket.close()

    logger().info("Disconnecting bt client address")
    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    if not found:
        assert found, f"device with address {bt_dut_address} not found"


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
            "ext_tcpip_features": 0,
            "custom_features": RS9116CustomFeatureBitMap.Default,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection
        }
    )
]

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(160, 160, 5, 3)])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_sniff_mode_act_as_slave_role_C20049(bt_dut,bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    test_case = "***********sniff mode acts as slave role****************"
    logger().info(f"{test_case}")
    sniff_mode_in_slave_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out)
    time.sleep(5)

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out"
, [(840, 840, 10, 5), (400, 400, 5, 2), (192, 160, 4, 2)])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_sniff_mode_with_different_interval_act_as_slave_role_c20050(bt_dut,bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    test_case = "********sniff mode with different intervals act as slave role**********"
    logger().info(f"{test_case}")
    sniff_mode_in_slave_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out)
    time.sleep(5)

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(160, 160, 5, 3)])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_sniff_mode_act_as_master_role_c20051(bt_dut,bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    test_case = "********sniff mode act as master role*************"
    logger().info(f"{test_case}")
    sniff_mode_in_master_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out)
    time.sleep(5)

@pytest.mark.skip()
@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(160, 160, 5, 3)])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_exit_sniff_mode_act_as_slave_role_c20052(bt_dut,bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    test_case = "**********exit sniff mode act as slave role************"
    logger().info(f"{test_case}")
    exit_sniff_mode_in_slave_role(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out)
    time.sleep(5)