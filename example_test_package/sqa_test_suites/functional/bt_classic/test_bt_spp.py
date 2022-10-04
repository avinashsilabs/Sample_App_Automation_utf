import pytest
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
import time
import random
import string
from datetime import datetime, timedelta
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116AsyncEventType
)

"""Test Author = M.Harshitha

Test Steps:
    1. Initiates the DUT Coex wlan and DualBluetoothBLEmode
    2. Initiates the DUT in master SPP mode (or)slave SPP mode 
    3. Initiates the Client in slave SPP (or) master SPP 
    4. Opens Bt socket and connects to the remote client.
    5. Initiates the SPP Connection
    6. Verifies ping after the connection.
    7. Verifies the powersave in wifi and BT
    8. Send Data transfer from Dut to BT client(SPP_Tx) or BT client to Dut(SPP_Rx)

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

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
            "ext_tcpip_features": 0,
            "custom_features": RS9116CustomFeatureBitMap.Default,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection
        }
    )
]

def test_bt_spp_tx_rx_data_transfer_master_mode_c20041(bt_dut, bt_client):

    send_text =text_generator()

    logger().info("configuring dut in spp master role")
    bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp()
    assert bt_dut_address, "failed to initialise bt in dut"

    logger().info(f"BT Dut address {bt_dut_address}")
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                             inquiry_duration_ms=20000, timeout=22, retry_counts=3)
    if not found:
        assert found, f"Dut unable to find the bt client device"

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_server_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_server_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_server_socket.accept(timeout=10)
            assert addr == bt_dut_address

            time.sleep(60)
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, f"Failed to ping BT client to DUT"

            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave )
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

            logger().info("Checking the BT Connection for 30 seconds")
            time.sleep(30)

            logger().info(f"Sending data from dut-SPP Tx for 60 sec")
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data, f"Dut failed to recevie data from bt client "
                assert data.decode() == send_text

            logger().info(f"Sending data from bt_client to dut-SPP Rx for 60 sec")
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                recv_text = text_generator()
                with bt_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(recv_text)
                    assert sent, f"Sending Data to the  DUT failed"
                    data_sent = bt_server_socket.recv()
                    assert data_sent
                    assert data_sent.decode() == recv_text, f"Data sent by Remote is different from data received by DUT"


def test_bt_spp_tx_remote_device_disconnect_c20046(bt_dut, bt_client):

    send_text = text_generator()

    logger().info("configuring dut in spp slave role")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address, "failed to initialise bt in dut"
    logger().info(f"BT dut address {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT Client address {bt_client_address}")

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        assert found, f"Dut was not found during the scan by bt client"

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

            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

            logger().info("Checking the BT Connection for 30 seconds")
            time.sleep(30)
            bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data,f"Dut failed to recevie data from bt client"
            assert data.decode() == send_text

            # Close connection
            bt_server_socket.close()
            time.sleep(4)

            # checking for disconnected event
            rsi_bt_on_spp_disconnect = False
            rsi_bt_on_disconn_event = False

            events = bt_dut.interfaces.bluetooth.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                        rsi_bt_on_spp_disconnect = True
                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                        rsi_bt_on_disconn_event = b"4E13" in event.event_data

            assert rsi_bt_on_spp_disconnect
            assert rsi_bt_on_disconn_event

def test_bt_spp_data_transfer_long_duration_c20048(bt_dut, bt_client):

    iter_count = 2

    send_text = text_generator()

    for count in range(0, iter_count):
        logger().info("configuring dut in spp slave role")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
        assert bt_dut_address, "failed to initialise bt in dut"
        logger().info(f"BT dut address {bt_dut_address}")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Failed to initiate master in remote device"
        logger().info(f"BT Client address {bt_client_address}")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found,f"Dut was not found during the scan by bt client"

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

                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifiPowersave, f"Failed to enable wifi in powersave"
                logger().info("==========Enables Power Save in BT Mode===========")
                enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_btPowersave, f"Failed to enable BT in Powersave"
                logger().info("Checking the BT Connection for 30 seconds")
                time.sleep(30)
                t_end = time.time() + 60 * 35
                while time.time() < t_end:
                    bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
                    data = bt_server_socket.recv()
                    assert data, f"Dut failed to recevie data from bt client"
                    assert data.decode() == send_text

        logger().info("Disconnecting bt client address")
        bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

        logger().info(f"Close Socket connection")
        bt_server_socket.close()
