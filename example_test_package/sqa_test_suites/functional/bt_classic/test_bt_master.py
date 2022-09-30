import pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from datetime import datetime, timedelta
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
import time
import random
import string
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116OperatingMode,
    RS9116Band,
    RS9116BTFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116AsyncEventType,
    RS9116PowerSaveProcedureTypes
)

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

    Author: RaviNemali and Harshitha
"""

def logger():
    return get_logger(__name__)

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
]

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(100, 100, 5, 3)])
def test_bt_physical_level_conn_master_mode_C20070(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_master_spp()
    assert bt_dut_address, f"failed to initialise bt in dut"
    logger().info(f"BT Dut address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
    assert bt_client_address, f"bt initialization failed on remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                         inquiry_duration_ms=20000, timeout=22, retry_counts=3)
    if not found:
        assert found, f"BT DUT is unable to inquiry, So Could not find bt client address {bt_client_address} during inquiry"

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_client_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=30)
            assert addr == bt_dut_address, f"failed to connect to bt dut"

            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            time.sleep(2)
            bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                          sniff_max_interval=sniff_max_interval,
                                                          sniff_min_interval=sniff_min_interval,
                                                          sniff_attempt=sniff_attempt,
                                                          sniff_tout=sniff_time_out)

            events = bt_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_MODE_CHANGED:
                    sniff_data = event.event_data
                    logger().info(f"Recevied Mode Change Event {sniff_data}")

            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    bt_client_socket.close()

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(100, 100, 5, 3)])
def test_bt_master_ssp_displayonly_C20071(bt_dut, bt_client , sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_master_ssp_display(pair_mode="1", capability="0")
    assert bt_dut_address, f"bt initialization failed on dut"
    logger().info(f"BT Dut address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayOnly")
    assert bt_client_address, f"bt initialization failed on remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                         inquiry_duration_ms=20000, timeout=22, retry_counts=3)
    if not found:
        assert found, f"BT DUT is unable to inquiry, So Could not find bt client address {bt_client_address} during inquiry"

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_client_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=10)
            assert addr == bt_dut_address, f"failed to connect to bt dut"

            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            time.sleep(2)
            bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                          sniff_max_interval=sniff_max_interval,
                                                          sniff_min_interval=sniff_min_interval,
                                                          sniff_attempt=sniff_attempt,
                                                          sniff_tout=sniff_time_out)

            events = bt_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_MODE_CHANGED:
                    sniff_data = event.event_data
                    logger().info(f"Recevied Mode Change Event {sniff_data}")

            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

            logger().info(f"Sending data from bt_client to dut for 60 sec")
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                recv_text = text_generator()
                with bt_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(recv_text)
                assert sent, "Sending Data to the DUT failed"
                data_sent = bt_client_socket.recv()
                assert data_sent
                assert data_sent.decode() == recv_text, 'Data sent by Remote is different from data received by DUT'

    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    bt_client_socket.close()

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(100, 100, 5, 3)])
def test_bt_master_spp_connection_DataTransfer_DisplayYesNo_C43168(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    send_text = text_generator()

    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_master_ssp_display(pair_mode="1", capability="1")
    assert bt_dut_address, f"failed to initialise bt in dut"
    logger().info(f"BT DUT address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayYesNo")
    assert bt_client_address, f"failed to initialise bt on remote device"
    logger().info(f"BT Client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                         inquiry_duration_ms=20000, timeout=22, retry_counts=3)
    if not found:
        assert found, f"BT DUT is unable to inquiry, So Could not find bt client address {bt_client_address} during inquiry"
    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_client_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=10)
            assert addr == bt_dut_address, f"failed to connect to bt dut"

            # Ping DUT
            time.sleep(60)
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response, f"Failed to ping BT client to DUT"

            time.sleep(2)

            bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                          sniff_max_interval=sniff_max_interval,
                                                          sniff_min_interval=sniff_min_interval,
                                                          sniff_attempt=sniff_attempt,
                                                          sniff_tout=sniff_time_out)

            events = bt_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_MODE_CHANGED:
                    sniff_data = event.event_data
                    logger().info(f"Recevied Mode Change Event {sniff_data}")


            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

           # Data will transfer 60 Seconds
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                # Send the data from dut to bt client
                bt_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data, "failed to recevie data from dut to bt client "
                assert data.decode() == send_text

    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    bt_client_socket.close()

@pytest.mark.parametrize("sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out", [(100, 100, 5, 3)])
def test_bt_master_spp_connection_DataTransfer_KeyboardOnly_C43169(bt_dut, bt_client, sniff_max_interval, sniff_min_interval, sniff_attempt, sniff_time_out):

    send_text = text_generator()

    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_master_ssp_display(pair_mode="1", capability="2")
    assert bt_dut_address, "failed to initialise bt in dut"
    logger().info(f"BT DUT address is{bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="KeyboardOnly")
    assert bt_client_address, "failed to initialise bt on remote device"
    logger().info(f"BT Client address is {bt_client_address}")

    found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                         inquiry_duration_ms=20000, timeout=22, retry_counts=3)

    logger().info(f"BT found device is {found}, found bt client address {bt_client_address}")
    if not found:
        assert found, f"BT DUT is unable to inquiry, So Could not find bt client address {bt_client_address} during inquiry"

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        with bt_dut.interfaces.bluetooth.run_bt_task():
            bt_client_socket.create_client()
            bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=10)
            assert addr == bt_dut_address, f"failed to connect to bt dut"

            # Ping DUT
            time.sleep(60)
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info(f"l2ping response {ping_response}")
            assert ping_response,  f"Failed to ping BT client to DUT"

            time.sleep(2)
            bt_dut.interfaces.bluetooth.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                          sniff_max_interval=sniff_max_interval,
                                                          sniff_min_interval=sniff_min_interval,
                                                          sniff_attempt=sniff_attempt,
                                                          sniff_tout=sniff_time_out)

            events = bt_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_MODE_CHANGED:
                    sniff_data = event.event_data
                    logger().info(f"Recevied Mode Change Event {sniff_data}")

            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifiPowersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifiPowersave, f"Failed to enable wifi in powersave"

            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btPowersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_btPowersave, f"Failed to enable BT in Powersave"

            # Data will transfer 60 Seconds
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                # Send the data from dut to bt client
                bt_dut.interfaces.bluetooth.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data, f"failed to recevie data from dut to bt client"
                assert data.decode() == send_text

    bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

    bt_client_socket.close()

def test_bt_master_with_wrong_pin_c20074(bt_dut, bt_client):

    logger().info("configuring dut in spp master role")
    bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_master_spp(bt_pin_code="1234")
    assert bt_dut_address, f"failed to initialise bt in dut"
    logger().info(f"BT Dut address {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="4554")
    assert bt_client_address, f"Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    bt_dut.interfaces.bluetooth.bt_inquiry_for_device(bt_client_address=bt_client_address,inquiry_type=2,inquiry_duration_ms=10000,
                                                        max_device_cnt=10, timeout=22, retry_counts=3)

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        logger().info("**** SPP Connection ****")
        with bt_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(bt_dut.interfaces.bluetooth.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
            assert result[1] is None
        bt_client_socket.close()

    recieved_authentication_failure = False
    time.sleep(1)
    events = bt_dut.interfaces.bluetooth.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                recieved_authentication_failure = b"4E05" in event.event_data
                break
    assert recieved_authentication_failure, f"Received authentication failure"