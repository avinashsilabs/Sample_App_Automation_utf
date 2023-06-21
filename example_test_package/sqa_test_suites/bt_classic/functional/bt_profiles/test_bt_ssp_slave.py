import pytest
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
import random
import string
from datetime import datetime, timedelta
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
    RS9116AsyncEventType,
    RS9116ExtTCPIPFeatureBitMap
)

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
                "features": RS9116FeatureBitMap.ULPGPIOHandshake,
                "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.TCPIPBypass,
                "ext_tcpip_features": 0,
                "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
                "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
                "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            }
    )
]


'''=============================== DUT AS SLAVE TEST CASES ================================='''

# This test case verifies the spp connection in slave mode
def test_bt_physical_level_conn_slave_c19958(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address ,"failed to initialise bt in dut"

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Failed to initiate master in remote device"

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


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_slave_spp_displayonly_data_transfer_c19959(wifi_dut, bt_client):

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_slave_ssp_display(pair_mode="1", capability="1")
    assert bt_dut_address, "failed to initialise bt in dut"
    logger().info(f"BT dut address is {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code, ssp=1)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT client address is {bt_client_address}")

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        assert found, "Dut was not found during the scan by bt client"

    bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
    with wifi_dut.interfaces.wifi.run_bt_task():
        bt_server_socket.create_server()
        connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
        assert connected, "failed to connect to bt dut"

    ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
    assert ping_response, f"Failed to ping BT client to DUT"
    logger().info(f"l2ping response {ping_response}")

    logger().info("==========Enables Power Save in Wifi Mode===========")
    enable_wifiPowersave = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifiPowersave, "Failed to enable wifi in powersave"

    logger().info("==========Enables Power Save in BT Mode===========")
    enable_btPowersave = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_btPowersave, "Failed to enable BT in Powersave"

    logger().info("Checking the BT Connection for 30 seconds")
    time.sleep(30)

    logger().info(f"Sending data from bt_client to dut-SPP Rx for 60 sec")
    end_time = datetime.now() + timedelta(seconds=60)
    while datetime.now() < end_time:
        recv_text = text_generator()
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)
            assert sent, f"Sending Data to the DUT failed"
            data_sent = bt_server_socket.recv()
            assert data_sent
            assert data_sent.decode() == recv_text, f"Data sent by Remote is different from data received by DUT"

    # Close connection
    bt_server_socket.close()
    time.sleep(0.2)
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
