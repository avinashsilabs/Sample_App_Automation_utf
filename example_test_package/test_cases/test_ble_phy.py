import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116AsyncEventType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError


#TODO : It looks like Raspi does not support LE PHY or other optional bluetooth features.
########## Current BTMon logs looks like
# < HCI Command: LE Set PHY (0x08|0x0032) plen 7        #3 [hci0] 20:27:04.015097
#         Handle: 64
#         All PHYs preference: 0x00
#         TX PHYs preference: 0x02
#           LE 2M
#         RX PHYs preference: 0x02
#           LE 2M
#         PHY options preference: S2 coding (0x0001)
# > HCI Event: Command Complete (0x0e) plen 4           #4 [hci0] 20:27:04.015432
#       LE Set PHY (0x08|0x0032) ncmd 1
#         Status: Unknown HCI Command (0x01)
# @ RAW Close: hcitool                            {0x0003} [hci0] 20:27:04.015486
# @ RAW Open: hcitool (privileged) version 2.22          {0x0003} 20:27:04.043516
# @ RAW Close: hcitool                                   {0x0003} 20:27:04.043591
# @ RAW Open: hcitool (privileged) version 2.22          {0x0003} 20:27:04.072328
# @ RAW Close: hcitool                                   {0x0003} 20:27:04.072354
# @ RAW Open: hcitool (privileged) version 2.22          {0x0003} 20:27:04.072389
# @ RAW Close: hcitool                                   {0x0003} 20:27:04.072399
# @ RAW Open: hcitool (privileged) version 2.22   {0x0003} [hci0] 20:27:04.072438
# < HCI Command: LE Read PHY (0x08|0x0030) plen 2       #5 [hci0] 20:27:04.072630
#         Handle: 64
# > HCI Event: Command Complete (0x0e) plen 4           #6 [hci0] 20:27:04.072941
#       LE Read PHY (0x08|0x0030) ncmd 1
#         Status: Unknown HCI Command (0x01)
#
########### Ideally they should look like
# < HCI Command: LE Set PHY (0x08|0x0032) plen 7
# 		Handle: 0
# 		All PHYs preference: 0x00
# 		TX PHYs preference: 0x02
# 		  LE 2M
# 		RX PHYs preference: 0x02
# 		  LE 2M
# 		PHY options preference: Reserved (0x0000)
# > HCI Event: Command Status (0x0f) plen 4
# 	  LE Set PHY (0x08|0x0032) ncmd 1
# 		Status: Success (0x00)
# > HCI Event: LE Meta Event (0x3e) plen 6
# 	  LE PHY Update Complete (0x0c)
# 		Status: Success (0x00)
# 		Handle: 0
# 		TX PHY: LE 2M (0x02)
# 		RX PHY: LE 2M (0x02)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
# def test_ble_scanning_phy(wifi_dut, wifi_access_point, ble_client):
def test_ble_scanning_phy(wifi_dut, ble_client, logger):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    with BleLogs(start_collecting_logs=True, bt_log_path=f"./reports/test_ble_scanning_phy.log") as ble_logs:

        rc, result = ble_client.interfaces.bluetooth.hci_tool_manager.read_phy(bt_dut_address)
        logger.info(f"PHY : {result.decode().splitlines()[-1]}")

        ble_client.interfaces.bluetooth.hci_tool_manager.set_phy(bt_dut_address, "00 02 02 00 00")

        rc, result = ble_client.interfaces.bluetooth.hci_tool_manager.read_phy(bt_dut_address)
        logger.info(f"PHY : {result.decode().splitlines()[-1]}")

        #TODO if the set phy command worked then we should look for "LE PHY Update Complete " in logs

        time.sleep(2)

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected