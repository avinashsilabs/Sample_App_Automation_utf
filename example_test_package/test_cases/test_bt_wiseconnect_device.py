import time

import pytest

from utf_wiseconnect.devices.rs911x import RS9116CoexMode


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.dut("rs9116_sapi_by_serial")
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.bt_client("bt_wiseconnect")
def test_bluetooth_with_wiseconnect_as_bt_client(bt_client, wifi_dut, wifi_access_point, logger):
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address is not None
    logger.info(f"Bt device address: {bt_client_address}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
    logger.info(f"DUT device address: {bt_dut_address}")
    assert bt_dut_address is not None

    # connecting from DUT
    connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
    logger.info(f'device connection state is {connected}')
    time.sleep(5)

    # disconnecting from DUT
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address, timeout=5)




