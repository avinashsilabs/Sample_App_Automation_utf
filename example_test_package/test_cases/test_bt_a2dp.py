import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116BTFeatureBitMap
import time

def logger():
    return get_logger(__name__)

@pytest.mark.config(
    "wifi_dut",
    wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "bt_features": RS9116BTFeatureBitMap.Default |
                           RS9116BTFeatureBitMap.A2DPProfileEnable |
                           RS9116BTFeatureBitMap.A2DPSourceRoleEnable
        }
)
def test_bt_a2dp_dut_as_src(wifi_dut, wifi_access_point, bt_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
        assert bt_client_address is not None

        #A2DP Connection
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(5)

        #Power save
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        wifi_dut.interfaces.wifi.power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        #disconnect
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")