import time
import pytest
from devices.rs911x import RS9116CoexMode
from interfaces.bluetooth.bluetooth_logs import BleLogs
from interfaces.cli.rs_at_commands import RSATCommands
from utils.logger import get_logger
from utils.stopwatch import Stopwatch
from utils.time_measurer import TimeMeasurer

pytestmark = [
    pytest.mark.bt_client("raspi_ble_client"),
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.Bluetooth,
        }
    )
]


def logger():
    return get_logger(__name__)


@pytest.mark.parametrize("enable_ssp", [True, False])
def test_bt_hid_dut_as_slave_ssp(wifi_dut, bt_client, enable_ssp):
    if not isinstance(wifi_dut.interfaces.wifi, RSATCommands):
        raise NotImplementedError(
            "This test case is only currently implemented for AT"
        )
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_hid(enable_ssp=enable_ssp)
        assert bt_dut_address is not None

        # Begin Scanning for BLE devices
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break

        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found

        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)

        # https://community.silabs.com/s/article/iwrap-hid-localization-country-code-x?language=en_US
        test_data = [["1,9,01,00,00,04,00,00,00,00,00", "1,9,01,00,00,00,00,00,00,00,00"],  # a, keyrelease
                     ["1,9,01,00,00,05,00,00,00,00,00", "1,9,01,00,00,00,00,00,00,00,00"],  # b, keyrelease
                     ["1,9,01,02,00,04,00,00,00,00,00", "1,9,01,02,00,00,00,00,00,00,00"],  # left Shift + a, keyrelease
                     ["1,9,01,02,00,05,00,00,00,00,00", "1,9,01,02,00,00,00,00,00,00,00"],  # left Shift + b, keyrelease
                     ["1,9,01,00,00,46,00,00,00,00,00", "1,9,01,00,00,00,00,00,00,00,00"]]  # =, keyrelease

        with BleLogs() as btlogs:
            btlogs.collect_logs()
            time.sleep(1)
            for item in test_data:
                wifi_dut.interfaces.wifi.bt_hid_send_interrupt(bt_client_address, data=item)
            time.sleep(1)

        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    logger().info(f"Scan in {t.duration} seconds")
