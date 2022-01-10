import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_at_commands import RSATCommands
from utils.logger import get_logger
from utils.stopwatch import Stopwatch
from utils.time_measurer import TimeMeasurer
import time

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

def test_bt_hid_dut_as_slave_ssp(wifi_dut, bt_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSATCommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    with TimeMeasurer() as t:

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_hid(enable_ssp=True)
        assert bt_dut_address is not None

        bt_dut_address = "80:C9:55:B9:EF:DC"

        # Begin Scanning for BLE devices
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                break
        else:
            logger.error(f"Unable to find device {bt_dut_address} within 30 sec.")
        bt_client.interfaces.bluetooth.stop_scanning()

        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client.interfaces.bluetooth.connect(bt_dut_address)

        logger().info(f"Sleeping")
        time.sleep(15)

        wifi_dut.interfaces.wifi.bt_hid_send_interrupt(bt_client_address,
                                                       data_arr=["01", "00", "00", "05", "00", "00", "00", "00", "00"])
        wifi_dut.interfaces.wifi.bt_hid_send_interrupt(bt_client_address,
                                                       data_arr=["01", "00", "00", "00", "00", "00", "00", "00", "00"])

        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    logger().info(f"Scan in {t.duration} seconds")