import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf_wiseconnect.interfaces.cli.rs_at_commands import RSATCommands
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer

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


@pytest.mark.parametrize("enable_ssp", [True, False])
def test_bt_hid_dut_as_slave(wifi_dut, bt_client, logger, enable_ssp):
    if not isinstance(wifi_dut.interfaces.wifi, RSATCommands):
        raise NotImplementedError(
            "This test case is only currently implemented for AT"
        )

    # https://community.silabs.com/s/article/iwrap-hid-localization-country-code-x?language=en_US
    # Page 53 of https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf
    test_data = ["9,01,00,00,04,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",  # a, keyrelease
                 "9,01,00,00,05,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",  # b, keyrelease
                 "9,01,02,00,04,00,00,00,00,00", "9,01,02,00,00,00,00,00,00,00",  # L-Shift + a, keyrelease
                 "9,01,02,00,05,00,00,00,00,00", "9,01,02,00,00,00,00,00,00,00",  # L-Shift + b, keyrelease
                 "9,01,00,00,2e,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",  # =, keyrelease
                 "9,01,00,00,3a,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00"]  # F1, keyrelease

    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_hid(enable_ssp=enable_ssp)
        assert bt_dut_address is not None

        # Begin Scanning for BLE devices
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
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
            connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            assert connected

        with HidRecorder() as hid_recorder:
            for item in test_data:
                wifi_dut.interfaces.wifi.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data)
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i]

        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    logger.info(f"Scan in {t.duration} seconds")