
import time
import pytest
from paramiko.util import log_to_file

from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.utils.logger import get_logger


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "bt_vulnerability_sniffer",
    bt_vulnerability_sniffer={
        "bt_exploit_type": "au_rand_flooding"
    },
)
def test_bt_vulnerability_sniffer(
    wifi_dut, bt_client, wifi_access_point, bt_vulnerability_sniffer, logger
):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=f"reports/test_ble_vul_sniffer.log_{int(time.time())}"
    )

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address is not None

    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected

        # Initiating power save
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            wifi_dut.interfaces.wifi.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            wifi_dut.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
            )

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(
                recv_text
            )  # SQA Agent is programmed to send back data
            assert sent
            data = bt_server_socket.recv()
            assert data is not None
            assert data.decode() == recv_text

        # Send data from dut to bt_client
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data is not None
        assert data.decode() == send_text

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )

        # Close connectiontest_bt_spp.py
        bt_server_socket.close()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()

    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
