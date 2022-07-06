import pytest

from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116ExtCustomFeatureBitMap,
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.time_measurer import TimeMeasurer
import time

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("dlink810_ap"),
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
            | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        },
    ),
]


def test_bt_spp_dut_as_slave(wifi_dut, wifi_access_point, bt_client, logger):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(
            bt_dut_address, pin_code
        )
        assert bt_client_address is not None

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(
            bt_dut_address, duration=20, retry_counts=3
        )
        if not found:
            logger.error(
                f"Dut was not found during the scan by bt client. The test case may fail."
            )

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(
                    dest_mac_addr=bt_dut_address, retry_counts=3
                )
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

            wifi_dut.interfaces.wifi.leave()
            time.sleep(1)
            bt_server_socket.close()
    logger.info(f"Scan in {t.duration} seconds")


def test_bt_spp_dut_as_master(wifi_dut, wifi_access_point, bt_client, logger):
    send_text = "sA0L9b1xEgGuUqN5YOlx"
    recv_text = "H2D7yZKRhKULU9Xil5Yv"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(
            bt_dut_address, pin_code
        )
        assert bt_client_address is not None
        time.sleep(1)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(
            bt_client_address=bt_client_address,
            inquiry_type=2,
            inquiry_duration_ms=20000,
            timeout=22,
            retry_counts=3,
        )
        if not found:
            logger.error(
                f"Dut unable to find the bt client device. The test case may fail."
            )

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                        (bt_client_socket.accept, 20),
                    ]
                )
                assert result[1] == bt_dut_address
                logger.info(f"Result from Callable Function {result}")

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
                sent = bt_client_socket.send(
                    recv_text
                )  # Dut is programmed to send back data
                assert sent
                data = bt_client_socket.recv()
                assert data is not None
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data is not None
            assert data.decode() == send_text

            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            wifi_dut.interfaces.wifi.leave()
            time.sleep(1)
            bt_client_socket.close()
    logger.info(f"Scan in {t.duration} seconds")
