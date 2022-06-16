import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116ExtCustomFeatureBitMap
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
                "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                                       RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid
            }
    )
]


def logger():
    return get_logger(__name__)


def test_bt_spp_dut_as_slave(wifi_dut, wifi_access_point, bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

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

            # Close connection
            bt_server_socket.close()
            time.sleep(2)
            wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")


def test_bt_spp_dut_as_slave_spp_disconnect(wifi_dut, wifi_access_point, bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
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
            logger().info("================================")
            # Close connection
            bt_server_socket.close() #TODO : check different disconnect method to close only SPP
            time.sleep(4)
            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            time.sleep(2)
            wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")

def test_bt_spp_dut_as_slave_spp_disconnect(wifi_dut, wifi_access_point, bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
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
            # Close connection
            start_capture_time = time.perf_counter_ns()
            bt_server_socket.close() 
            time.sleep(4)        
            # cheking for disconnected event 
            rsi_bt_on_spp_disconnect = False
            rsi_bt_on_disconn_event = False
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=start_capture_time)
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                        rsi_bt_on_spp_disconnect = b"resp_status: 0x0" in event.event_data
                       
                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                        rsi_bt_on_disconn_event = b"resp_status: 0x4E13" in event.event_data
                        
            assert rsi_bt_on_spp_disconnect
            assert rsi_bt_on_disconn_event
            
            # Send data from dut to bt_client after closing socket
            with pytest.raises(WlanError) as exc_info:
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                assert exc_info.value.error_code == 0x4500, "SPP Not Connected, expected is 0x4500"

            
            wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")

def test_bt_spp_dut_as_master(wifi_dut, wifi_access_point, bt_client):
    send_text = "sA0L9b1xEgGuUqN5YOlx"
    recv_text = "H2D7yZKRhKULU9Xil5Yv"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None
        time.sleep(1)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=2,
                                                              inquiry_duration_ms=20000,
                                                              timeout=22,
                                                              retry_counts=3)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                    (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

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

            # Close connection
            bt_client_socket.close()
            time.sleep(2)
            wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")


def test_bt_spp_dut_as_slave_wrong_pin(wifi_dut, wifi_access_point, bt_client):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp(bt_pin_code="1234")
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code="9876")
        assert bt_client_address is not None

        bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                time.sleep(1)
                assert not connected
            bt_server_socket.close()

        recieved_authentication_failure = False
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    recieved_authentication_failure = b"4E05" in event.event_data
                    break
        assert recieved_authentication_failure
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")


def test_bt_spp_dut_as_master_wrong_pin(wifi_dut, wifi_access_point, bt_client):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp(bt_pin_code="1234")
        assert bt_dut_address is not None
        time.sleep(0.5)

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="9876")
        assert bt_client_address is not None
        time.sleep(1)

        wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                       inquiry_type=2,
                                                       inquiry_duration_ms=20000,
                                                       timeout=22,
                                                       retry_counts=3)

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
                assert result[1] is None
            bt_client_socket.close()

        recieved_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    recieved_authentication_failure = b"4E05" in event.event_data
                    break
        assert recieved_authentication_failure
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")