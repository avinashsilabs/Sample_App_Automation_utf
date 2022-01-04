import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116BTFeatureBitMap
import time
import os

def logger():
    return get_logger(__name__)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "bt_features": RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        },
    ),
]


def test_bt_a2dp_dut_as_src(wifi_dut, wifi_access_point, bt_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    capture_file_path = "./a2dp_capture_test_bt_a2dp_dut_as_src.wav"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
        assert bt_client_address is not None

        #A2DP Connection
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address, expect="")
        time.sleep(0.5)
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )

        #Start capturing audio
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)

        # A2DP SBC Audio streaming to Raspi
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(3)

        #Power save
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        wifi_dut.interfaces.wifi.power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
        )

        #disconnect
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

        # assert the captured audio size
        captured_audio_size = os.path.getsize(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert 5 <= int(captured_audio_size / 100000) <= 6
    logger().info(f"Scan in {t.duration} seconds")


def test_bt_avrcp_dut_as_src(wifi_dut, wifi_access_point, bt_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    capture_file_path = "./a2dp_capture_test_bt_avrcp_dut_as_src.wav"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp(enable_avrcp=True)
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
        assert bt_client_address is not None

        #A2DP Connection
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address, expect="")
        time.sleep(0.5)
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )

        #Start capturing audio
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)

        # Playback and volume control from Raspi
        bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=7)
        bt_client.interfaces.bluetooth.bt_media_player.next(bt_dut_address)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=60)
        bt_client.interfaces.bluetooth.bt_media_player.previous(bt_dut_address)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=127)
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)

        #Power save
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        wifi_dut.interfaces.wifi.power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
        )

        #disconnect
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

        #assert the captured audio size
        captured_audio_size = os.path.getsize(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert 8 <= int(captured_audio_size/100000) <= 11
    logger().info(f"Scan in {t.duration} seconds")