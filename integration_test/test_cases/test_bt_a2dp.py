import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116BTFeatureBitMap
import time
import os

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.firmware_app('test_bt_a2dp'),
    pytest.mark.dut("rs9116_sapi"),
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
    pytest.mark.skip
]

@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
@pytest.mark.test_src_map_id('SM11825')
def test_bt_a2dp_dut_as_src(firmware_loader, wifi_dut, wifi_access_point, bt_client, logger):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    capture_file_path = "/tmp/a2dp_capture_test_bt_a2dp_dut_as_src.wav"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(
            bt_dut_address=bt_dut_address, pin_code=pin_code
        )
        assert bt_client_address is not None

        # A2DP Connection
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
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )

        # Start capturing audio
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(
            capture_file_path
        )

        # A2DP SBC Audio streaming to Raspi
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(5)

        # disconnect
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

        # assert the captured audio size
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(
            capture_file_path
        )
        logger.info(f"captured_audio_size : {captured_audio_size}")
        assert int(captured_audio_size / 100000) >= 1
    logger.info(f"Scan in {t.duration} seconds")


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
@pytest.mark.test_src_map_id('SM11829')
def test_bt_avrcp_dut_as_src(firmware_loader, wifi_dut, wifi_access_point, bt_client, logger):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    capture_file_path = "/tmp/a2dp_capture_test_bt_avrcp_dut_as_src.wav"
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp(enable_avrcp=True)
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
        assert bt_client_address is not None

        #A2DP Connection
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
        time.sleep(1)
        bt_client.interfaces.bluetooth.bt_media_player.stop(bt_dut_address)
        time.sleep(3)

        #assert the captured audio size
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger.info(f"captured_audio_size : {captured_audio_size}")
        assert int(captured_audio_size/100000) >= 1
    logger.info(f"Scan in {t.duration} seconds")
