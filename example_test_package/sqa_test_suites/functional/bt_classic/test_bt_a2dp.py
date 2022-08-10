import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116BTFeatureBitMap
from utf.utils.logger import get_logger
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
import time
from datetime import datetime

""" Test-Plan:BT_A2DP
    Test-Author:M.Harshitha   
    Test Steps:
        1. Configure DUT in a2dp Initiator_Role
        2. Configure remote BT headset in advertise mode
        3. Start BT inquiry with RSSI from DUT
        4. start capturing audio with AVRCP Play,Pause,Volume UP,Volume Down,Next,Previous
        5. Check if music streaming starts and successful
        5. Capturing the size of audio file
    Setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "bt_features": RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        },
    ),
]

def logger():
    return get_logger(__name__)

# BT_inquiry inputs
inquiry_type = 2
inquiry_duration_ms = 20000
timeout = 22

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable","bt_power_save_disable","bt_disconnect"])
def test_bt_a2dp_simple_play_C20054(wifi_dut, bt_client):
    current_time = time.time()
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_dut_simple_play_C20054.wav" + '_' + str(
    datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

    logger().info("========Configure DUT in a2dp Initiator_Role===============")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
    assert bt_dut_address, "failed to initialise bt in dut "
    logger().info(f"BT Dut address {bt_dut_address}")

    logger().info("==========Configure Raspberry pi device as sink===========")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address, "Failed to initiate sink in remote device "
    logger().info(f"BT Client address {bt_client_address}")

    time.sleep(10)
    logger().info("Searching for the bt client address")
    device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(
        bt_client_address=bt_client_address,
        inquiry_type=inquiry_type,
        inquiry_duration_ms=inquiry_duration_ms,
        timeout=timeout,
        retry_counts=3,
    )
    if device_found == True:
        logger().info(f"BT found device is {device_found}, BT address {bt_client_address} are found")

        logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        time.sleep(10)

        logger().info("======= Initiating the Power Save==========")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifipowersave = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifipowersave, "Failed to enable wifi power save"
            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btpowersave = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_btpowersave, "Failed to enable BT power save"
        time.sleep(10)
        ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info(f"l2ping response {ping_response}")
        assert ping_response, "dut is in inactive state..."

        # Start capturing audio
        logger().info("==============Start Capturing audio================")
        capture = bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        assert capture, "capture is empty"

        # # A2DP SBC Audio streaming to Raspi
        logger().info("==============Start A2DP SBC Audio streaming from DUT to Raspberry===========")
        audio_streaming = wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        assert audio_streaming, "Failed audio streaming"

        # assert the captured audio size
        logger().info("============Capturing the size of audio file=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert captured_audio_size != 0, "captured size is zero"
    else:
        logger().info(f"BT found device is {device_found}, BT address {bt_client_address} are not found")
        assert device_found, "Dut unable to find the bt client address, test case may stop execution"

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable","bt_power_save_disable", "bt_disconnect"])
def test_a2dp_arvcp_functional_C20060(wifi_dut, bt_client):
    current_time = time.time()
    capture_file_path = "./reports/a2dp_capture_test_bt_avrcp_functional_C20060.wav" + '_' + str(
    datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

    logger().info("========Configure DUT in a2dp Initiator_Role==========")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp(enable_avrcp=True)
    assert bt_dut_address, "failed to initialise bt in dut"
    logger().info(f"BT Dut address {bt_dut_address}")

    logger().info("==========Configure Raspberry pi device as sink==========")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address, "Failed to initiate sink in remote device "
    logger().info(f"BT Client address {bt_client_address}")

    time.sleep(10)
    device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(
        bt_client_address=bt_client_address,
        inquiry_type=inquiry_type,
        inquiry_duration_ms=inquiry_duration_ms,
        timeout=timeout,
        retry_counts=3,
    )
    if device_found == True:
        logger().info(f"BT found device is {device_found}, found bt client address {bt_client_address}")

        logger().info("=============Initiating BT Connection and followed by A2DP Connection============")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        time.sleep(10)

        logger().info("======= Initiating the Power Save==========")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifipowersave = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifipowersave, "Failed to enable wifi power save"
            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btpowersave = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_btpowersave, "Failed to enable BT power save"

        time.sleep(10)
        ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info(f"l2ping response {ping_response}")
        assert ping_response, "dut is in inactive state..."

        # Start capturing audio
        logger().info("=======Start Capturing audio==========")
        capture = bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        assert capture, "capture is empty"

        # Playback and volume control from Raspi
        logger().info("===========AVRCP Play==========")
        bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
        time.sleep(1)
        logger().info("==========AVRCP Pause==========")
        bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)
        time.sleep(1)
        logger().info("========AVRCP Play========")
        bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
        time.sleep(1)
        logger().info("=========AVRCP Volume down===========")
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=8)
        logger().info("========AVRCP Next===========")
        bt_client.interfaces.bluetooth.bt_media_player.next(bt_dut_address)
        time.sleep(1)
        logger().info("===========AVRCP Previous============")
        bt_client.interfaces.bluetooth.bt_media_player.previous(bt_dut_address)
        time.sleep(1)
        logger().info("============AVRCP Volume up===============")
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=127)
        time.sleep(1)
        logger().info("===========AVRCP Pause============")
        bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)
        time.sleep(10)

        # assert the captured audio size
        logger().info("==========Capturing audio size=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert captured_audio_size != 0, "captured size is zero"
    else:
        logger().info(f"BT found device is {device_found}, BT address {bt_client_address} are not found")
        assert device_found, "Dut unable to find the bt client address, test case may stop execution"

@pytest.mark.skip("This test case is skipped for now due to facing an issue while Capturing audio size")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable","bt_power_save_disable"])
def test_bt_a2dp_repair_functionality_C20059(wifi_dut, bt_client):
    current_time = time.time()
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_repair_functionality_C20059.wav"+ '_' + str(
    datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

    logger().info("========Configure DUT in a2dp Initiator_Role===============")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
    assert bt_dut_address, "failed to initialise bt in dut"
    logger().info(f"BT Dut address {bt_dut_address}")

    logger().info("===========Configure Raspberry pi device as sink===========")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address, "Failed to initiate sink in remote device"
    logger().info(f"BT Client address {bt_client_address}")
    time.sleep(10)
    device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(
        bt_client_address=bt_client_address,
        inquiry_type=inquiry_type,
        inquiry_duration_ms=inquiry_duration_ms,
        timeout=timeout,
        retry_counts=3,
    )
    if device_found == True:
        logger().info(f"BT found device is {device_found}, found bt client address {bt_client_address}")
        time.sleep(5)
        logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        time.sleep(10)

        logger().info("======= Initiating the Power Save==========")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifipowersave = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifipowersave, "Failed to enable wifi power save"
            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btpowersave = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_btpowersave, "Failed to enable BT power save"

        time.sleep(10)

        ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info(f"l2ping response {ping_response}")
        assert ping_response, "dut is in inactive state..."

        logger().info("==========Start Capturing audio=============")
        capture = bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        assert capture, "capture is empty"

        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        audio_streaming = wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        assert audio_streaming, "Failed audio streaming"

        time.sleep(5)

        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address, timeout=70)

        time.sleep(80)

        logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address, timeout=60)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        time.sleep(15)
        logger().info("==========Start Capturing audio=============")
        capture = bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        assert capture, "capture is empty"

        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        audio_streaming = wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        assert audio_streaming, "Failed audio streaming"

        time.sleep(10)
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert captured_audio_size != 0, "Capture size is zero"
    else:
        logger().info(f"BT found device is {device_found}, BT address {bt_client_address} are not found")
        assert device_found, "Dut unable to find the bt client address, test case may stop execution"

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable","bt_power_save_disable", "bt_disconnect"])
def test_bt_a2dp_power_cycle_C20057(wifi_dut, bt_client):
    current_time = time.time()
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_dut_power_play_C20057.wav" + '_' + str(
    datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

    logger().info("============Configure DUT in a2dp Initiator_Role=============")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
    assert bt_dut_address, "failed to initialise bt in dut "
    logger().info(f"BT Dut address {bt_dut_address}")

    logger().info("==========Configure Raspberry pi device as sink==============")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address, "Failed to initiate sink in remote device"
    logger().info(f"BT Client address {bt_client_address}")
    time.sleep(10)
    device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(
        bt_client_address=bt_client_address,
        inquiry_type=inquiry_type,
        inquiry_duration_ms=inquiry_duration_ms,
        timeout=timeout,
        retry_counts=3,
    )
    if device_found == True:
        logger().info(f"BT found device is {device_found}, found bt client address {bt_client_address}")

        logger().info("=============Initiating BT Connection and followed by A2DP Connection============")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        time.sleep(10)

        logger().info("======= Initiating the Power Save==========")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            logger().info("==========Enables Power Save in Wifi Mode===========")
            enable_wifipowersave = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifipowersave, "Failed to enable wifi power save"
            logger().info("==========Enables Power Save in BT Mode===========")
            enable_btpowersave = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_btpowersave, "Failed to enable BT power save"

        time.sleep(10)
        # Ping dut
        ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info(f"l2ping response {ping_response}")
        assert ping_response, "dut is in inactive state..."

        # Start capturing audio
        logger().info("==========Start Capturing audio=============")
        capture = bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        assert capture, "capture is empty"

        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        audio_streaming = wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        assert audio_streaming, "Failed audio streaming"

        time.sleep(4)

        logger().info("===========reset soft==========")
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(80)
        logger().info("======init===============")
        wifi_dut.interfaces.wifi.init()
        time.sleep(10)
        logger().info("============Configure DUT in a2dp Initiator_Role=============")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address, "failed to initialise bt in dut"
        logger().info(f"BT Dut address {bt_dut_address}")

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                       pin_code=pin_code)
        assert bt_client_address, "Failed to initiate sink in remote device"
        logger().info(f"BT Client address {bt_client_address}")

        logger().info("==============Initiating BT Connection and followed by A2DP Connection===============")
        connected = wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

        # A2DP SBC Audio streaming to Raspi
        logger().info("==============Start A2DP SBC Audio streaming from DUT to Raspberry===========")
        audio_streaming = wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        assert audio_streaming, "Failed audio streaming"
        time.sleep(10)
        # assert the captured audio size
        logger().info("============Capturing the size of audio file=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert captured_audio_size != 0, "Captured size is zero"
    else:
        logger().info(f"BT found device is {device_found}, BT address {bt_client_address} are not found")
        assert device_found, "Dut unable to find the bt client address, test case may stop execution"
