import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116BTFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
import os

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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "bt_features": RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        },
    ),
]

def logger():
    return get_logger(__name__)

def test_bt_a2dp_simple_play_C20054(wifi_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    event_data = ""
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_dut_simple_play_C20054.wav"
    with TimeMeasurer() as t:
        logger().info("========Configure DUT in a2dp Initiator_Role===============")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None
        logger().info("===========Configure Raspberry pi device as sink===========")
        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
        assert bt_client_address is not None
        logger().info(f'Start BT inquiry with RSSI from DUT')
        wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
        time.sleep(duration / 1000)
        # Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0
        # Search for Inquiry type and Remote BT device address
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            if bt_client_address in event_data:
                logger().info(f'Remote BT address found ==> {bt_client_address}')
                break
        logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)
        # Ping dut
        logger().info("=========Invoke the L2ping===========")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        #Start capturing audio
        logger().info("==============Start Capturing audio================")
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        # A2DP SBC Audio streaming to Raspi
        logger().info("==============Start A2DP SBC Audio streaming from DUT to Raspberry===========")
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(3)
        # assert the captured audio size
        logger().info("============Capturing the size of audio file=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        # So here we are getting the captured audio size in bytes that is divided into 1 lakh to get in MB
        # here we are checking the size in between 5 to 6 MB , 5 is Minimum and 6 is Maximum
        assert 5 <= int(captured_audio_size / 100000) <= 6
    logger().info(f"Test case executed in {t.duration} seconds")

def test_a2dp_arvcp_functional_C20060(wifi_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    event_data = ""
    capture_file_path = "./reports/a2dp_capture_test_bt_avrcp_functional_C20060.wav"
    with TimeMeasurer() as t:
        logger().info("========Configure DUT in a2dp Initiator_Role==========")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp(enable_avrcp=True)
        assert bt_dut_address is not None
        logger().info("==========Configure Raspberry pi device as sink==========")
        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,pin_code=pin_code)
        assert bt_client_address is not None
        logger().info(f'Start BT inquiry with RSSI from DUT')
        wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
        time.sleep(duration / 1000)
        # Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0
        # Search for Inquiry type and Remote BT device address
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            if bt_client_address in event_data:
                logger().info(f'Remote BT address found ==> {bt_client_address}')
                break
        logger().info("=============Initiating BT Connection and followed by A2DP Connection============")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)
        # Ping dut
        logger().info("=========Invoke the l2ping=========")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Start capturing audio
        logger().info("=======Start Capturing audio==========")
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
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
        bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=7)
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
        # assert the captured audio size
        logger().info("==========Capturing audio size=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        # So here we are getting the captured audio size in bytes that is divided into 1 lakh to get in MB
        # here we are checking the size in between 8 to 11 MB , 8 is Minimum and 11 is Maximum
        assert 8 <= int(captured_audio_size / 100000) <= 11
    logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_a2dp_repair_functionality_C20059(wifi_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    event_data = ""
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_repair_functionality_C20059.wav"
    with TimeMeasurer() as t:
        logger().info("========Configure DUT in a2dp Initiator_Role===============")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None
        logger().info("===========Configure Raspberry pi device as sink===========")
        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                           pin_code=pin_code)
        assert bt_client_address is not None
        logger().info(f'Start BT inquiry with RSSI from DUT')
        wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
        time.sleep(duration / 1000)
        # Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0
        # Search for Inquiry type and Remote BT device address
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            if bt_client_address in event_data:
                logger().info(f'Remote BT address found ==> {bt_client_address}')
                break
        logger().info("========== Initiating BT Connection and followed by A2DP Connection=========")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)
        # Start capturing audio
        logger().info("==========Start Capturing audio=============")
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(3)
        logger().info("==========Initiating BT disconnecting from DUT============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        assert 5 <= int(captured_audio_size / 100000) <= 6
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        time.sleep(60)
        capture_file_path_two = "./reports/a2dp_capture_test_bt_a2dp_repair_functionality_2.wav"
        logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)
        # Start capturing audio
        logger().info("==========Start Capturing audio=============")
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path_two)
        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(3)
        logger().info("==========Initiating BT disconnecting from DUT============")
        captured_audio_size_two = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path_two)
        logger().info(f"captured_audio_size_two : {captured_audio_size_two}")
        # So here we are getting the captured audio size in bytes that is divided into 1 lakh to get in MB
        # here we are checking the size in between 5 to 6 MB , 5 is Minimum and 6 is Maximum
        assert 5 <= int(captured_audio_size_two / 100000) <= 6
    logger().info(f"Test case executed in {t.duration} seconds")


def test_bt_a2dp_power_cycle_C20057(wifi_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    event_data = ""
    capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_dut_power_play_C20057.wav"
    with TimeMeasurer() as t:
        logger().info("============Configure DUT in a2dp Initiator_Role=============")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None
        logger().info("==========Configure Raspberry pi device as sink==============")
        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,pin_code=pin_code)
        assert bt_client_address is not None
        logger().info(f"{bt_client_address}")
        logger().info(f'Start BT inquiry with RSSI from DUT')
        wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
        time.sleep(duration / 1000)
        # Get Asynchronous messages
        time.sleep(2)
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0
        # Search for Inquiry type and Remote BT device address
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            if bt_client_address in event_data:
                logger().info(f'Remote BT address found ==> {bt_client_address}')
                break
        logger().info("=============Initiating BT Connection and followed by A2DP Connection==========")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        time.sleep(10)
        # Ping dut
        logger().info("Invoke the L2ping")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
        # Start capturing audio
        logger().info("==========Start Capturing audio=============")
        bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
        # A2DP SBC Audio streaming to Raspi
        logger().info("==========Start A2DP SBC Audio streaming from DUT to Raspberry=============")
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(3)
        logger().info("==========Initiating BT disconnecting from DUT============")
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        time.sleep(60)
        logger().info("===========deinit==========")
        wifi_dut.interfaces.wifi.reset_soft()
        logger().info("======init===============")
        wifi_dut.interfaces.wifi.init()
        logger().info("============Configure DUT in a2dp Initiator_Role=============")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                           pin_code=pin_code)
        assert bt_client_address is not None
        logger().info("==============Initiating BT Connection and followed by A2DP Connection===============")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
        # A2DP SBC Audio streaming to Raspi
        logger().info("==============Start A2DP SBC Audio streaming from DUT to Raspberry===========")
        wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
        time.sleep(2)
        # assert the captured audio size
        logger().info("============Capturing the size of audio file=============")
        captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
        logger().info(f"captured_audio_size : {captured_audio_size}")
        # So here we are getting the captured audio size in bytes that is divided into 1 lakh to get in MB
        # here we are checking the size in between 5 to 6 MB , 5 is Minimum and 6 is Maximum
        assert 5 <= int(captured_audio_size / 100000) <= 6
    logger().info(f"Test case executed in {t.duration} seconds")














































































